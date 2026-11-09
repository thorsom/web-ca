"""ACME server (RFC 8555): http-01, dns-01 (incl. wildcards), dns and ip identifiers."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass

import dns.resolver
import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import APIRouter, BackgroundTasks, Request, Response
from fastapi.responses import JSONResponse

from . import ca as cax
from . import db, service, settings

router = APIRouter()

ORDER_LIFETIME = 7 * 86400
AUTHZ_LIFETIME = 7 * 86400
ERR = "urn:ietf:params:acme:error:"


class AcmeError(Exception):
    def __init__(self, type_: str, detail: str, status: int = 400, subproblems=None):
        self.type, self.detail, self.status, self.subproblems = type_, detail, status, subproblems


# ---------------------------------------------------------------- encoding helpers

def b64u_dec(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        raise AcmeError("malformed", "invalid base64url")


def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def rfc3339(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def base_url(request: Request) -> str:
    return (settings.PUBLIC_URL or str(request.base_url)).rstrip("/")


def u(request: Request, path: str) -> str:
    return f"{base_url(request)}/acme{path}"


# ---------------------------------------------------------------- nonces / responses

def new_nonce() -> str:
    n = b64u_enc(secrets.token_bytes(16))
    with db.connect() as c:
        c.execute("INSERT INTO acme_nonces(nonce,created) VALUES(?,?)", (n, time.time()))
        c.execute("DELETE FROM acme_nonces WHERE created<?", (time.time() - 3600,))
    return n


def consume_nonce(n: str) -> bool:
    with db.connect() as c:
        return c.execute("DELETE FROM acme_nonces WHERE nonce=?", (n,)).rowcount == 1


def reply(request: Request, body=None, status=200, location=None, up=None, media="application/json", raw: str | None = None):
    content = raw if raw is not None else (json.dumps(body) if body is not None else "")
    resp = Response(content=content, status_code=status, media_type=media)
    resp.headers["Replay-Nonce"] = new_nonce()
    resp.headers["Cache-Control"] = "no-store"
    resp.headers.append("Link", f'<{u(request, "/directory")}>;rel="index"')
    if up:
        resp.headers.append("Link", f'<{up}>;rel="up"')
    if location:
        resp.headers["Location"] = location
    return resp


def problem_response(request: Request, exc: AcmeError):
    body = {"type": exc.type if exc.type.startswith("urn:") else ERR + exc.type, "detail": exc.detail, "status": exc.status}
    if exc.subproblems:
        body["subproblems"] = exc.subproblems
    r = JSONResponse(body, status_code=exc.status, media_type="application/problem+json")
    r.headers["Replay-Nonce"] = new_nonce()
    r.headers["Cache-Control"] = "no-store"
    return r


# ---------------------------------------------------------------- JWS

def jwk_to_key(jwk: dict):
    try:
        if jwk["kty"] == "EC":
            curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[jwk["crv"]]
            return ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_dec(jwk["x"]), "big"),
                                                 int.from_bytes(b64u_dec(jwk["y"]), "big"), curve).public_key()
        if jwk["kty"] == "RSA":
            key = rsa.RSAPublicNumbers(int.from_bytes(b64u_dec(jwk["e"]), "big"),
                                       int.from_bytes(b64u_dec(jwk["n"]), "big")).public_key()
            if key.key_size < 2048:
                raise AcmeError("badPublicKey", "RSA keys must be at least 2048 bits")
            return key
    except AcmeError:
        raise
    except Exception:
        pass
    raise AcmeError("badPublicKey", "unsupported or invalid JWK")


def jwk_thumbprint(jwk: dict) -> str:
    if jwk["kty"] == "EC":
        d = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    else:
        d = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    return b64u_enc(hashlib.sha256(json.dumps(d, separators=(",", ":"), sort_keys=True).encode()).digest())


_HASHES = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}
_ALG_CURVE = {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}


def verify_signature(key, alg: str, signing_input: bytes, sig: bytes):
    if alg not in ("ES256", "ES384", "ES512", "RS256", "RS384", "RS512"):
        raise AcmeError("badSignatureAlgorithm", f"unsupported algorithm {alg}")
    h = _HASHES[alg[2:]]
    try:
        if alg.startswith("ES"):
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != _ALG_CURVE[alg]:
                raise AcmeError("badSignatureAlgorithm", "algorithm does not match the key")
            size = (key.curve.key_size + 7) // 8
            if len(sig) != 2 * size:
                raise InvalidSignature()
            key.verify(encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big")),
                       signing_input, ec.ECDSA(h))
        else:
            if not isinstance(key, rsa.RSAPublicKey):
                raise AcmeError("badSignatureAlgorithm", "algorithm does not match the key")
            key.verify(sig, signing_input, padding.PKCS1v15(), h)
    except InvalidSignature:
        raise AcmeError("unauthorized", "JWS signature verification failed", 403)


@dataclass
class Jws:
    payload: dict | None      # None => POST-as-GET
    account: object | None
    jwk: dict | None
    thumbprint: str | None


async def parse_jws(request: Request, expected_url: str, mode: str) -> Jws:
    """mode: 'jwk' (new-acct), 'kid' (everything else) or 'either' (revoke-cert)."""
    try:
        body = await request.json()
        prot_b64, pay_b64, sig_b64 = body["protected"], body["payload"], body["signature"]
        protected = json.loads(b64u_dec(prot_b64))
    except AcmeError:
        raise
    except Exception:
        raise AcmeError("malformed", "request body is not a valid flattened JWS")
    if not isinstance(protected, dict):
        raise AcmeError("malformed", "invalid protected header")

    alg = protected.get("alg")
    if protected.get("url") != expected_url:
        raise AcmeError("unauthorized", "JWS 'url' header does not match the request URL", 401)
    nonce = protected.get("nonce")
    if not nonce or not consume_nonce(nonce):
        raise AcmeError("badNonce", "invalid or already used nonce")
    has_jwk, has_kid = "jwk" in protected, "kid" in protected
    if has_jwk == has_kid:
        raise AcmeError("malformed", "exactly one of 'jwk' and 'kid' must be present")
    if mode == "jwk" and not has_jwk or mode == "kid" and not has_kid:
        raise AcmeError("malformed", f"this endpoint requires '{'jwk' if mode == 'jwk' else 'kid'}'")

    account = jwk = thumb = None
    if has_jwk:
        jwk = protected["jwk"]
        key = jwk_to_key(jwk)
        thumb = jwk_thumbprint(jwk)
    else:
        prefix = u(request, "/acct/")
        kid = str(protected["kid"])
        if not kid.startswith(prefix):
            raise AcmeError("accountDoesNotExist", "unknown account URL", 400)
        with db.connect() as c:
            account = c.execute("SELECT * FROM acme_accounts WHERE id=?", (kid[len(prefix):],)).fetchone()
        if not account:
            raise AcmeError("accountDoesNotExist", "unknown account", 400)
        if account["status"] != "valid":
            raise AcmeError("unauthorized", "account is deactivated", 403)
        jwk = json.loads(account["jwk"])
        key = jwk_to_key(jwk)
        thumb = account["thumbprint"]

    verify_signature(key, alg, f"{prot_b64}.{pay_b64}".encode(), b64u_dec(sig_b64))
    if pay_b64 == "":
        payload = None
    else:
        try:
            payload = json.loads(b64u_dec(pay_b64))
        except Exception:
            raise AcmeError("malformed", "payload is not valid JSON")
    return Jws(payload, account, jwk if has_jwk else None, thumb)


# ---------------------------------------------------------------- policy

_DNS_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def check_identifier(idt: dict):
    import ipaddress
    t, v = idt.get("type"), idt.get("value")
    if t not in ("dns", "ip") or not isinstance(v, str) or not v:
        raise AcmeError("unsupportedIdentifier", "only 'dns' and 'ip' identifiers are supported")
    v = v.strip().lower()
    if t == "ip":
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise AcmeError("rejectedIdentifier", f"invalid IP address {v}")
        return {"type": t, "value": v}
    if not _DNS_RE.match(v) or "." not in v.lstrip("*."):
        raise AcmeError("rejectedIdentifier", f"invalid DNS name {v}")
    if settings.ACME_ALLOWED_DOMAINS:
        bare = v[2:] if v.startswith("*.") else v
        if not any(bare == d or bare.endswith("." + d) for d in settings.ACME_ALLOWED_DOMAINS):
            raise AcmeError("rejectedIdentifier", f"{v} is not within the domains this CA serves")
    return {"type": t, "value": v}


# ---------------------------------------------------------------- object renderers

def account_obj(request, a):
    return {"status": a["status"], "contact": json.loads(a["contact"]), "orders": u(request, f"/acct/{a['id']}/orders")}


def challenge_obj(request, ch):
    o = {"type": ch["type"], "url": u(request, f"/chall/{ch['id']}"), "status": ch["status"], "token": ch["token"]}
    if ch["validated"]:
        o["validated"] = ch["validated"]
    if ch["error"]:
        o["error"] = json.loads(ch["error"])
    return o


def authz_obj(request, az):
    with db.connect() as c:
        chs = c.execute("SELECT * FROM acme_challenges WHERE authz_id=? ORDER BY type", (az["id"],)).fetchall()
    o = {"status": az["status"], "expires": rfc3339(az["expires"]),
         "identifier": {"type": az["id_type"], "value": az["id_value"]},
         "challenges": [challenge_obj(request, c) for c in chs]}
    if az["wildcard"]:
        o["wildcard"] = True
    return o


def order_obj(request, o):
    with db.connect() as c:
        azs = c.execute("SELECT id FROM acme_authzs WHERE order_id=? ORDER BY rowid", (o["id"],)).fetchall()
    out = {"status": o["status"], "expires": rfc3339(o["expires"]), "identifiers": json.loads(o["identifiers"]),
           "authorizations": [u(request, f"/authz/{a['id']}") for a in azs], "finalize": u(request, f"/order/{o['id']}/finalize")}
    if o["status"] == "valid" and o["cert_id"]:
        out["certificate"] = u(request, f"/cert/{o['id']}")
    if o["error"]:
        out["error"] = json.loads(o["error"])
    return out


def refresh_order(order_id: str):
    with db.connect() as c:
        o = c.execute("SELECT * FROM acme_orders WHERE id=?", (order_id,)).fetchone()
        if not o:
            raise AcmeError("malformed", "unknown order", 404)
        if o["status"] == "pending":
            azs = c.execute("SELECT * FROM acme_authzs WHERE order_id=?", (order_id,)).fetchall()
            status = "pending"
            if o["expires"] < time.time() or any(a["status"] in ("invalid", "deactivated", "expired", "revoked") for a in azs):
                status = "invalid"
            elif all(a["status"] == "valid" for a in azs):
                status = "ready"
            if status != o["status"]:
                c.execute("UPDATE acme_orders SET status=? WHERE id=?", (status, order_id))
        o = c.execute("SELECT * FROM acme_orders WHERE id=?", (order_id,)).fetchone()
    return o


def own_order(order_id: str, account) -> object:
    o = refresh_order(order_id)
    if o["account_id"] != account["id"]:
        raise AcmeError("unauthorized", "this order belongs to another account", 403)
    return o


# ---------------------------------------------------------------- endpoints

@router.get("/directory")
async def directory(request: Request):
    return JSONResponse({
        "newNonce": u(request, "/new-nonce"), "newAccount": u(request, "/new-acct"),
        "newOrder": u(request, "/new-order"), "revokeCert": u(request, "/revoke-cert"),
        "meta": {"website": base_url(request), "externalAccountRequired": False},
    })


@router.api_route("/new-nonce", methods=["HEAD", "GET"])
async def new_nonce_ep(request: Request):
    resp = Response(status_code=200 if request.method == "HEAD" else 204)
    resp.headers["Replay-Nonce"] = new_nonce()
    resp.headers["Cache-Control"] = "no-store"
    resp.headers.append("Link", f'<{u(request, "/directory")}>;rel="index"')
    return resp


def _contacts(payload):
    contact = payload.get("contact", [])
    if not isinstance(contact, list) or not all(isinstance(c, str) and c.startswith("mailto:") for c in contact):
        raise AcmeError("invalidContact", "contact must be a list of mailto: URLs")
    return contact


@router.post("/new-acct")
async def new_account(request: Request):
    j = await parse_jws(request, u(request, "/new-acct"), "jwk")
    p = j.payload or {}
    with db.connect() as c:
        a = c.execute("SELECT * FROM acme_accounts WHERE thumbprint=? AND status='valid'", (j.thumbprint,)).fetchone()
        if a:
            return reply(request, account_obj(request, a), 200, location=u(request, f"/acct/{a['id']}"))
        if p.get("onlyReturnExisting"):
            raise AcmeError("accountDoesNotExist", "no account exists for this key")
        contact = _contacts(p)
        aid = b64u_enc(secrets.token_bytes(12))
        c.execute("INSERT INTO acme_accounts(id,jwk,thumbprint,contact) VALUES(?,?,?,?)",
                  (aid, json.dumps(j.jwk), j.thumbprint, json.dumps(contact)))
        a = c.execute("SELECT * FROM acme_accounts WHERE id=?", (aid,)).fetchone()
    return reply(request, account_obj(request, a), 201, location=u(request, f"/acct/{aid}"))


@router.post("/acct/{aid}")
async def account_ep(aid: str, request: Request):
    j = await parse_jws(request, u(request, f"/acct/{aid}"), "kid")
    if j.account["id"] != aid:
        raise AcmeError("unauthorized", "not your account", 403)
    p = j.payload
    if p:
        with db.connect() as c:
            if "contact" in p:
                c.execute("UPDATE acme_accounts SET contact=? WHERE id=?", (json.dumps(_contacts(p)), aid))
            if p.get("status") == "deactivated":
                c.execute("UPDATE acme_accounts SET status='deactivated' WHERE id=?", (aid,))
            elif "status" in p:
                raise AcmeError("malformed", "status can only be set to 'deactivated'")
    with db.connect() as c:
        a = c.execute("SELECT * FROM acme_accounts WHERE id=?", (aid,)).fetchone()
    return reply(request, account_obj(request, a))


@router.post("/acct/{aid}/orders")
async def account_orders(aid: str, request: Request):
    j = await parse_jws(request, u(request, f"/acct/{aid}/orders"), "kid")
    if j.account["id"] != aid:
        raise AcmeError("unauthorized", "not your account", 403)
    with db.connect() as c:
        rows = c.execute("SELECT id FROM acme_orders WHERE account_id=? ORDER BY created DESC LIMIT 100", (aid,)).fetchall()
    return reply(request, {"orders": [u(request, f"/order/{r['id']}") for r in rows]})


@router.post("/new-order")
async def new_order(request: Request):
    j = await parse_jws(request, u(request, "/new-order"), "kid")
    p = j.payload
    if not p or not isinstance(p.get("identifiers"), list) or not p["identifiers"]:
        raise AcmeError("malformed", "'identifiers' is required")
    if len(p["identifiers"]) > 100:
        raise AcmeError("malformed", "too many identifiers (max 100)")
    if not db.get_setting("acme_ca_id"):
        raise AcmeError("serverInternal", "no issuing CA has been configured for ACME yet", 500)

    seen, idents, subs = set(), [], []
    for raw in p["identifiers"]:
        try:
            ident = check_identifier(raw if isinstance(raw, dict) else {})
            key = (ident["type"], ident["value"])
            if key not in seen:
                seen.add(key)
                idents.append(ident)
        except AcmeError as e:
            subs.append({"type": ERR + e.type, "detail": e.detail, "identifier": raw})
    if subs:
        raise AcmeError("rejectedIdentifier", "one or more identifiers were rejected", 400, subs)

    oid = b64u_enc(secrets.token_bytes(12))
    exp = time.time() + ORDER_LIFETIME
    with db.connect() as c:
        c.execute("INSERT INTO acme_orders(id,account_id,status,identifiers,expires) VALUES(?,?,?,?,?)",
                  (oid, j.account["id"], "pending", json.dumps(idents), exp))
        for ident in idents:
            wildcard = ident["value"].startswith("*.")
            azid = b64u_enc(secrets.token_bytes(12))
            c.execute("INSERT INTO acme_authzs(id,order_id,id_type,id_value,wildcard,status,expires) VALUES(?,?,?,?,?,?,?)",
                      (azid, oid, ident["type"], ident["value"][2:] if wildcard else ident["value"], int(wildcard),
                       "pending", time.time() + AUTHZ_LIFETIME))
            types = ["dns-01"] if wildcard else (["http-01", "dns-01"] if ident["type"] == "dns" else ["http-01"])
            for t in types:
                c.execute("INSERT INTO acme_challenges(id,authz_id,type,token,status) VALUES(?,?,?,?,'pending')",
                          (b64u_enc(secrets.token_bytes(12)), azid, t, b64u_enc(secrets.token_bytes(32))))
        o = c.execute("SELECT * FROM acme_orders WHERE id=?", (oid,)).fetchone()
    return reply(request, order_obj(request, o), 201, location=u(request, f"/order/{oid}"))


@router.post("/order/{oid}")
async def get_order(oid: str, request: Request):
    j = await parse_jws(request, u(request, f"/order/{oid}"), "kid")
    o = own_order(oid, j.account)
    return reply(request, order_obj(request, o), location=u(request, f"/order/{oid}"))


@router.post("/authz/{azid}")
async def get_authz(azid: str, request: Request):
    j = await parse_jws(request, u(request, f"/authz/{azid}"), "kid")
    with db.connect() as c:
        az = c.execute("SELECT * FROM acme_authzs WHERE id=?", (azid,)).fetchone()
    if not az:
        raise AcmeError("malformed", "unknown authorization", 404)
    own_order(az["order_id"], j.account)
    if j.payload and j.payload.get("status") == "deactivated":
        with db.connect() as c:
            c.execute("UPDATE acme_authzs SET status='deactivated' WHERE id=?", (azid,))
            az = c.execute("SELECT * FROM acme_authzs WHERE id=?", (azid,)).fetchone()
    elif az["status"] == "pending" and az["expires"] < time.time():
        with db.connect() as c:
            c.execute("UPDATE acme_authzs SET status='expired' WHERE id=?", (azid,))
            az = c.execute("SELECT * FROM acme_authzs WHERE id=?", (azid,)).fetchone()
    return reply(request, authz_obj(request, az))


@router.post("/chall/{cid}")
async def challenge_ep(cid: str, request: Request, bg: BackgroundTasks):
    j = await parse_jws(request, u(request, f"/chall/{cid}"), "kid")
    with db.connect() as c:
        ch = c.execute("SELECT * FROM acme_challenges WHERE id=?", (cid,)).fetchone()
        if not ch:
            raise AcmeError("malformed", "unknown challenge", 404)
        az = c.execute("SELECT * FROM acme_authzs WHERE id=?", (ch["authz_id"],)).fetchone()
    own_order(az["order_id"], j.account)
    if ch["status"] == "pending" and az["status"] == "pending" and j.payload is not None:
        with db.connect() as c:
            c.execute("UPDATE acme_challenges SET status='processing' WHERE id=?", (cid,))
            ch = c.execute("SELECT * FROM acme_challenges WHERE id=?", (cid,)).fetchone()
        bg.add_task(validate_challenge, cid)
    return reply(request, challenge_obj(request, ch), up=u(request, f"/authz/{az['id']}"))


@router.post("/order/{oid}/finalize")
async def finalize(oid: str, request: Request):
    j = await parse_jws(request, u(request, f"/order/{oid}/finalize"), "kid")
    o = own_order(oid, j.account)
    if o["status"] != "ready":
        raise AcmeError("orderNotReady", f"order is '{o['status']}', not 'ready'", 403)
    try:
        csr = x509.load_der_x509_csr(b64u_dec((j.payload or {}).get("csr", "")))
        cax.check_csr(csr)
    except AcmeError:
        raise
    except Exception as e:
        raise AcmeError("badCSR", f"invalid CSR: {e}")

    wanted = {(i["type"], i["value"]) for i in json.loads(o["identifiers"])}
    got = set()
    for g in cax.get_sans(csr):
        if isinstance(g, x509.DNSName):
            got.add(("dns", g.value.lower()))
        elif isinstance(g, x509.IPAddress):
            got.add(("ip", str(g.value)))
        else:
            raise AcmeError("badCSR", "only DNS and IP subject alternative names are allowed")
    if got != wanted:
        raise AcmeError("badCSR", "the CSR's subject alternative names must exactly match the order's identifiers")

    with db.connect() as c:  # claim the order so concurrent finalize calls can't double-issue
        if c.execute("UPDATE acme_orders SET status='processing' WHERE id=? AND status='ready'", (oid,)).rowcount != 1:
            raise AcmeError("orderNotReady", "order is already being processed", 403)

    try:
        ca_id = int(db.get_setting("acme_ca_id") or 0)
        days = int(db.get_setting("acme_cert_days") or settings.ACME_DEFAULT_CERT_DAYS)
        sans = [x509.DNSName(v) if t == "dns" else x509.IPAddress(__import__("ipaddress").ip_address(v)) for t, v in sorted(wanted)]
        first_dns = next((v for t, v in sorted(wanted) if t == "dns" and not v.startswith("*") and len(v) <= 64), None)
        subject = cax.build_name(cn=first_dns) if first_dns else x509.Name([])
        cert_id, _ = service.sign_with_ca(ca_id, subject=subject, public_key=csr.public_key(), profile="server",
                                          sans=sans, days=days, source="acme", acme_account=j.account["id"])
        with db.connect() as c:
            c.execute("UPDATE acme_orders SET status='valid', cert_id=? WHERE id=?", (cert_id, oid))
    except Exception as e:
        with db.connect() as c:
            c.execute("UPDATE acme_orders SET status='invalid', error=? WHERE id=?",
                      (json.dumps({"type": ERR + "serverInternal", "detail": str(e)}), oid))
        raise AcmeError("serverInternal", f"issuance failed: {e}", 500)
    o = refresh_order(oid)
    return reply(request, order_obj(request, o), location=u(request, f"/order/{oid}"))


@router.post("/cert/{oid}")
async def get_cert(oid: str, request: Request):
    j = await parse_jws(request, u(request, f"/cert/{oid}"), "kid")
    o = own_order(oid, j.account)
    if o["status"] != "valid" or not o["cert_id"]:
        raise AcmeError("orderNotReady", "certificate is not available", 403)
    crow = service.get_cert(o["cert_id"])
    pem = crow["cert_pem"] + service.chain_pem(crow["ca_id"], include_root=False)
    return reply(request, raw=pem, media="application/pem-certificate-chain")


@router.post("/revoke-cert")
async def revoke_cert(request: Request):
    j = await parse_jws(request, u(request, "/revoke-cert"), "either")
    p = j.payload or {}
    try:
        cert = x509.load_der_x509_certificate(b64u_dec(p.get("certificate", "")))
    except AcmeError:
        raise
    except Exception:
        raise AcmeError("malformed", "invalid certificate")
    reason = p.get("reason", 0)
    if reason not in cax.ACME_REASON_CODES:
        raise AcmeError("badRevocationReason", "unsupported revocation reason")
    with db.connect() as c:
        row = c.execute("SELECT * FROM certs WHERE serial=? AND cert_pem=?", (cax.serial_hex(cert), cax.cert_pem(cert))).fetchone()
    if not row:
        raise AcmeError("malformed", "certificate was not issued by this CA", 404)
    if j.account is not None:
        allowed = row["acme_account"] == j.account["id"]
    else:
        allowed = cax.pub_der(jwk_to_key(j.jwk)) == cax.pub_der(cert.public_key())
    if not allowed:
        raise AcmeError("unauthorized", "you are not allowed to revoke this certificate", 403)
    if row["revoked_at"]:
        raise AcmeError("alreadyRevoked", "certificate is already revoked")
    service.revoke(row["id"], cax.ACME_REASON_CODES[reason])
    return reply(request, raw="", status=200)


# ---------------------------------------------------------------- challenge validation

def _fail(cid: str, azid: str, detail: str):
    err = json.dumps({"type": ERR + "unauthorized", "detail": detail, "status": 403})
    with db.connect() as c:
        c.execute("UPDATE acme_challenges SET status='invalid', error=? WHERE id=?", (err, cid))
        c.execute("UPDATE acme_authzs SET status='invalid' WHERE id=?", (azid,))


def validate_challenge(cid: str):
    with db.connect() as c:
        ch = c.execute("SELECT * FROM acme_challenges WHERE id=?", (cid,)).fetchone()
        az = c.execute("SELECT * FROM acme_authzs WHERE id=?", (ch["authz_id"],)).fetchone()
        acct = c.execute("SELECT a.thumbprint FROM acme_orders o JOIN acme_accounts a ON a.id=o.account_id WHERE o.id=?",
                         (az["order_id"],)).fetchone()
    key_auth = f"{ch['token']}.{acct['thumbprint']}"
    host = az["id_value"]
    ok, detail = False, ""
    if settings.ACME_SKIP_VALIDATION:
        ok = True
    elif ch["type"] == "http-01":
        host_part = f"[{host}]" if ":" in host else host
        port = "" if settings.ACME_HTTP01_PORT == 80 else f":{settings.ACME_HTTP01_PORT}"
        url = f"http://{host_part}{port}/.well-known/acme-challenge/{ch['token']}"
        try:
            with httpx.Client(timeout=10, follow_redirects=True, max_redirects=5) as cl:
                r = cl.get(url)
            ok = r.status_code == 200 and r.text.strip() == key_auth
            detail = "" if ok else f"{url} returned HTTP {r.status_code} with unexpected content"
        except Exception as e:
            detail = f"could not fetch {url}: {e}"
    elif ch["type"] == "dns-01":
        expected = b64u_enc(hashlib.sha256(key_auth.encode()).digest())
        name = f"_acme-challenge.{host}"
        try:
            ans = dns.resolver.resolve(name, "TXT", lifetime=10)
            values = ["".join(s.decode() for s in r.strings) for r in ans]
            ok = expected in values
            detail = "" if ok else f"no matching TXT record at {name}"
        except Exception as e:
            detail = f"DNS lookup of {name} failed: {e}"
    if not ok:
        return _fail(cid, az["id"], detail or "validation failed")
    with db.connect() as c:
        c.execute("UPDATE acme_challenges SET status='valid', validated=? WHERE id=?", (cax.iso(cax.now()), cid))
        c.execute("UPDATE acme_authzs SET status='valid' WHERE id=?", (az["id"],))
