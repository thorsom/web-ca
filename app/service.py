"""Business logic tying crypto and storage together."""
from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import ca as cax
from . import db, settings


class NotFound(Exception):
    pass


# ---------------------------------------------------------------- key sealing

def seal_key(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(settings.MASTER_KEY.encode())).decode()


def open_key(sealed: str):
    return serialization.load_pem_private_key(sealed.encode(), settings.MASTER_KEY.encode())


# ---------------------------------------------------------------- CA records

def get_ca(ca_id: int):
    with db.connect() as c:
        r = c.execute("SELECT * FROM cas WHERE id=?", (ca_id,)).fetchone()
    if not r:
        raise NotFound(f"CA {ca_id} not found")
    return r


def list_cas():
    with db.connect() as c:
        return c.execute("SELECT * FROM cas ORDER BY id").fetchall()


def ca_cert(row) -> x509.Certificate:
    return x509.load_pem_x509_certificate(row["cert_pem"].encode())


def signer(ca_id: int):
    row = get_ca(ca_id)
    if not row["key_enc"]:
        raise ValueError(f"CA '{row['name']}' has no private key stored (it was uploaded without one) and cannot sign")
    return row, ca_cert(row), open_key(row["key_enc"])


def chain_rows(ca_id: int) -> list:
    """The CA itself followed by its ancestors up to the root."""
    rows, seen = [], set()
    cur = get_ca(ca_id)
    while cur and cur["id"] not in seen:
        rows.append(cur)
        seen.add(cur["id"])
        cur = get_ca(cur["parent_id"]) if cur["parent_id"] else None
    return rows


def chain_pem(ca_id: int, include_root=True) -> str:
    rows = chain_rows(ca_id)
    if not include_root:
        rows = [r for r in rows if r["kind"] != "root"]
    return "".join(r["cert_pem"] for r in rows)


def ca_public(row) -> dict:
    return {
        "id": row["id"], "name": row["name"], "kind": row["kind"], "parent_id": row["parent_id"],
        "subject": row["subject"], "serial": row["serial"], "not_before": row["not_before"],
        "not_after": row["not_after"], "path_len": row["path_len"], "has_key": bool(row["key_enc"]),
        "created": row["created"], "acme_default": str(row["id"]) == (db.get_setting("acme_ca_id") or ""),
        "complete_chain": row["kind"] == "root" or row["parent_id"] is not None,
    }


def urls_for(ca_id: int):
    if not settings.PUBLIC_URL:
        return None
    return {"aia": f"{settings.PUBLIC_URL}/ca/{ca_id}.crt", "crl": f"{settings.PUBLIC_URL}/crl/{ca_id}.crl"}


def _find_db_parent(cert: x509.Certificate):
    for r in list_cas():
        pc = ca_cert(r)
        if cert.issuer == pc.subject and cax.is_issued_by(cert, pc):
            return r["id"]
    return None


def insert_ca(name: str, cert: x509.Certificate, key, parent_id: int | None) -> int:
    bc = cax.basic_constraints(cert)
    kind = "root" if cax.is_self_signed(cert) else "intermediate"
    with db.connect() as c:
        cur = c.execute(
            "INSERT INTO cas(name,kind,parent_id,subject,serial,fingerprint,not_before,not_after,path_len,cert_pem,key_enc)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (name, kind, parent_id, cert.subject.rfc4514_string(), cax.serial_hex(cert), cax.fingerprint(cert),
             cax.iso(cert.not_valid_before_utc), cax.iso(cert.not_valid_after_utc),
             bc.path_length if bc else None, cax.cert_pem(cert), seal_key(key) if key is not None else None))
        new_id = cur.lastrowid
        # link previously uploaded orphans that were issued by this certificate
        for r in c.execute("SELECT * FROM cas WHERE parent_id IS NULL AND kind='intermediate' AND id<>?", (new_id,)).fetchall():
            if cax.is_issued_by(ca_cert(r), cert):
                c.execute("UPDATE cas SET parent_id=? WHERE id=?", (new_id, r["id"]))
    if kind == "intermediate" and key is not None and not db.get_setting("acme_ca_id"):
        db.set_setting("acme_ca_id", new_id)
    return new_id


def import_ca(cert_pem: str, key_pem: str | None = None, key_password: str | None = None,
              chain_pem: str | None = None, name: str | None = None) -> int:
    main = cax.load_cert_pem(cert_pem)
    pool = cax.load_certs_pem(chain_pem) if chain_pem and chain_pem.strip() else []
    bc = cax.basic_constraints(main)
    if not bc or not bc.ca:
        raise ValueError("this certificate is not a CA certificate (BasicConstraints CA:TRUE is missing)")
    key = None
    if key_pem and key_pem.strip():
        key = cax.load_key_pem(key_pem, key_password)
        if cax.pub_der(key.public_key()) != cax.pub_der(main.public_key()):
            raise ValueError("the private key does not match the certificate")

    with db.connect() as c:
        existing = c.execute("SELECT * FROM cas WHERE fingerprint=?", (cax.fingerprint(main),)).fetchone()
    if existing:
        if key is not None and not existing["key_enc"]:
            with db.connect() as c:
                c.execute("UPDATE cas SET key_enc=? WHERE id=?", (seal_key(key), existing["id"]))
            return existing["id"]
        raise ValueError(f"this certificate is already imported as '{existing['name']}'")

    # collect ancestors from the supplied bundle, walking upwards
    chain, cur = [main], main
    while not cax.is_self_signed(cur) and _find_db_parent(cur) is None:
        parent = next((p for p in pool if cax.is_issued_by(cur, p)), None)
        if parent is None:
            break
        chain.append(parent)
        cur = parent

    new_id = None
    for cert in reversed(chain):
        with db.connect() as c:
            have = c.execute("SELECT id FROM cas WHERE fingerprint=?", (cax.fingerprint(cert),)).fetchone()
        if have:
            new_id = have["id"]
            continue
        label = (name if cert is main and name else None) or cax.common_name(cert.subject) or cert.subject.rfc4514_string()
        new_id = insert_ca(label, cert, key if cert is main else None, _find_db_parent(cert) if not cax.is_self_signed(cert) else None)
    return new_id


def delete_ca(ca_id: int):
    get_ca(ca_id)
    with db.connect() as c:
        if c.execute("SELECT 1 FROM cas WHERE parent_id=?", (ca_id,)).fetchone():
            raise ValueError("this CA has sub-CAs; delete or detach them first")
        c.execute("DELETE FROM certs WHERE ca_id=?", (ca_id,))
        c.execute("DELETE FROM cas WHERE id=?", (ca_id,))
    if db.get_setting("acme_ca_id") == str(ca_id):
        db.set_setting("acme_ca_id", None)


# ---------------------------------------------------------------- issued certificates

def sign_with_ca(ca_id: int, *, subject, public_key, profile="server", key_usage=(), extended_key_usage=(),
                 sans=(), days=365, path_length=None, name_constraints=None, is_ca_custom=False,
                 source="manual", acme_account=None) -> tuple[int, x509.Certificate]:
    row, issuer_cert, issuer_key = signer(ca_id)
    cert = cax.issue_certificate(
        issuer_cert=issuer_cert, issuer_key=issuer_key, subject=subject, public_key=public_key, profile=profile,
        key_usage=key_usage, extended_key_usage=extended_key_usage, sans=sans, days=days,
        path_length=path_length, name_constraints=name_constraints, is_ca_custom=is_ca_custom, urls=urls_for(ca_id))
    with db.connect() as c:
        cur = c.execute(
            "INSERT INTO certs(ca_id,serial,subject,sans,profile,source,not_before,not_after,cert_pem,acme_account)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ca_id, cax.serial_hex(cert), cert.subject.rfc4514_string(), ", ".join(cax.san_strings(cax.get_sans(cert))),
             profile, source, cax.iso(cert.not_valid_before_utc), cax.iso(cert.not_valid_after_utc),
             cax.cert_pem(cert), acme_account))
    return cur.lastrowid, cert


def list_certs():
    with db.connect() as c:
        return c.execute("SELECT c.*, a.name AS ca_name FROM certs c JOIN cas a ON a.id=c.ca_id ORDER BY c.id DESC").fetchall()


def get_cert(cert_id: int):
    with db.connect() as c:
        r = c.execute("SELECT * FROM certs WHERE id=?", (cert_id,)).fetchone()
    if not r:
        raise NotFound(f"certificate {cert_id} not found")
    return r


def revoke(cert_id: int, reason: str = "unspecified"):
    if reason not in cax.REVOKE_REASONS:
        raise ValueError(f"unknown revocation reason {reason!r}")
    r = get_cert(cert_id)
    if r["revoked_at"]:
        raise ValueError("certificate is already revoked")
    with db.connect() as c:
        c.execute("UPDATE certs SET revoked_at=?, revoke_reason=? WHERE id=?", (cax.iso(cax.now()), reason, cert_id))


def build_crl_for(ca_id: int) -> x509.CertificateRevocationList:
    _, cert, key = signer(ca_id)
    with db.connect() as c:
        rows = c.execute("SELECT serial, revoked_at, revoke_reason FROM certs WHERE ca_id=? AND revoked_at IS NOT NULL", (ca_id,)).fetchall()
    revoked = [(int(r["serial"], 16), dt.datetime.strptime(r["revoked_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=cax.UTC),
                r["revoke_reason"]) for r in rows]
    return cax.build_crl(cert, key, revoked)
