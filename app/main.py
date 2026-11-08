import logging
import os
import secrets
from typing import Literal, Optional

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from . import acme, db, service, settings
from . import ca as cax

logging.basicConfig(level=logging.INFO)
db.init()

app = FastAPI(title="Certificate Authority", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(acme.router, prefix="/acme", tags=["acme"])

STATIC = os.path.join(os.path.dirname(__file__), "static")
basic = HTTPBasic(realm="CA admin")


def admin(creds: HTTPBasicCredentials = Depends(basic)):
    ok_user = secrets.compare_digest(creds.username.encode(), settings.ADMIN_USER.encode())
    ok_pass = secrets.compare_digest(creds.password.encode(), settings.ADMIN_PASSWORD.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(401, "invalid credentials", headers={"WWW-Authenticate": 'Basic realm="CA admin"'})


api = APIRouter(prefix="/api", dependencies=[Depends(admin)])


@app.exception_handler(acme.AcmeError)
async def acme_error_handler(request: Request, exc: acme.AcmeError):
    return acme.problem_response(request, exc)


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(service.NotFound)
async def not_found_handler(request: Request, exc: service.NotFound):
    return JSONResponse({"detail": str(exc)}, status_code=404)


# ------------------------------------------------------------------ models

class Subject(BaseModel):
    cn: Optional[str] = None
    o: Optional[str] = None
    ou: Optional[str] = None
    c: Optional[str] = None
    st: Optional[str] = None
    l: Optional[str] = None
    email: Optional[str] = None


class Constraints(BaseModel):
    permitted_dns: list[str] = []
    excluded_dns: list[str] = []
    permitted_ip: list[str] = []
    excluded_ip: list[str] = []

    def build(self):
        return cax.build_name_constraints(self.permitted_dns, self.excluded_dns, self.permitted_ip, self.excluded_ip)


class Options(BaseModel):
    profile: Literal["server", "client", "server_client", "code_signing", "email", "timestamping",
                     "ocsp_signing", "ca", "custom"] = "server"
    key_usage: list[str] = []
    extended_key_usage: list[str] = []
    is_ca: bool = False                 # only used by the "custom" profile
    path_length: Optional[int] = Field(None, ge=0, le=10)
    constraints: Constraints = Constraints()
    days: int = Field(365, ge=1, le=36500)


class RootReq(BaseModel):
    name: Optional[str] = None
    subject: Subject
    key_type: str = "ec384"
    days: int = Field(3650, ge=1, le=36500)
    path_length: Optional[int] = Field(None, ge=0, le=10)
    constraints: Constraints = Constraints()


class IntermediateReq(BaseModel):
    name: Optional[str] = None
    parent_id: int
    subject: Subject
    key_type: str = "ec256"
    days: int = Field(1825, ge=1, le=36500)
    path_length: Optional[int] = Field(0, ge=0, le=10)
    constraints: Constraints = Constraints()


class UploadReq(BaseModel):
    name: Optional[str] = None
    cert_pem: str
    key_pem: Optional[str] = None
    key_password: Optional[str] = None
    chain_pem: Optional[str] = None


class SignCsrReq(BaseModel):
    ca_id: int
    csr_pem: str
    options: Options = Options()
    copy_csr_sans: bool = True
    extra_sans: list[str] = []


class Pkcs12Req(BaseModel):
    ca_id: int
    subject: Subject
    sans: list[str] = []
    key_type: str = "rsa2048"
    options: Options = Options()
    password: str
    legacy: bool = False
    include_chain: bool = True
    friendly_name: Optional[str] = None


class RevokeReq(BaseModel):
    reason: str = "unspecified"


class AcmeSettings(BaseModel):
    ca_id: Optional[int] = None
    cert_days: Optional[int] = Field(None, ge=1, le=825)


class ServerTlsReq(BaseModel):
    ca_id: int
    hostnames: list[str]
    key_type: str = "ec256"
    days: int = Field(365, ge=1, le=825)


def pem_response(text: str, filename: str, media="application/x-pem-file"):
    return Response(text, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def default_ca_name(subject: Subject, name):
    return name or subject.cn or subject.o or "CA"


# ------------------------------------------------------------------ meta

@api.get("/meta")
def meta():
    return {"key_types": cax.KEY_TYPES, "key_usages": cax.KU_NAMES, "extended_key_usages": list(cax.EKU_MAP),
            "profiles": [{"id": k, "label": v} for k, v in cax.PROFILE_LABELS.items()],
            "revoke_reasons": list(cax.REVOKE_REASONS), "public_url": settings.PUBLIC_URL,
            "https": os.path.exists(os.path.join(settings.DATA_DIR, "tls", "server.crt"))}


# ------------------------------------------------------------------ authorities

@api.get("/cas")
def list_cas():
    return [service.ca_public(r) for r in service.list_cas()]


@api.post("/cas/root")
def create_root(r: RootReq):
    key = cax.generate_key(r.key_type)
    subject = cax.build_name(**r.subject.model_dump())
    cert = cax.issue_certificate(issuer_cert=None, issuer_key=key, subject=subject, public_key=key.public_key(),
                                 profile="ca", days=r.days, path_length=r.path_length, name_constraints=r.constraints.build())
    ca_id = service.insert_ca(default_ca_name(r.subject, r.name), cert, key, None)
    return service.ca_public(service.get_ca(ca_id))


@api.post("/cas/intermediate")
def create_intermediate(r: IntermediateReq):
    key = cax.generate_key(r.key_type)
    subject = cax.build_name(**r.subject.model_dump())
    _, cert = service.sign_with_ca(r.parent_id, subject=subject, public_key=key.public_key(), profile="ca", days=r.days,
                                   path_length=r.path_length, name_constraints=r.constraints.build(), source="intermediate")
    ca_id = service.insert_ca(default_ca_name(r.subject, r.name), cert, key, r.parent_id)
    return service.ca_public(service.get_ca(ca_id))


@api.post("/cas/upload")
def upload_ca(r: UploadReq):
    ca_id = service.import_ca(r.cert_pem, r.key_pem, r.key_password, r.chain_pem, r.name)
    return service.ca_public(service.get_ca(ca_id))


@api.delete("/cas/{ca_id}")
def delete_ca(ca_id: int):
    service.delete_ca(ca_id)
    return {"ok": True}


@api.get("/cas/{ca_id}/cert.pem")
def ca_cert_pem(ca_id: int):
    row = service.get_ca(ca_id)
    return pem_response(row["cert_pem"], f"ca-{ca_id}.pem")


@api.get("/cas/{ca_id}/chain.pem")
def ca_chain_pem(ca_id: int):
    return pem_response(service.chain_pem(ca_id), f"ca-{ca_id}-chain.pem")


@api.get("/cas/{ca_id}/crl.pem")
def ca_crl_pem(ca_id: int):
    crl = service.build_crl_for(ca_id)
    return pem_response(crl.public_bytes(serialization.Encoding.PEM).decode(), f"ca-{ca_id}.crl.pem")


# ------------------------------------------------------------------ certificates

def cert_public(r):
    return {k: r[k] for k in ("id", "ca_id", "ca_name", "serial", "subject", "sans", "profile", "source",
                              "not_before", "not_after", "revoked_at", "revoke_reason", "created")}


@api.get("/certs")
def list_certs():
    return [cert_public(r) for r in service.list_certs()]


@api.get("/certs/{cert_id}/cert.pem")
def cert_pem_dl(cert_id: int):
    return pem_response(service.get_cert(cert_id)["cert_pem"], f"cert-{cert_id}.pem")


@api.get("/certs/{cert_id}/fullchain.pem")
def cert_fullchain_dl(cert_id: int):
    r = service.get_cert(cert_id)
    return pem_response(r["cert_pem"] + service.chain_pem(r["ca_id"]), f"cert-{cert_id}-fullchain.pem")


@api.post("/certs/{cert_id}/revoke")
def revoke(cert_id: int, r: RevokeReq):
    service.revoke(cert_id, r.reason)
    return {"ok": True}


def _sans_from(csr, copy_csr: bool, extra):
    sans = list(cax.get_sans(csr)) if copy_csr else []
    sans += cax.parse_sans(extra)
    return sans


@api.post("/certs/sign-csr")
def sign_csr(r: SignCsrReq):
    csr = cax.load_csr_pem(r.csr_pem)
    o = r.options
    sans = _sans_from(csr, r.copy_csr_sans, r.extra_sans)
    if not sans and len(csr.subject) == 0:
        raise ValueError("the CSR has no subject and no SANs")
    cert_id, cert = service.sign_with_ca(
        r.ca_id, subject=csr.subject, public_key=csr.public_key(), profile=o.profile, key_usage=o.key_usage,
        extended_key_usage=o.extended_key_usage, sans=sans, days=o.days, path_length=o.path_length,
        name_constraints=o.constraints.build(), is_ca_custom=o.is_ca, source="csr")
    row = service.get_cert(cert_id)
    return {"id": cert_id, "serial": row["serial"], "not_after": row["not_after"], "subject": row["subject"],
            "cert_pem": row["cert_pem"], "chain_pem": service.chain_pem(r.ca_id),
            "fullchain_pem": row["cert_pem"] + service.chain_pem(r.ca_id)}


@api.post("/certs/pkcs12")
def make_p12(r: Pkcs12Req):
    key = cax.generate_key(r.key_type)
    subject = cax.build_name(**r.subject.model_dump())
    o = r.options
    sans = cax.parse_sans(r.sans)
    if o.profile in ("server", "server_client") and r.subject.cn and not sans:
        sans = [cax.parse_san(r.subject.cn)]  # browsers require a SAN for TLS server certificates
    cert_id, cert = service.sign_with_ca(
        r.ca_id, subject=subject, public_key=key.public_key(), profile=o.profile, key_usage=o.key_usage,
        extended_key_usage=o.extended_key_usage, sans=sans, days=o.days, path_length=o.path_length,
        name_constraints=o.constraints.build(), is_ca_custom=o.is_ca, source="pkcs12")
    chain = [service.ca_cert(x) for x in service.chain_rows(r.ca_id)] if r.include_chain else []
    name = r.friendly_name or r.subject.cn or "certificate"
    data = cax.make_pkcs12(key, cert, chain, r.password, name, r.legacy)
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)
    return Response(data, media_type="application/x-pkcs12",
                    headers={"Content-Disposition": f'attachment; filename="{safe}.p12"', "X-Certificate-Id": str(cert_id)})


# ------------------------------------------------------------------ ACME settings, server TLS

@api.get("/acme")
def acme_info(request: Request):
    base = (settings.PUBLIC_URL or str(request.base_url)).rstrip("/")
    ca_id = db.get_setting("acme_ca_id")
    with db.connect() as c:
        counts = {t: c.execute(f"SELECT COUNT(*) n FROM {t}").fetchone()["n"] for t in ("acme_accounts", "acme_orders")}
    return {"directory_url": f"{base}/acme/directory", "ca_id": int(ca_id) if ca_id else None,
            "cert_days": int(db.get_setting("acme_cert_days") or settings.ACME_DEFAULT_CERT_DAYS),
            "skip_validation": settings.ACME_SKIP_VALIDATION, "allowed_domains": settings.ACME_ALLOWED_DOMAINS,
            "http01_port": settings.ACME_HTTP01_PORT, "accounts": counts["acme_accounts"], "orders": counts["acme_orders"],
            "https": base.startswith("https://")}


@api.put("/acme")
def acme_update(s: AcmeSettings):
    if s.ca_id is not None:
        row = service.get_ca(s.ca_id)
        if not row["key_enc"]:
            raise ValueError("that CA has no private key and cannot issue certificates")
        cax.assert_can_sign(service.ca_cert(row))
        db.set_setting("acme_ca_id", s.ca_id)
    if s.cert_days is not None:
        db.set_setting("acme_cert_days", s.cert_days)
    return {"ok": True}


@api.post("/server-tls")
def server_tls(r: ServerTlsReq):
    """Issue a TLS certificate for this very application and store it where the entrypoint picks it up."""
    key = cax.generate_key(r.key_type)
    names = [h.strip() for h in r.hostnames if h.strip()]
    if not names:
        raise ValueError("at least one hostname is required")
    sans = cax.parse_sans(names)
    cn = names[0] if len(names[0]) <= 64 and not names[0].replace(".", "").isdigit() else "ca-server"
    _, cert = service.sign_with_ca(r.ca_id, subject=cax.build_name(cn=cn), public_key=key.public_key(),
                                   profile="server", sans=sans, days=r.days, source="server-tls")
    d = os.path.join(settings.DATA_DIR, "tls")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "server.crt"), "w") as f:
        f.write(cax.cert_pem(cert) + service.chain_pem(r.ca_id, include_root=False))
    fd = os.open(os.path.join(d, "server.key"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(cax.key_pem(key))
    return {"ok": True, "message": "Certificate stored. Restart the container to serve the UI and ACME over HTTPS."}


app.include_router(api)


# ------------------------------------------------------------------ public endpoints

@app.get("/ca/{name}")
def public_ca(name: str):
    stem, _, ext = name.rpartition(".")
    if not stem.isdigit() or ext not in ("pem", "crt"):
        raise HTTPException(404)
    row = service.get_ca(int(stem))
    if ext == "pem":
        return Response(row["cert_pem"], media_type="application/x-pem-file")
    return Response(service.ca_cert(row).public_bytes(serialization.Encoding.DER), media_type="application/pkix-cert")


@app.get("/crl/{name}")
def public_crl(name: str):
    stem, _, ext = name.rpartition(".")
    if not stem.isdigit() or ext != "crl":
        raise HTTPException(404)
    crl = service.build_crl_for(int(stem))
    return Response(crl.public_bytes(serialization.Encoding.DER), media_type="application/pkix-crl")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/", dependencies=[Depends(admin)])
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))
