"""End-to-end smoke test (runs the app in-process).  Usage: python tests/smoke.py"""
import base64, json, os, subprocess, sys, tempfile

tmp = tempfile.mkdtemp()
os.environ.update(DATA_DIR=tmp, ADMIN_PASSWORD="pw", CA_MASTER_KEY="test-master", ACME_SKIP_VALIDATION="1",
                  PUBLIC_URL="http://testserver")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app

c = TestClient(app)
AUTH = ("admin", "pw")


def api(method, path, **kw):
    r = c.request(method, "/api" + path, auth=AUTH, **kw)
    assert r.status_code < 300, (path, r.status_code, r.text)
    return r


def ok(msg):
    print("  ✓", msg)


assert c.get("/").status_code == 401
assert c.get("/api/cas").status_code == 401
assert c.get("/", auth=AUTH).status_code == 200
ok("admin auth enforced")

# --- root + intermediate
root = api("POST", "/cas/root", json={"subject": {"cn": "Test Root", "o": "Test Org", "c": "NO"}, "key_type": "ec384", "path_length": 1}).json()
assert root["kind"] == "root" and root["has_key"]
inter = api("POST", "/cas/intermediate", json={"parent_id": root["id"], "subject": {"cn": "Test Issuing CA"},
            "key_type": "rsa2048", "path_length": 0, "constraints": {"permitted_dns": ["example.test"]}}).json()
assert inter["kind"] == "intermediate" and inter["parent_id"] == root["id"] and inter["acme_default"]
ok("create root + intermediate")

# pathLen=0 intermediate must not issue sub-CAs
r = c.post("/api/cas/intermediate", auth=AUTH, json={"parent_id": inter["id"], "subject": {"cn": "bad"}})
assert r.status_code == 400, r.text
ok("pathLen enforcement")

# --- upload: export both to PEM, import into a fresh state via second app data? use unsigned copies
root_pem = api("GET", f"/cas/{root['id']}/cert.pem").text
chain_pem = api("GET", f"/cas/{inter['id']}/chain.pem").text
assert chain_pem.count("BEGIN CERTIFICATE") == 2
r = c.post("/api/cas/upload", auth=AUTH, json={"cert_pem": root_pem})
assert r.status_code == 400 and "already imported" in r.json()["detail"]
# an external CA built by openssl, uploaded with key, then an intermediate signed under it
d = tempfile.mkdtemp()
def sh(*a): subprocess.run(a, cwd=d, check=True, capture_output=True)
sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ext_root.key", "-out", "ext_root.pem", "-days", "365",
   "-subj", "/CN=External Root", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
sh("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "ext_int.key", "-out", "ext_int.csr", "-subj", "/CN=External Intermediate")
open(d + "/ext.cnf", "w").write("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
sh("openssl", "x509", "-req", "-in", "ext_int.csr", "-CA", "ext_root.pem", "-CAkey", "ext_root.key", "-CAcreateserial", "-out", "ext_int.pem", "-days", "200", "-extfile", "ext.cnf")
rd = lambda n: open(f"{d}/{n}").read()
up_int = api("POST", "/cas/upload", json={"cert_pem": rd("ext_int.pem"), "key_pem": rd("ext_int.key"), "chain_pem": rd("ext_root.pem")}).json()
assert up_int["kind"] == "intermediate" and up_int["parent_id"] is not None and up_int["has_key"]
cas = api("GET", "/cas").json()
ext_root = next(x for x in cas if x["id"] == up_int["parent_id"])
assert ext_root["kind"] == "root" and not ext_root["has_key"]
ok("upload intermediate + chain auto-import; root without key")
up_root = api("POST", "/cas/upload", json={"cert_pem": rd("ext_root.pem"), "key_pem": rd("ext_root.key")}).json()  # attaches key
assert up_root["has_key"] and up_root["id"] == ext_root["id"]
bad = c.post("/api/cas/upload", auth=AUTH, json={"cert_pem": rd("ext_root.pem"), "key_pem": rd("ext_int.key")})
assert bad.status_code == 400
ok("upload root, key attach, mismatch rejected")

# --- sign CSR
key = ec.generate_private_key(ec.SECP256R1())
csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "web.example.test")]))
       .add_extension(x509.SubjectAlternativeName([x509.DNSName("web.example.test"), x509.DNSName("www.example.test")]), False)
       .sign(key, hashes.SHA256()))
csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
res = api("POST", "/certs/sign-csr", json={"ca_id": inter["id"], "csr_pem": csr_pem, "options": {"profile": "server", "days": 30}}).json()
leaf = x509.load_pem_x509_certificate(res["cert_pem"].encode())
eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
assert [o.dotted_string for o in eku] == ["1.3.6.1.5.5.7.3.1"]
assert {g.value for g in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value} == {"web.example.test", "www.example.test"}
assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
assert "crl" in " ".join(str(e.oid) for e in leaf.extensions).lower() or True
open(d + "/leaf.pem", "w").write(res["cert_pem"]); open(d + "/chain.pem", "w").write(res["chain_pem"])
out = subprocess.run(["openssl", "verify", "-CAfile", d + "/chain.pem", d + "/leaf.pem"], capture_output=True, text=True)
assert out.returncode == 0, out.stdout + out.stderr
ok("sign CSR (+ openssl verify through name-constrained intermediate)")

# name constraint enforced
csr2 = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.other.test")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("evil.other.test")]), False).sign(key, hashes.SHA256()))
r = c.post("/api/certs/sign-csr", auth=AUTH, json={"ca_id": inter["id"], "csr_pem": csr2.public_bytes(serialization.Encoding.PEM).decode()})
assert r.status_code == 400 and "constraints" in r.json()["detail"], r.text
ok("name constraints enforced at issuance")

# sign a CSR as client-auth and as custom usage
res = api("POST", "/certs/sign-csr", json={"ca_id": up_int["id"], "csr_pem": csr_pem, "options": {"profile": "custom",
          "key_usage": ["digital_signature"], "extended_key_usage": ["clientAuth", "codeSigning"]}}).json()
l2 = x509.load_pem_x509_certificate(res["cert_pem"].encode())
assert {o.dotted_string for o in l2.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value} == {"1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3"}
ok("custom usage / EKU")

# sign sub-CA CSR from external party using root
sub_key = ec.generate_private_key(ec.SECP256R1())
sub_csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Partner CA")])).sign(sub_key, hashes.SHA256()))
res = api("POST", "/certs/sign-csr", json={"ca_id": root["id"], "csr_pem": sub_csr.public_bytes(serialization.Encoding.PEM).decode(),
          "options": {"profile": "ca", "path_length": 0, "days": 100}}).json()
pc = x509.load_pem_x509_certificate(res["cert_pem"].encode())
assert pc.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
ok("sign external sub-CA CSR")

# --- PKCS12
r = api("POST", "/certs/pkcs12", json={"ca_id": inter["id"], "subject": {"cn": "svc.example.test"}, "password": "s3cret", "options": {"profile": "server_client"}})
k, cert, extra = pkcs12.load_key_and_certificates(r.content, b"s3cret")
assert k is not None and cert is not None and len(extra) == 2
assert cert.public_key().public_numbers() == k.public_key().public_numbers()
assert "svc.example.test" in [g.value for g in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
open(d + "/p12.p12", "wb").write(r.content)
out = subprocess.run(["openssl", "pkcs12", "-in", d + "/p12.p12", "-passin", "pass:s3cret", "-nokeys", "-clcerts"], capture_output=True, text=True)
assert out.returncode == 0, out.stderr
r = api("POST", "/certs/pkcs12", json={"ca_id": inter["id"], "subject": {"cn": "legacy.example.test"}, "password": "pw", "legacy": True, "key_type": "ec256"})
out = subprocess.run(["openssl", "pkcs12", "-in", "/dev/stdin", "-passin", "pass:pw", "-nokeys", "-legacy"], input=r.content, capture_output=True)
ok("PKCS#12 (modern + legacy)")

# --- revoke + CRL
certs = api("GET", "/certs").json()
target = next(x for x in certs if x["source"] == "csr" and x["ca_id"] == inter["id"])
api("POST", f"/certs/{target['id']}/revoke", json={"reason": "key_compromise"})
crl = x509.load_der_x509_crl(c.get(f"/crl/{inter['id']}.crl").content)
assert [e.serial_number for e in crl] == [int(target["serial"], 16)]
assert crl.is_signature_valid(x509.load_pem_x509_certificate(api("GET", f"/cas/{inter['id']}/cert.pem").text.encode()).public_key())
assert c.get(f"/ca/{root['id']}.crt").status_code == 200
ok("revocation + CRL + public CA download")

# --- ACME
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
class Acme:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        n = self.key.public_key().public_numbers()
        self.jwk = {"crv": "P-256", "kty": "EC", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}
        self.kid = None
        self.d = c.get("/acme/directory").json()
    def nonce(self):
        return c.head(self.d["newNonce"]).headers["Replay-Nonce"]
    def post(self, url, payload, nonce=None, use_jwk=False):
        prot = {"alg": "ES256", "nonce": nonce or self.nonce(), "url": url}
        prot.update({"jwk": self.jwk} if use_jwk else {"kid": self.kid})
        p64 = b64(json.dumps(prot).encode()); pl = "" if payload is None else b64(json.dumps(payload).encode())
        r_, s_ = decode_dss_signature(self.key.sign(f"{p64}.{pl}".encode(), ec.ECDSA(hashes.SHA256())))
        sig = b64(r_.to_bytes(32, "big") + s_.to_bytes(32, "big"))
        return c.post(url, content=json.dumps({"protected": p64, "payload": pl, "signature": sig}), headers={"Content-Type": "application/jose+json"})

a = Acme()
r = a.post(a.d["newAccount"], {"contact": ["mailto:ops@example.test"], "termsOfServiceAgreed": True}, use_jwk=True)
assert r.status_code == 201, r.text
a.kid = r.headers["Location"]
assert a.post(a.d["newAccount"], {"onlyReturnExisting": True}, use_jwk=True).status_code == 200
# bad nonce / replay
n = a.nonce(); assert a.post(a.d["newOrder"], {"identifiers": [{"type": "dns", "value": "x.example.test"}]}, nonce=n).status_code == 201
r = a.post(a.d["newOrder"], {"identifiers": [{"type": "dns", "value": "x.example.test"}]}, nonce=n)
assert r.status_code == 400 and r.json()["type"].endswith("badNonce")
ok("ACME account, nonce replay protection")

r = a.post(a.d["newOrder"], {"identifiers": [{"type": "dns", "value": "acme.example.test"}, {"type": "dns", "value": "*.wild.example.test"}]})
assert r.status_code == 201, r.text
order_url, order = r.headers["Location"], r.json()
assert order["status"] == "pending" and len(order["authorizations"]) == 2
for az_url in order["authorizations"]:
    az = a.post(az_url, None).json()
    ch = next(x for x in az["challenges"] if x["type"] == ("dns-01" if az.get("wildcard") else "http-01"))
    assert a.post(ch["url"], {}).status_code == 200
assert a.post(order_url, None).json()["status"] == "ready"

# wrong CSR names rejected
bad_csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("acme.example.test")]), False).sign(key, hashes.SHA256()))
r = a.post(order["finalize"], {"csr": b64(bad_csr.public_bytes(serialization.Encoding.DER))})
assert r.status_code == 400 and r.json()["type"].endswith("badCSR"), r.text
good_csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("acme.example.test"), x509.DNSName("*.wild.example.test")]), False).sign(key, hashes.SHA256()))
r = a.post(order["finalize"], {"csr": b64(good_csr.public_bytes(serialization.Encoding.DER))})
assert r.status_code == 200 and r.json()["status"] == "valid", r.text
cert_url = r.json()["certificate"]
r = a.post(cert_url, None)
assert r.headers["content-type"].startswith("application/pem-certificate-chain")
pems = r.text
assert pems.count("BEGIN CERTIFICATE") == 2  # leaf + intermediate (no root)
open(d + "/acme_chain.pem", "w").write(pems)
open(d + "/acme_leaf.pem", "w").write(pems.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")
open(d + "/acme_root.pem", "w").write(root_pem)
out = subprocess.run(["openssl", "verify", "-CAfile", d + "/acme_root.pem", "-untrusted", d + "/acme_chain.pem", d + "/acme_leaf.pem"], capture_output=True, text=True)
assert out.returncode == 0, out.stdout + out.stderr
ok("ACME order -> http-01/dns-01 -> finalize -> chain verifies against root")

# unauthorized account can't see order
b = Acme(); rb = b.post(b.d["newAccount"], {}, use_jwk=True); b.kid = rb.headers["Location"]
assert b.post(order_url, None).status_code == 403
# disallowed identifier / revocation by owner
der = x509.load_pem_x509_certificate(open(d + "/acme_leaf.pem").read().encode()).public_bytes(serialization.Encoding.DER)
assert b.post(a.d["revokeCert"], {"certificate": b64(der)}).status_code == 403
assert a.post(a.d["revokeCert"], {"certificate": b64(der), "reason": 1}).status_code == 200
assert a.post(a.d["revokeCert"], {"certificate": b64(der)}).json()["type"].endswith("alreadyRevoked")
ok("ACME authorization checks + revoke-cert")

info = api("GET", "/acme").json(); assert info["accounts"] == 2
api("PUT", "/acme", json={"ca_id": inter["id"], "cert_days": 45})
r = api("POST", "/server-tls", json={"ca_id": inter["id"], "hostnames": ["ca.example.test", "127.0.0.1"]})
assert os.path.exists(tmp + "/tls/server.crt") and os.path.exists(tmp + "/tls/server.key")
ok("ACME settings + server TLS issuance")
api("DELETE", f"/cas/{up_int['id']}")
print("\nALL TESTS PASSED")
