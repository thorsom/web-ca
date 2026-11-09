"""Pure cryptographic operations: key generation, certificate building, CRLs, PKCS#12."""
from __future__ import annotations

import datetime as dt
import ipaddress
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, AuthorityInformationAccessOID

UTC = dt.timezone.utc

KEY_TYPES = ["rsa2048", "rsa3072", "rsa4096", "ec256", "ec384"]

KU_NAMES = ["digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
            "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only"]

EKU_MAP = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "OCSPSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
    "smartcardLogin": ExtendedKeyUsageOID.SMARTCARD_LOGON,
    "ipsecIKE": ExtendedKeyUsageOID.IPSEC_IKE,
    "anyExtendedKeyUsage": ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
}

# profile -> (key usage, extended key usage, is_ca)
PRESETS = {
    "server": (["digital_signature", "key_encipherment"], ["serverAuth"], False),
    "client": (["digital_signature", "key_encipherment"], ["clientAuth"], False),
    "server_client": (["digital_signature", "key_encipherment"], ["serverAuth", "clientAuth"], False),
    "code_signing": (["digital_signature"], ["codeSigning"], False),
    "email": (["digital_signature", "content_commitment", "key_encipherment"], ["emailProtection"], False),
    "timestamping": (["digital_signature", "content_commitment"], ["timeStamping"], False),
    "ocsp_signing": (["digital_signature"], ["OCSPSigning"], False),
    "ca": (["key_cert_sign", "crl_sign"], [], True),
    "custom": ([], [], False),
}
PROFILE_LABELS = {
    "server": "TLS server", "client": "TLS client", "server_client": "TLS server + client",
    "code_signing": "Code signing", "email": "S/MIME e-mail", "timestamping": "Time stamping",
    "ocsp_signing": "OCSP responder", "ca": "Sub-CA (intermediate)", "custom": "Custom",
}

REVOKE_REASONS = {
    "unspecified": None,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
}
ACME_REASON_CODES = {0: "unspecified", 1: "key_compromise", 2: "ca_compromise", 3: "affiliation_changed",
                     4: "superseded", 5: "cessation_of_operation", 6: "certificate_hold", 9: "privilege_withdrawn"}


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


def iso(d: dt.datetime) -> str:
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- keys / names

def generate_key(key_type: str):
    if key_type not in KEY_TYPES:
        raise ValueError(f"unknown key type {key_type!r}")
    if key_type.startswith("rsa"):
        return rsa.generate_private_key(65537, int(key_type[3:]))
    return ec.generate_private_key(ec.SECP256R1() if key_type == "ec256" else ec.SECP384R1())


def build_name(cn=None, o=None, ou=None, c=None, st=None, l=None, email=None) -> x509.Name:
    attrs = []
    for oid, val in ((NameOID.COUNTRY_NAME, c), (NameOID.STATE_OR_PROVINCE_NAME, st), (NameOID.LOCALITY_NAME, l),
                     (NameOID.ORGANIZATION_NAME, o), (NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
                     (NameOID.COMMON_NAME, cn), (NameOID.EMAIL_ADDRESS, email)):
        if val and val.strip():
            attrs.append(x509.NameAttribute(oid, val.strip()))
    if not attrs:
        raise ValueError("the subject needs at least one attribute (e.g. a common name)")
    return x509.Name(attrs)


def common_name(name: x509.Name) -> str | None:
    v = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return v[0].value if v else None


def sig_hash(key):
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return hashes.SHA384() if key.curve.key_size >= 384 else hashes.SHA256()
    return hashes.SHA384() if key.key_size >= 4096 else hashes.SHA256()


def pub_der(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def key_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def load_cert_pem(pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(pem.strip().encode())
    except Exception as e:
        raise ValueError(f"invalid PEM certificate: {e}")


def load_certs_pem(pem: str) -> list[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(pem.strip().encode())
    except Exception as e:
        raise ValueError(f"invalid PEM certificate bundle: {e}")


def load_csr_pem(pem: str) -> x509.CertificateSigningRequest:
    try:
        csr = x509.load_pem_x509_csr(pem.strip().encode())
    except Exception as e:
        raise ValueError(f"invalid PEM CSR: {e}")
    check_csr(csr)
    return csr


def check_csr(csr: x509.CertificateSigningRequest):
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid (proof of possession failed)")
    pub = csr.public_key()
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        raise ValueError("RSA keys smaller than 2048 bits are not accepted")


def load_key_pem(pem: str, password: str | None = None):
    try:
        return serialization.load_pem_private_key(pem.strip().encode(), password.encode() if password else None)
    except TypeError:
        raise ValueError("the private key is encrypted - please supply its password")
    except Exception as e:
        raise ValueError(f"invalid private key: {e}")


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def serial_hex(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "x")


def get_sans(cert_or_csr) -> list[x509.GeneralName]:
    try:
        return list(cert_or_csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return []


def san_strings(gns) -> list[str]:
    out = []
    for g in gns:
        if isinstance(g, x509.DNSName):
            out.append(f"DNS:{g.value}")
        elif isinstance(g, x509.IPAddress):
            out.append(f"IP:{g.value}")
        elif isinstance(g, x509.RFC822Name):
            out.append(f"email:{g.value}")
        elif isinstance(g, x509.UniformResourceIdentifier):
            out.append(f"URI:{g.value}")
    return out


def parse_san(v: str) -> x509.GeneralName:
    v = v.strip()
    low = v.lower()
    if low.startswith("dns:"):
        return x509.DNSName(v[4:].strip())
    if low.startswith("ip:"):
        return x509.IPAddress(ipaddress.ip_address(v[3:].strip()))
    if low.startswith("email:"):
        return x509.RFC822Name(v[6:].strip())
    if low.startswith("uri:"):
        return x509.UniformResourceIdentifier(v[4:].strip())
    try:
        return x509.IPAddress(ipaddress.ip_address(v))
    except ValueError:
        pass
    if "://" in v:
        return x509.UniformResourceIdentifier(v)
    if "@" in v:
        return x509.RFC822Name(v)
    return x509.DNSName(v)


def parse_sans(values) -> list[x509.GeneralName]:
    out = []
    for v in values or []:
        if v and v.strip():
            try:
                out.append(parse_san(v))
            except ValueError as e:
                raise ValueError(f"invalid subject alternative name {v!r}: {e}")
    return out


# ---------------------------------------------------------------- policy helpers

def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:
        return False


def is_issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    if child.issuer != parent.subject:
        return False
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:
        return False


def basic_constraints(cert: x509.Certificate):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return None


def assert_can_sign(cert: x509.Certificate):
    bc = basic_constraints(cert)
    if not bc or not bc.ca:
        raise ValueError("the selected certificate is not a CA certificate")
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_cert_sign:
            raise ValueError("the CA certificate's key usage does not allow certificate signing")
    except x509.ExtensionNotFound:
        pass
    if cert.not_valid_after_utc < now():
        raise ValueError("the CA certificate has expired")


def check_ca_parent(parent: x509.Certificate, path_length: int | None) -> int | None:
    """Validate/adjust path length for a new sub-CA below `parent`."""
    bc = basic_constraints(parent)
    if bc is not None and bc.path_length is not None:
        if bc.path_length == 0:
            raise ValueError("the issuing CA has pathLen=0 and cannot issue sub-CA certificates")
        limit = bc.path_length - 1
        if path_length is None or path_length > limit:
            if path_length is not None:
                raise ValueError(f"path length {path_length} exceeds what the issuing CA allows (max {limit})")
            return limit
    return path_length


def check_name_constraints(issuer: x509.Certificate, sans: list[x509.GeneralName]):
    try:
        nc = issuer.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return

    def under(name: str, base: str) -> bool:
        name, base = name.lower().lstrip("*."), base.lower().lstrip(".")
        return name == base or name.endswith("." + base)

    perm = [p for p in (nc.permitted_subtrees or []) if isinstance(p, x509.DNSName)]
    excl = [p for p in (nc.excluded_subtrees or []) if isinstance(p, x509.DNSName)]
    for g in sans:
        if not isinstance(g, x509.DNSName):
            continue
        if any(under(g.value, e.value) for e in excl):
            raise ValueError(f"{g.value} is excluded by the issuing CA's name constraints")
        if perm and not any(under(g.value, p.value) for p in perm):
            raise ValueError(f"{g.value} is outside the issuing CA's permitted name constraints")


def build_name_constraints(permitted_dns=(), excluded_dns=(), permitted_ip=(), excluded_ip=()):
    def mk(dns, ips):
        out = [x509.DNSName(d.strip()) for d in dns if d.strip()]
        out += [x509.IPAddress(ipaddress.ip_network(i.strip(), strict=False)) for i in ips if i.strip()]
        return out or None
    p, e = mk(permitted_dns, permitted_ip), mk(excluded_dns, excluded_ip)
    return x509.NameConstraints(p, e) if (p or e) else None


def resolve_usage(profile: str, key_usage, eku, public_key, is_ca_custom=False):
    if profile not in PRESETS:
        raise ValueError(f"unknown profile {profile!r}")
    ku, ek, is_ca = PRESETS[profile]
    ku, ek = list(ku), list(ek)
    if profile in ("custom", "ca"):
        if key_usage or profile == "custom":
            ku = list(key_usage or [])
        ek = list(eku or [])
        if profile == "custom":
            is_ca = bool(is_ca_custom)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        ku = [k for k in ku if k not in ("key_encipherment", "data_encipherment")]
    if is_ca and "key_cert_sign" not in ku:
        ku.append("key_cert_sign")
    for k in ku:
        if k not in KU_NAMES:
            raise ValueError(f"unknown key usage {k!r}")
    for k in ek:
        if k not in EKU_MAP:
            raise ValueError(f"unknown extended key usage {k!r}")
    return is_ca, ku, ek


def key_usage_ext(names) -> x509.KeyUsage:
    flags = {n: n in names for n in KU_NAMES}
    if (flags["encipher_only"] or flags["decipher_only"]) and not flags["key_agreement"]:
        raise ValueError("encipher_only / decipher_only require key_agreement")
    return x509.KeyUsage(**flags)


# ---------------------------------------------------------------- issuance

def issue_certificate(*, issuer_cert, issuer_key, subject: x509.Name, public_key, profile="server",
                      key_usage=(), extended_key_usage=(), sans=(), days=365, path_length=None,
                      name_constraints: x509.NameConstraints | None = None, is_ca_custom=False,
                      urls: dict | None = None) -> x509.Certificate:
    """Issue (or self-sign when issuer_cert is None) a certificate."""
    is_ca, ku, ek = resolve_usage(profile, key_usage, extended_key_usage, public_key, is_ca_custom)
    sans = list(sans)
    if days < 1:
        raise ValueError("validity must be at least one day")

    nb = now() - dt.timedelta(minutes=5)
    na = nb + dt.timedelta(days=days, minutes=5)
    if issuer_cert is not None:
        assert_can_sign(issuer_cert)
        if is_ca:
            path_length = check_ca_parent(issuer_cert, path_length)
        elif sans:
            check_name_constraints(issuer_cert, sans)
        na = min(na, issuer_cert.not_valid_after_utc)
        if na <= nb:
            raise ValueError("the issuing CA is about to expire")
        issuer_name = issuer_cert.subject
    else:
        issuer_name = subject

    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(public_key)
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na))
    b = b.add_extension(x509.BasicConstraints(ca=is_ca, path_length=path_length if is_ca else None), critical=True)
    if ku:
        b = b.add_extension(key_usage_ext(ku), critical=True)
    if ek:
        b = b.add_extension(x509.ExtendedKeyUsage([EKU_MAP[k] for k in ek]), critical="timeStamping" in ek and len(ek) == 1)
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=len(subject) == 0)
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    if issuer_cert is None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
    else:
        try:
            ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
        except x509.ExtensionNotFound:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())
        b = b.add_extension(aki, critical=False)
    if is_ca and name_constraints is not None:
        b = b.add_extension(name_constraints, critical=True)
    if urls and issuer_cert is not None:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(urls["aia"]))]), critical=False)
        b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(urls["crl"])], relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
    return b.sign(issuer_key, sig_hash(issuer_key))


def build_crl(ca_cert: x509.Certificate, ca_key, revoked) -> x509.CertificateRevocationList:
    """revoked: iterable of (serial_int, datetime, reason_name)."""
    t = now()
    b = (x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject)
         .last_update(t - dt.timedelta(minutes=1)).next_update(t + dt.timedelta(days=7))
         .add_extension(x509.CRLNumber(int(time.time())), critical=False))
    try:
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
    except x509.ExtensionNotFound:
        pass
    for serial, when, reason in revoked:
        rb = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
        flag = REVOKE_REASONS.get(reason or "unspecified")
        if flag is not None:
            rb = rb.add_extension(x509.CRLReason(flag), critical=False)
        b = b.add_revoked_certificate(rb.build())
    return b.sign(ca_key, sig_hash(ca_key))


# ---------------------------------------------------------------- PKCS#12

def make_pkcs12(key, cert, chain, password: str, name: str, legacy=False) -> bytes:
    if not password:
        raise ValueError("a password is required to protect the PKCS#12 file")
    pw = password.encode()
    if legacy:
        enc = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000)
               .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(pw))
    else:
        enc = serialization.BestAvailableEncryption(pw)
    return pkcs12.serialize_key_and_certificates(name.encode() if name else None, key, cert, chain or None, enc)
