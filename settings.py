"""Runtime configuration (environment variables) and persisted bootstrap secrets."""
import logging
import os
import secrets

log = logging.getLogger("ca")

DATA_DIR = os.environ.get("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)

# Externally visible base URL, e.g. https://ca.example.internal:8443 (no trailing slash).
# Used for ACME URLs behind proxies and for AIA / CRL URLs embedded in issued certificates.
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")

# ACME
ACME_SKIP_VALIDATION = os.environ.get("ACME_SKIP_VALIDATION", "").lower() in ("1", "true", "yes")
ACME_ALLOWED_DOMAINS = [d.strip().lower().lstrip(".") for d in os.environ.get("ACME_ALLOWED_DOMAINS", "").split(",") if d.strip()]
ACME_HTTP01_PORT = int(os.environ.get("ACME_HTTP01_PORT", "80"))
ACME_DEFAULT_CERT_DAYS = int(os.environ.get("ACME_CERT_DAYS", "90"))

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")


def _persisted_secret(filename: str, env_value: str | None, announce: str | None = None) -> str:
    if env_value:
        return env_value
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    value = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    if announce:
        log.warning("%s: %s  (stored in %s)", announce, value, path)
    return value


# Passphrase protecting CA private keys at rest (PKCS#8 encryption). Keep it safe: losing it = losing the CA keys.
MASTER_KEY = _persisted_secret(".master_key", os.environ.get("CA_MASTER_KEY"))
ADMIN_PASSWORD = _persisted_secret(".admin_password", os.environ.get("ADMIN_PASSWORD"),
                                   announce=f"Generated admin password for user '{ADMIN_USER}'")
