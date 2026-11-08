# Web CA

Containerised certificate authority with a web UI, REST API and ACME (RFC 8555) server.

## Run
```bash
docker compose up -d --build
docker compose logs ca | grep "admin password"    # only if you didn't set ADMIN_PASSWORD
# open http://localhost:8000  (user: admin)
```
Set `ADMIN_PASSWORD`, `CA_MASTER_KEY` (encrypts CA keys at rest – back it up separately) and `PUBLIC_URL`
(e.g. `https://ca.example.internal:8000`, embedded as ACME base + AIA/CRL URLs) via environment or an `.env` file.

## Features (UI tabs)
- **Authorities**: create root; create intermediate (path length, name constraints); upload existing root/intermediate (PEM, optional key + parent chain; root vs intermediate auto-detected, chain auto-linked).
- **Issue**: sign a CSR (profiles: TLS server/client/both, code signing, S/MIME, timestamping, OCSP, sub-CA, or custom key usage / EKU / CA flag / path length / name constraints); generate key + certificate as password-protected **PKCS#12** (key is not stored).
- **Certificates**: list, download PEM / full chain, revoke (CRL at `/crl/<caId>.crl`; CA certs at `/ca/<caId>.pem|.crt`).
- **ACME & TLS**: directory at `/acme/directory`; http-01, dns-01 (wildcards), dns + ip identifiers. Choose the issuing CA and lifetime. Optionally issue a TLS cert for the app itself and restart to serve HTTPS (most ACME clients require HTTPS).

ACME env: `ACME_ALLOWED_DOMAINS=example.internal,corp.local` restricts issuable names; `ACME_HTTP01_PORT`; `ACME_SKIP_VALIDATION=1` (testing only!).

## Security notes
- Admin UI/API use HTTP Basic auth – run behind HTTPS. ACME and `/ca`, `/crl` are public by design.
- http-01 validation makes the server fetch URLs for client-supplied hostnames; restrict with `ACME_ALLOWED_DOMAINS` and network policy.
- Keep an offline root in real deployments: upload the root *without* its key and use an intermediate for issuing.

## Test
`python tests/smoke.py` (needs `openssl`) runs the whole flow in-process.
