import os
import ssl
import sys
import urllib.request

port = os.environ.get("PORT", "8000")
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
for scheme in ("http", "https"):
    try:
        with urllib.request.urlopen(f"{scheme}://127.0.0.1:{port}/healthz", timeout=3, context=ctx) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        continue
sys.exit(1)
