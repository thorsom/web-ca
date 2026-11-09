#!/bin/sh
set -e

ARGS="--host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=* --no-server-header"

# If a TLS certificate was issued for this server (UI: ACME & TLS -> "Serve this application over HTTPS"),
# or mounted manually, serve HTTPS directly.
if [ -f "$DATA_DIR/tls/server.crt" ] && [ -f "$DATA_DIR/tls/server.key" ]; then
  echo "TLS material found in $DATA_DIR/tls - serving HTTPS"
  ARGS="$ARGS --ssl-certfile $DATA_DIR/tls/server.crt --ssl-keyfile $DATA_DIR/tls/server.key"
fi

exec uvicorn app.main:app $ARGS
