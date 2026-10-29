#!/usr/bin/env bash
# Generate a local, self-signed TLS certificate for development use.
# Prefers mkcert (trusted by the local system) and falls back to openssl.
set -euo pipefail

cd "$(dirname "$0")"

if command -v mkcert >/dev/null 2>&1; then
  mkcert -install
  mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1
else
  echo "mkcert not found, falling back to openssl (browser will show a warning)." >&2
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout key.pem -out cert.pem -days 365 \
    -subj "/CN=localhost"
fi

echo "Certificate written to certs/cert.pem and certs/key.pem"
