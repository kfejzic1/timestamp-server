#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CERT_DIR"

DAYS=365
RSA_BITS=2048

echo "==> Generating Certificate Authority"
openssl req -x509 -newkey rsa:$RSA_BITS -nodes \
  -keyout ca.key -out ca.crt -days $DAYS \
  -subj "/CN=FROST-TSA-CA/O=FROST Timestamp Authority"

generate_cert() {
  local name="$1"
  shift
  local san="$*"

  echo "==> Generating certificate for: $name (SANs: $san)"

  cat > "${name}.ext" <<EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=${san}
EXTEOF

  openssl req -newkey rsa:$RSA_BITS -nodes \
    -keyout "${name}.key" -out "${name}.csr" \
    -subj "/CN=${name}/O=FROST Timestamp Authority"

  openssl x509 -req -in "${name}.csr" \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "${name}.crt" -days $DAYS \
    -extfile "${name}.ext"

  rm -f "${name}.csr" "${name}.ext"
}

generate_cert "gateway"    "DNS:gateway,DNS:localhost,IP:127.0.0.1"
generate_cert "aggregator" "DNS:aggregator,DNS:localhost,IP:127.0.0.1"
generate_cert "signer"     "DNS:signer,DNS:*.signer,DNS:localhost,IP:127.0.0.1"

rm -f ca.srl

echo "==> Certificates generated in $CERT_DIR"
ls -la "$CERT_DIR"/*.crt "$CERT_DIR"/*.key
