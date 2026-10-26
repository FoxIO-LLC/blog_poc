#!/bin/bash
set -euo pipefail

D=/etc/goahead/certs
mkdir -p "$D"
cd "$D"

openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=test-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout ca.key -out ca.crt
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout server.key -out server.csr
openssl x509 -req -days 365 -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
openssl req -newkey rsa:2048 -nodes -subj "/CN=valid-client" \
    -keyout client-valid.key -out client-valid.csr
openssl x509 -req -days 365 -in client-valid.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial -out client-valid.crt
openssl req -newkey rsa:2048 -nodes -subj "/CN=revoked-client" \
    -keyout client-revoked.key -out client-revoked.csr
openssl x509 -req -days 365 -in client-revoked.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial -out client-revoked.crt

touch index.txt
echo 1000 > serial
echo 1000 > crlnumber
cat > ca.cnf <<'EOF'
[ca]
default_ca = CA_default

[CA_default]
database = /etc/goahead/certs/index.txt
serial = /etc/goahead/certs/serial
crlnumber = /etc/goahead/certs/crlnumber
private_key = /etc/goahead/certs/ca.key
certificate = /etc/goahead/certs/ca.crt
default_md = sha256
default_crl_days = 365
policy = policy_any

[policy_any]
commonName = optional
EOF

openssl ca -config ca.cnf -revoke client-revoked.crt -batch
openssl ca -config ca.cnf -gencrl -out crl.pem -batch

exec goahead \
    --auth /etc/goahead/auth.txt \
    --route /etc/goahead/route.txt \
    --log stdout:4 \
    /var/www/goahead \
    "https://0.0.0.0:443"
