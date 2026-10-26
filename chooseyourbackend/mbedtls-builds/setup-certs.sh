#!/bin/bash
set -euo pipefail

D=/etc/goahead/certs
mkdir -p "$D"
cd "$D"

openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=goahead-dh-poc/O=PoC" \
    -keyout server.key -out server.crt

exec goahead \
    --auth /etc/goahead/auth.txt \
    --route /etc/goahead/route.txt \
    --log stdout:5 \
    /var/www/goahead \
    "https://0.0.0.0:443"
