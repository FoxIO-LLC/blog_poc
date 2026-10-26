#!/bin/bash
set -euo pipefail

IMAGE_VULN=goahead-libressl-336
IMAGE_FIXED=goahead-libressl-431
NAME_VULN=${NAME_VULN:-goahead-libressl-336}
NAME_FIXED=${NAME_FIXED:-goahead-libressl-431}
PORT_VULN=${PORT_VULN:-4443}
PORT_FIXED=${PORT_FIXED:-4445}
CURL=curl
[ -x /usr/bin/curl ] && CURL=/usr/bin/curl
D=/etc/goahead/certs

cleanup() {
    docker rm -f $NAME_VULN $NAME_FIXED >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    echo "RESULT: failed"
    exit 1
}

if [ "${REBUILD:-0}" = "1" ] || ! docker image inspect $IMAGE_VULN >/dev/null 2>&1; then
    docker build --platform linux/amd64 --build-arg LIBRESSL_VERSION=3.3.6 -t $IMAGE_VULN . -q
fi
if [ "${REBUILD:-0}" = "1" ] || ! docker image inspect $IMAGE_FIXED >/dev/null 2>&1; then
    docker build --platform linux/amd64 --build-arg LIBRESSL_VERSION=4.3.1 -t $IMAGE_FIXED . -q
fi

docker rm -f $NAME_VULN $NAME_FIXED >/dev/null 2>&1 || true
docker run --platform linux/amd64 -d --name $NAME_VULN -p $PORT_VULN:443 $IMAGE_VULN >/dev/null
docker run --platform linux/amd64 -d --name $NAME_FIXED -p $PORT_FIXED:443 $IMAGE_FIXED >/dev/null

for c in $NAME_VULN $NAME_FIXED; do
    for i in $(seq 1 60); do
        docker logs $c 2>&1 | grep -q 'Started https' && break
        sleep 1
    done
done

for c in $NAME_VULN $NAME_FIXED; do
    for f in attack-chain.pem attack-leaf.key client-legit.crt client-legit.key; do
        docker cp $c:$D/$f /tmp/$c-$f >/dev/null
    done
done

req() {
    $CURL -sk -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true
}

status() {
    if [ "$1" = "000" ]; then echo "rejected"; else echo "HTTP $1"; fi
}

R_NONE_V=$(req https://localhost:$PORT_VULN/index.html)
R_NONE_F=$(req https://localhost:$PORT_FIXED/index.html)
R_LEGIT_V=$(req --cert /tmp/$NAME_VULN-client-legit.crt --key /tmp/$NAME_VULN-client-legit.key https://localhost:$PORT_VULN/index.html)
R_LEGIT_F=$(req --cert /tmp/$NAME_FIXED-client-legit.crt --key /tmp/$NAME_FIXED-client-legit.key https://localhost:$PORT_FIXED/index.html)
R_ATTACK_V=$(req --cert /tmp/$NAME_VULN-attack-chain.pem --key /tmp/$NAME_VULN-attack-leaf.key https://localhost:$PORT_VULN/index.html)
R_ATTACK_F=$(req --cert /tmp/$NAME_FIXED-attack-chain.pem --key /tmp/$NAME_FIXED-attack-leaf.key https://localhost:$PORT_FIXED/index.html)

BODY=$($CURL -sk --cert /tmp/$NAME_VULN-attack-chain.pem --key /tmp/$NAME_VULN-attack-leaf.key \
    https://localhost:$PORT_VULN/index.html 2>/dev/null | tr -d '\n' || true)

TRACE_V=$(docker logs $NAME_VULN 2>&1 | grep -m1 'preverify_ok=0' | sed 's/.*VERIFY_CB_ENTRY: //' || true)
TRACE_F=$(docker logs $NAME_FIXED 2>&1 | grep -m1 'preverify_ok=0' | sed 's/.*VERIFY_CB_ENTRY: //' || true)
CERT_COUNT=$(grep -c 'BEGIN CERTIFICATE' /tmp/$NAME_VULN-attack-chain.pem)

echo "GoAhead 6.1.0 - mTLS chain-depth limit (VERIFY_DEPTH=10)"
echo "attacker chain: $CERT_COUNT certificates, self-signed root"
echo "------------------------------------------------------------"
printf '%-26s %-12s %-12s\n' "" "LibreSSL" "LibreSSL"
printf '%-26s %-12s %-12s\n' "" "3.3.6" "4.3.1"
printf '%-26s %-12s %-12s\n' "no client certificate" "$(status $R_NONE_V)" "$(status $R_NONE_F)"
printf '%-26s %-12s %-12s\n' "legitimate client cert" "$(status $R_LEGIT_V)" "$(status $R_LEGIT_F)"
printf '%-26s %-12s %-12s\n' "17-cert attack chain" "$(status $R_ATTACK_V)" "$(status $R_ATTACK_F)"
echo
echo "callback 3.3.6: $TRACE_V"
echo "callback 4.3.1: $TRACE_F"
echo
echo "protected content: $BODY"
echo

[ "$CERT_COUNT" = "17" ] || fail "attack chain has $CERT_COUNT certificates, expected 17"
[ "$R_NONE_V" = "000" ] || fail "no-cert request on 3.3.6 returned $R_NONE_V"
[ "$R_NONE_F" = "000" ] || fail "no-cert request on 4.3.1 returned $R_NONE_F"
[ "$R_LEGIT_V" = "200" ] || fail "legit cert on 3.3.6 returned $R_LEGIT_V"
[ "$R_LEGIT_F" = "200" ] || fail "legit cert on 4.3.1 returned $R_LEGIT_F"
[ "$R_ATTACK_V" = "200" ] || fail "over-depth chain on 3.3.6 returned $R_ATTACK_V (bypass not reproduced)"
[ "$R_ATTACK_F" = "000" ] || fail "over-depth chain on 4.3.1 returned $R_ATTACK_F (control failed)"
grep -q 'error=20' <<< "$TRACE_V" || fail "3.3.6 did not report error 20: '$TRACE_V'"
grep -q 'depth=10' <<< "$TRACE_V" || fail "3.3.6 reported wrong depth: '$TRACE_V'"
grep -q 'error=22' <<< "$TRACE_F" || fail "4.3.1 did not report error 22: '$TRACE_F'"
grep -q 'depth=10' <<< "$TRACE_F" || fail "4.3.1 reported wrong depth: '$TRACE_F'"
[ "$BODY" = "MUTUAL-TLS-PROTECTED-CONTENT" ] || fail "unexpected protected content '$BODY'"

echo "RESULT: 3.3.6 served the protected resource; 4.3.1 rejected the chain"
