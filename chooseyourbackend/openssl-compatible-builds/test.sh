#!/bin/bash
set -euo pipefail

IMAGE=goahead-openssl-crl
NAME=${NAME:-goahead-openssl-crl}
PORT=${PORT:-14443}
CURL=curl
[ -x /usr/bin/curl ] && CURL=/usr/bin/curl
D=/etc/goahead/certs

cleanup() {
    docker rm -f $NAME >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    echo "RESULT: failed"
    exit 1
}

if [ "${REBUILD:-0}" = "1" ] || ! docker image inspect $IMAGE >/dev/null 2>&1; then
    docker build --platform linux/amd64 -t $IMAGE . -q
fi

docker rm -f $NAME >/dev/null 2>&1 || true
docker run --platform linux/amd64 -d --name $NAME -p $PORT:443 $IMAGE >/dev/null
for i in $(seq 1 30); do
    docker logs $NAME 2>&1 | grep -q 'Started https' && break
    sleep 1
done

for f in client-valid.crt client-valid.key client-revoked.crt client-revoked.key crl.pem; do
    docker cp $NAME:$D/$f /tmp/$NAME-$f >/dev/null || fail "could not read $f from the container"
done

req() {
    $CURL -sk -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true
}

R_NONE=$(req https://localhost:$PORT/index.html)
R_VALID=$(req --cert /tmp/$NAME-client-valid.crt --key /tmp/$NAME-client-valid.key https://localhost:$PORT/index.html)
R_REVOKED=$(req --cert /tmp/$NAME-client-revoked.crt --key /tmp/$NAME-client-revoked.key https://localhost:$PORT/index.html)

BODY=$($CURL -sk --cert /tmp/$NAME-client-revoked.crt --key /tmp/$NAME-client-revoked.key \
    https://localhost:$PORT/index.html 2>/dev/null | tr -d '\n' || true)

TRACE=$(docker logs $NAME 2>&1 | grep VERIFY_CB | tail -2 | sed 's/.*VERIFY_CB: //' || true)
SERIAL=$(openssl x509 -in /tmp/$NAME-client-revoked.crt -noout -serial | cut -d= -f2)

NONE="rejected"
[ "${R_NONE:-000}" = "000" ] || NONE="HTTP $R_NONE"

REVOKED="rejected"
case ${R_REVOKED:-000} in
    200|302) REVOKED="HTTP $R_REVOKED   <-- accepted" ;;
esac

echo "GoAhead 6.1.0 + OpenSSL 3.6.2"
echo "mTLS: VERIFY_PEER=1, VERIFY_ISSUER=1, CRL configured"
echo "------------------------------------------------------------"
printf '%-26s %s\n' "no client certificate" "$NONE"
printf '%-26s %s\n' "valid client certificate" "HTTP $R_VALID"
printf '%-26s %s\n' "REVOKED client cert" "$REVOKED"
echo
echo "verify callback (revoked cert)"
sed 's/^/  /' <<< "$TRACE"
echo
echo "protected content: $BODY"
echo

[ "$R_NONE" = "000" ] || fail "no-cert request returned $R_NONE"
[ "$R_VALID" = "200" ] || fail "valid cert returned $R_VALID"
case ${R_REVOKED:-000} in
    200|302) ;;
    *) fail "revoked cert returned $R_REVOKED (bypass not reproduced)" ;;
esac
openssl crl -in /tmp/$NAME-crl.pem -noout -text | grep -qi "$SERIAL" ||
    fail "CRL does not list the revoked serial $SERIAL"
grep -q 'error=0(ok) depth=1' <<< "$TRACE" || fail "revoked cert did not report error 0 at depth 1"
grep -q 'error=0(ok) depth=0' <<< "$TRACE" || fail "revoked cert did not report error 0 at depth 0"
[ "$BODY" = "MUTUAL-TLS-PROTECTED-CONTENT" ] || fail "unexpected protected content '$BODY'"

echo "RESULT: revoked client certificate reaches the protected resource"
