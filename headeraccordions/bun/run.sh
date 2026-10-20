#!/usr/bin/env bash
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$DIR/docker-compose.yml")
PORT="${PORT:-8085}"
CONTAINER="${CONTAINER:-ha-bun}"

state() {
    if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
        echo "server: ALIVE $(docker stats --no-stream --format '{{.MemUsage}}' "$CONTAINER" 2>/dev/null)"
    else
        echo "server: DOWN oom=$(docker inspect "$CONTAINER" --format '{{.State.OOMKilled}}' 2>/dev/null) exit=$(docker inspect "$CONTAINER" --format '{{.State.ExitCode}}' 2>/dev/null)"
    fi
}

case "${1:-}" in
    start)  "${COMPOSE[@]}" up -d --build; sleep 5; state ;;
    attack) (cd "$DIR/client" && go run . --target "127.0.0.1:${PORT}" --authority localhost \
                --conns 1 --streams 100 --refs 500000 --capacity 4096 --hold 10s --no-fin) ;;
    status) state ;;
    logs)   docker logs -f "$CONTAINER" ;;
    stop)   "${COMPOSE[@]}" down --remove-orphans ;;
    *)      echo "usage: ./run.sh {start|attack|status|logs|stop}" ;;
esac
