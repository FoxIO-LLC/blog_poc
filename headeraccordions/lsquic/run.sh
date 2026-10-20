#!/usr/bin/env bash
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$DIR/docker-compose.yml")
PORT="${PORT:-8084}"
CONTAINER="${CONTAINER:-ha-lsquic}"

state() {
    if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
        echo "server: ALIVE $(docker stats --no-stream --format '{{.MemUsage}}' "$CONTAINER" 2>/dev/null)"
    else
        echo "server: DOWN oom=$(docker inspect "$CONTAINER" --format '{{.State.OOMKilled}}' 2>/dev/null) exit=$(docker inspect "$CONTAINER" --format '{{.State.ExitCode}}' 2>/dev/null)"
    fi
}

case "${1:-}" in
    start)  "${COMPOSE[@]}" up -d; sleep 8; state ;;
    attack)
        (cd "$DIR/client" && go run . --target "127.0.0.1:${PORT}" --conns 10 --streams 100 \
            --blocks 16 --hold 12s --no-fin) &
        CPID=$!
        while kill -0 "$CPID" 2>/dev/null; do
            docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" || { echo "container died"; break; }
            docker stats "$CONTAINER" --no-stream --format "  {{.MemUsage}}" 2>/dev/null || break
            sleep 1
        done
        wait "$CPID" 2>/dev/null
        state
        docker exec "$CONTAINER" sh -c 'grep -E "^oom_kill" /sys/fs/cgroup/memory.events' 2>/dev/null || true
        ;;
    status) state ;;
    logs)   docker logs -f "$CONTAINER" ;;
    stop)   "${COMPOSE[@]}" down --remove-orphans ;;
    *)      echo "usage: ./run.sh {start|attack|status|logs|stop}" ;;
esac
