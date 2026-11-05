#!/usr/bin/env bash
# Postgres desechable para los tests e2e de AUTH (127.0.0.1:5433, sin volumen).
# El postgres del compose no publica puertos (red internal), por eso existe este.
# Uso: ./scripts/test-db.sh up|down
set -euo pipefail

NAME=auth-test-db
case "${1:-}" in
  up)
    if docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
      echo "$NAME ya está en marcha."; exit 0
    fi
    docker run -d --rm --name "$NAME" \
      -e POSTGRES_USER=auth -e POSTGRES_DB=auth_test -e POSTGRES_PASSWORD=e2e-db-pass \
      -p 127.0.0.1:5433:5432 postgres:16-alpine >/dev/null
    for _ in $(seq 1 30); do
      if docker exec "$NAME" pg_isready -U auth -d auth_test >/dev/null 2>&1; then
        echo "$NAME listo en 127.0.0.1:5433"; exit 0
      fi
      sleep 1
    done
    echo "error: $NAME no respondió a tiempo" >&2; exit 1 ;;
  down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "$NAME detenido." ;;
  *)
    echo "Uso: $0 up|down" >&2; exit 2 ;;
esac
