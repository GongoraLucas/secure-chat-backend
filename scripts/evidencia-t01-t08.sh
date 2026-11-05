#!/usr/bin/env bash
# Evidencia de T01 (servicios independientes) y T08 (AUTH caído → STEGO no procesa).
# Uso, desde la raíz con el compose levantado:
#   ./scripts/evidencia-t01-t08.sh > docs/evidencias/t01-t08.txt 2>&1
# La contraseña de admin se lee de auth-service/.env (no se versiona) y se pasa a newman con --env-var.
# El entorno exportado (contiene JWT) vive en un directorio temporal que se borra al salir.
set -u
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
ENV="$TMP/env.json"
ADMIN_PW="$(grep -E '^ADMIN_PASSWORD=' auth-service/.env | cut -d= -f2- | sed -E "s/^['\"]|['\"]$//g")"
NM=(npx newman run postman/backend-v1-manual.postman_collection.json --working-dir . --color off)

run()    { echo; echo "\$ $*" | sed "s#$ENV#entorno-exportado.json#g"; "$@" 2>&1; }
health() { echo; echo "\$ curl -s -w ' HTTP %{http_code}' $1/health"; curl -s -m 3 -w " HTTP %{http_code}" "$1/health" || echo " (sin respuesta, curl exit $?)"; echo; }
count()  { docker compose exec -T stego python -c "import sqlite3;c=sqlite3.connect('/data/stego.db');print('analyses =',c.execute('select count(*) from analyses').fetchone()[0])"; }

echo "# Evidencia I1 · T01 y T08 · $(date -Iseconds)"
echo "# docker compose $(docker compose version --short)"
run docker compose ps --format "table {{.Service}}\t{{.Status}}"

# Usuarios demo (ana, beto, carla): idempotente, sin aserciones de escenario.
npx newman run postman/backend-v1.postman_collection.json -e postman/local.postman_environment.json \
  --working-dir . --folder "00 Setup" --env-var "admin_password=$ADMIN_PW" \
  --export-environment "$ENV" --reporters cli --color off > "$TMP/setup.txt" 2>&1 \
  || { echo "00 Setup falló:"; grep -E "assertions|AssertionError" "$TMP/setup.txt"; exit 1; }

echo; echo "## T01 · AUTH y STEGO se inician y detienen por separado"
echo; echo "### 1) STEGO detenido: AUTH sigue atendiendo"
run docker compose stop stego
health http://localhost:3000
health http://localhost:8000
echo; echo "### 2) STEGO arriba y AUTH detenido: STEGO sigue atendiendo"
run docker compose start stego
run docker compose up -d --wait stego
run docker compose stop auth
health http://localhost:8000
health http://localhost:3000
run docker compose start auth
run docker compose up -d --wait auth
echo; echo "### 3) Newman T01 con ambos arriba"
run "${NM[@]}" -e "$ENV" --folder "T01 Servicios independientes"

echo; echo "## T08 · AUTH inaccesible: STEGO no procesa (deny by default)"
run "${NM[@]}" -e "$ENV" --folder "T08-a Preparar (AUTH arriba)" --export-environment "$ENV"
echo; echo "\$ (STEGO) SELECT count(*) FROM analyses   # antes"; count
run docker compose stop auth
run "${NM[@]}" -e "$ENV" --folder "T08 AUTH detenido"
echo; echo "\$ (STEGO) SELECT count(*) FROM analyses   # después: sin cambios"; count
echo; echo "\$ docker compose logs stego | grep authz_unavailable | tail -1"
docker compose logs --no-log-prefix stego 2>&1 | grep authz_unavailable | tail -1
run docker compose start auth
run docker compose up -d --wait auth
run docker compose ps --format "table {{.Service}}\t{{.Status}}"
