#!/usr/bin/env bash
# Genera el par RSA 2048 para firmar JWT (RS256).
#   keys/private.pem -> solo AUTH (montada :ro)
#   keys/public.pem  -> AUTH y STEGO (montada :ro)
# Uso: ./scripts/gen-keys.sh [--force]
# Nunca imprime el contenido de las claves.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="$ROOT/keys"
PRIV="$KEY_DIR/private.pem"
PUB="$KEY_DIR/public.pem"

command -v openssl >/dev/null || { echo "error: openssl no está instalado" >&2; exit 1; }

if [[ -f "$PRIV" && "${1:-}" != "--force" ]]; then
  echo "Ya existen claves en $KEY_DIR (usa --force para regenerarlas)."
  exit 0
fi

umask 077
mkdir -p "$KEY_DIR"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PRIV" 2>/dev/null
openssl pkey -in "$PRIV" -pubout -out "$PUB"
chmod 600 "$PRIV"
chmod 644 "$PUB"
chmod 755 "$KEY_DIR"

echo "Claves generadas:"
echo "  $PRIV (600)"
echo "  $PUB (644)"
echo -n "  SHA-256 de la pública: "
openssl pkey -pubin -in "$PUB" -outform DER | openssl dgst -sha256 | awk '{print $NF}'
