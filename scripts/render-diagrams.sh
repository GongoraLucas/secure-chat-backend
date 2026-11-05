#!/usr/bin/env bash
# Renderiza docs/diagrams/*.puml a PNG (y SVG con --svg) en docs/diagrams/img/.
# Usa Docker (imagen oficial plantuml/plantuml), así no hace falta instalar Java.
# Alternativa sin Docker: extensión "PlantUML" de VS Code, o `java -jar plantuml.jar`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/docs/diagrams"
FORMAT="-tpng"
[[ "${1:-}" == "--svg" ]] && FORMAT="-tsvg"

cd "$DIR"
FILES=( [0-9]*.puml )
docker run --rm -u "$(id -u):$(id -g)" -v "$DIR":/data -w /data plantuml/plantuml \
  "$FORMAT" -o img -failfast2 "${FILES[@]}"

echo "Diagramas generados en docs/diagrams/img/"
