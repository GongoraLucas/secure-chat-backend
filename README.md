# Backend V1 · Salas de Chat Seguras

Proyecto Integrador del Primer Parcial · Desarrollo de Software Seguro · ESPE.

Dos microservicios REST independientes:

- **AUTH** (`auth-service/`, NestJS + PostgreSQL): usuarios, roles N:M, login con argon2id, JWT RS256 y autorización RBAC vigente.
- **STEGO** (`stego-service/`, FastAPI + SQLite): validación de imágenes PNG/BMP y detección de esteganografía LSB por chi-cuadrado, solo tras una decisión de autorización de AUTH.

## Requisitos

- Docker y Docker Compose v2
- `openssl` (para generar las claves)
- Python 3.12 (solo para generar muestras y ejecutar tests de STEGO fuera de Docker)
- Node.js 22 + `npx` (solo para tests de AUTH y newman fuera de Docker)

## Puesta en marcha

```bash
git clone <URL_DEL_REPO> && cd <repo>

# 1. Claves RSA (quedan en keys/, ignorado por git)
./scripts/gen-keys.sh

# 2. Variables de entorno
cp .env.example               .env                 # DB_USER, DB_NAME, DB_PASSWORD (postgres y AUTH)
cp auth-service/.env.example  auth-service/.env
cp stego-service/.env.example stego-service/.env
#    Editar: DB_PASSWORD en .env (raíz); ADMIN_PASSWORD en auth-service/.env;
#    el MISMO SERVICE_TOKEN en auth-service/.env y stego-service/.env
#    (generar con: openssl rand -hex 32)

# 3. Levantar
docker compose up -d --build
docker compose ps

# 4. Migraciones y seed de AUTH
docker compose exec auth npm run migration:run
docker compose exec auth npm run seed      # idempotente: roles, permisos §5 y admin desde env

# 5. Muestras de imágenes (necesita numpy/Pillow: usa el venv de STEGO,
#    p. ej. `python3.12 -m venv stego-service/.venv && stego-service/.venv/bin/pip install -r stego-service/requirements.txt`)
stego-service/.venv/bin/python scripts/make_samples.py
```

| Servicio | URL | Documentación |
|---|---|---|
| AUTH | http://localhost:3000 | http://localhost:3000/api/docs |
| STEGO | http://localhost:8000 | http://localhost:8000/docs |

## Pruebas

```bash
./scripts/test-db.sh up   # Postgres desechable en 127.0.0.1:5433 para las e2e de AUTH
cd auth-service  && npm ci && npm run test && npm run test:e2e
cd stego-service && python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt && pytest -q
npx newman run postman/backend-v1.postman_collection.json -e postman/local.postman_environment.json --working-dir .
```

Postman: importar `postman/backend-v1.postman_collection.json`, `postman/backend-v1-manual.postman_collection.json` y `postman/local.postman_environment.json`, y poner en `admin_password` el valor de `ADMIN_PASSWORD`.

## Documentación

| Documento | Contenido |
|---|---|
| [01 Arquitectura](docs/01-arquitectura.md) | Componentes, límites de confianza, despliegue y recursos |
| [02 Modelo de datos](docs/02-modelo-datos.md) | ER y relación N:M |
| [03 Seguridad JWT y RBAC](docs/03-seguridad-jwt-rbac.md) | JWT, roles vigentes, matriz de roles, servicio a servicio |
| [04 APIs](docs/04-api.md) | Endpoints, ejemplos, OpenAPI |
| [05 Detector](docs/05-detector-esteganografia.md) | Chi-cuadrado, parámetros, resultados y limitaciones |
| [06 Matriz de riesgos](docs/06-matriz-riesgos.md) | Activos, amenazas, controles, ZT/SbD/SL, ISO 27001/27034 |
| [07 Pruebas](docs/07-pruebas-evidencias.md) | Trazabilidad T01–T12 y evidencias |
| [08 Sustentación](docs/08-guia-sustentacion.md) | Guion de la demo y preguntas frecuentes |

Diagramas en PlantUML: `docs/diagrams/*.puml` → `./scripts/render-diagrams.sh`.
Exportar la documentación a DOCX o PDF (opcional): `./scripts/export-docs.sh`.

## Estructura

```
auth-service/     NestJS · AUTH
stego-service/    FastAPI · STEGO
docs/             documentación, diagramas PlantUML, OpenAPI exportada, evidencias
postman/          colecciones y entorno
samples/          imágenes de prueba (generadas con scripts/make_samples.py)
scripts/          claves, muestras, diagramas, exportación
keys/             claves RSA (no versionadas)
```

## Referencias

ISO/IEC 27001:2022 · ISO/IEC 27034-1:2011 · OWASP ASVS 5.0 · OWASP File Upload Cheat Sheet · RFC 7519 · RFC 7517 · RFC 8725 · NIST SP 800-207 · Westfeld y Pfitzmann (2000), *Attacks on Steganographic Systems*.
