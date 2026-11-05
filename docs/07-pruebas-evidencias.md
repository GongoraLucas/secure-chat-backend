# 7. Pruebas y evidencias reproducibles

## 7.1 Niveles de prueba

| Nivel | Herramienta | Qué cubre | Comando |
|---|---|---|---|
| Unitarias AUTH | Jest | hashing, TokenService, AuthorizationService, guard de servicio | `cd auth-service && npm run test` |
| e2e AUTH | Jest + Supertest | login, 401/403, N:M, duplicados, revocación | `./scripts/test-db.sh up && cd auth-service && npm run test:e2e` |
| Unitarias/integración STEGO | pytest + respx | JWT local, cliente de autorización, validación, detector, propiedad | `cd stego-service && pytest -q` |
| Integración de sistema | Postman / newman | escenarios T02–T12 contra los contenedores | ver 7.3 |
| Manual guiada | Postman + docker | T01 y T08 (detener AUTH) | ver 7.4 |

## 7.2 Matriz de trazabilidad T01–T12

| ID | Escenario | Prueba automatizada | Carpeta Postman (aserciones) | Resultado |
|---|---|---|---|---|
| T01 | Iniciar y detener servicios por separado | — (`scripts/evidencia-t01-t08.sh`) | manual / T01 (2) | ✔ |
| T02 | Login válido e inválido | e2e `auth.e2e-spec.ts` (`T02: …`) | T02 (16) | ✔ |
| T03 | Sin JWT, manipulado, `alg:none`, vencido | pytest `test_jwt_verifier.py` (`test_alg_none_rejected`, `test_expired_rejected`, `test_tampered_payload_rejected`…), `test_analyze.py::test_token_manipulado_401` | T03 (6) | ✔ |
| T04 | USER intenta analizar | e2e `internal-authorization.e2e-spec.ts` (`T04: …`), pytest `test_analyze.py::test_allowed_false_403_no_procesa` | T04 (2) | ✔ |
| T05 | Usuario con 2 roles; rol en 2 usuarios | e2e `database.e2e-spec.ts` (`T05: N:M …`), `admin-crud.e2e-spec.ts` | 00 Setup (14) + T05 (8) | ✔ |
| T06 | Asignación duplicada | e2e `database.e2e-spec.ts` (`T06: …`), `admin-crud.e2e-spec.ts` (`user-roles · T06`) | T06 (1) | ✔ |
| T07 | Revocación con JWT vigente | e2e `authorization.e2e-spec.ts` y `internal-authorization.e2e-spec.ts` (`T07: …`) | T07 (4) | ✔ |
| T08 | AUTH inaccesible | pytest `test_analyze.py::test_auth_no_disponible_503_no_procesa`, `test_authz_client.py::test_fallo_de_red_o_timeout_es_unavailable` | manual / T08 (2 + 2) | ✔ |
| T09 | Original vs. muestra LSB | pytest `test_chi_square.py` (`test_muestras_limpias_no_son_sospechosas`, `test_stego_lsb_full_es_sospechoso`…), `test_analyze.py::test_stego_lsb_full_sospechoso_cuarentena` | T09 (11) | ✔ |
| T10 | Inválido, corrupto, demasiado grande | pytest `test_file_validation.py`, `test_analyze.py` (`test_fake_png_415`, `test_corrupto_422_registra_error_rechazo`, `test_archivo_grande_413`) | T10 (3) | ✔ |
| T11 | Análisis ajeno | pytest `test_results.py::test_ajeno_sin_read_any_404_igual_que_inexistente` | T11 (4) | ✔ |
| T12 | Bitácoras sin secretos | pytest `test_analyze.py::test_bitacora_no_contiene_jwt` | T12 (2) + revisión 7.5 | ✔ |

Ejecución del 2026-11-04 (I2): `pytest -q` en STEGO → 146 passed; AUTH `npm run test` → 47 passed (7 suites) y `npm run test:e2e` → 79 passed (7 suites); newman → 73/73 aserciones; T01/T08 con [`scripts/evidencia-t01-t08.sh`](evidencias/t01-t08.txt). La carpeta `Logout` (2 aserciones) cubre la revocación por `jti` de §4.

## 7.3 Ejecución de la colección

Requisitos: servicios levantados, muestras generadas (`stego-service/.venv/bin/python scripts/make_samples.py`) y `postman/local.postman_environment.json` con `admin_password` igual a `ADMIN_PASSWORD` del `.env` de AUTH.

```bash
npx newman run postman/backend-v1.postman_collection.json \
  -e postman/local.postman_environment.json \
  --working-dir . \
  --reporters cli,json --reporter-json-export docs/evidencias/newman.json
```

La colección es **re-ejecutable**: crea los usuarios si no existen, tolera asignaciones previas y restaura el rol retirado en T07 al final.

Para no versionar la contraseña de admin, se inyecta en la ejecución: `--env-var "admin_password=$(grep ^ADMIN_PASSWORD= auth-service/.env | cut -d= -f2-)"`. `newman.json` incluye los cuerpos (contraseñas y JWT), por eso está en `.gitignore`; se versiona solo la salida de consola [`newman.txt`](evidencias/newman.txt), que no muestra cuerpos.

Resumen real (2026-11-04, contenedores levantados con `docker compose up -d --build`):

```text
┌─────────────────────────┬────────────────────┬───────────────────┐
│                         │           executed │            failed │
├─────────────────────────┼────────────────────┼───────────────────┤
│              iterations │                  1 │                 0 │
├─────────────────────────┼────────────────────┼───────────────────┤
│                requests │                 45 │                 0 │
├─────────────────────────┼────────────────────┼───────────────────┤
│            test-scripts │                 45 │                 0 │
├─────────────────────────┼────────────────────┼───────────────────┤
│      prerequest-scripts │                  3 │                 0 │
├─────────────────────────┼────────────────────┼───────────────────┤
│              assertions │                 73 │                 0 │
├─────────────────────────┴────────────────────┴───────────────────┤
│ total run duration: 9.5s                                         │
└──────────────────────────────────────────────────────────────────┘
```

Resultados de T09 en esta corrida (AUTH real): `clean_noise` y `clean_gradient` → `sin_indicios`; `stego_lsb_50` → `sospechoso`/`cuarentena`, carga estimada 50 %; `stego_lsb_full` → `sospechoso`/`cuarentena`, 100 %. T10: `fake.png` 415, `corrupt.png` 422, `too_big.png` 413. T07: `beto` analiza (200), se le retira ANALYST y el **mismo** JWT recibe 403.

Nota: newman imprime el resumen y luego no termina el proceso por sí solo en esta máquina; el resultado ya está completo cuando aparece la tabla.

## 7.4 Escenarios manuales (T01, T08)

```bash
./scripts/evidencia-t01-t08.sh > docs/evidencias/t01-t08.txt 2>&1
```

El script crea los usuarios demo (`00 Setup`, con la contraseña de admin leída de `auth-service/.env` vía `--env-var`), detiene y arranca cada servicio por separado, obtiene el JWT de `ana` con AUTH arriba (`T08-a`) y lo reutiliza con AUTH detenido (`T08 AUTH detenido`). El entorno exportado con el JWT queda en un directorio temporal que se borra al terminar.

Resultado real (2026-11-04, [salida completa](evidencias/t01-t08.txt)):

| Escenario | Comprobación | Resultado |
|---|---|---|
| T01 | STEGO detenido → `GET :3000/health` | 200 `{"status":"ok"}` |
| T01 | AUTH detenido → `GET :8000/health` | 200 `{"status":"ok"}` |
| T01 | newman `T01 Servicios independientes` | 2/2 aserciones |
| T08 | newman `T08-a` (login de ana) | 2/2 aserciones |
| T08 | newman `T08 AUTH detenido` | 2/2 aserciones: **503**, sin `analysis_id` |
| T08 | filas en `analyses` antes / después | 6 / 6 (no se procesó ni persistió; las 6 previas son de la corrida de newman) |
| T08 | log de STEGO | `authz_unavailable action=steganography.analyze jti=… reason=ConnectError` (sin JWT) |

## 7.5 Bitácoras (T12)

La imagen de STEGO no trae el cliente `sqlite3`, así que la bitácora se lee con el Python del contenedor y la BD abierta en solo lectura; los logs de AUTH se exportan sin códigos de color:

```bash
docker compose logs auth --no-color --no-log-prefix | grep -E "login_|authz_|role_|token_" > docs/evidencias/auth-audit.log
docker compose exec -T stego python -c "import sqlite3;c=sqlite3.connect('file:/data/stego.db?mode=ro',uri=True);[print('|'.join('' if v is None else str(v) for v in r)) for r in c.execute('SELECT ts,event,user_id,analysis_id,detail FROM audit_log ORDER BY id')]" > docs/evidencias/stego-audit.txt
grep -E "eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.|argon2id\\$|BEGIN (RSA )?PRIVATE" docs/evidencias/*.log docs/evidencias/*.txt || echo "OK: sin JWT completos, hashes ni claves"
```

Resultado real (2026-11-04, tras la corrida de newman):

- Salida del `grep`: `OK: sin JWT completos, hashes ni claves`. Además, la contraseña de admin y el `SERVICE_TOKEN` no aparecen en ningún archivo versionado de `docs/evidencias/` (solo en `newman.json`, que no se versiona).
- [`auth-audit.log`](evidencias/auth-audit.log): 37 líneas con eventos `login_success`, `authz_check`/`authz_denied` (`subject_id`, `action`, `reason`), `role_assigned`/`role_revoked` (`actor_id`, `user_id`, `role_id`) y `token_revoked` (`user_id`, `jti`). Identifican usuario y token por `jti`, nunca por el JWT.
- [`stego-audit.txt`](evidencias/stego-audit.txt) (`ts|event|user_id|analysis_id|detail`): 21 filas — `token_invalid` 5, `analysis_completed` 5, `analysis_rejected` 3, `authz_denied` 3, `authz_unavailable` 2, `result_read` 2, `result_not_found` 1. Los `token_invalid` solo registran `missing`/`invalid`, sin usuario ni token.
