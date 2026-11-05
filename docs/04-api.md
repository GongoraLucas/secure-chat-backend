# 4. Contratos de las APIs

Cada servicio publica su especificación **OpenAPI** generada desde el código:

| Servicio | Swagger UI | Documento JSON |
|---|---|---|
| AUTH | http://localhost:3000/api/docs | http://localhost:3000/api/docs-json |
| STEGO | http://localhost:8000/docs | http://localhost:8000/openapi.json |

Copias exportadas para la entrega: `docs/openapi/auth.openapi.json` y `docs/openapi/stego.openapi.json`.

Exportadas el 2026-11-04 desde los contenedores en ejecución (AUTH OpenAPI 3.0.0, STEGO OpenAPI 3.1.0), con formato `python3 -m json.tool`:

```bash
curl -sf localhost:3000/api/docs-json | python3 -m json.tool > docs/openapi/auth.openapi.json
curl -sf localhost:8000/openapi.json  | python3 -m json.tool > docs/openapi/stego.openapi.json
```

## 4.1 Resumen de endpoints

| Servicio | Método | Ruta | Acceso | Respuestas |
|---|---|---|---|---|
| AUTH | POST | /api/auth/login | Público con rate limit | 200, 400, 401, 429 |
| AUTH | GET | /api/auth/profile | Autenticado (`profile.read`) | 200, 401, 403 |
| AUTH | POST | /api/auth/logout | Autenticado (`profile.read`) | 204, 401, 403 |
| AUTH | GET, POST | /api/users | ADMIN | 200/201, 400, 401, 403, 409 |
| AUTH | PATCH | /api/users/:id | ADMIN | 200, 400, 401, 403, 404 |
| AUTH | GET, POST | /api/roles | ADMIN | 200/201, 400, 401, 403, 409 |
| AUTH | PATCH | /api/roles/:id | ADMIN | 200, 400, 401, 403, 404 |
| AUTH | POST | /api/user-roles | ADMIN | 201, 400, 401, 403, 404, 409 |
| AUTH | DELETE | /api/user-roles/:id | ADMIN | 204, 400, 401, 403, 404 |
| AUTH | POST | /internal/authorization/check | Solo STEGO (`X-Service-Token`) | 200, 400, 401 |
| STEGO | POST | /api/steganography/analyze | ADMIN o ANALYST | 200, 400 (multipart mal formado), 401, 403, 413, 415, 422, 503 |
| STEGO | GET | /api/steganography/results/:id | Dueño o ADMIN | 200, 401, 403, 404, 503 |
| Ambos | GET | /health | Público | 200 |

## 4.2 Ejemplos

**Login**
```http
POST /api/auth/login
Content-Type: application/json

{ "username": "ana", "password": "********" }
```
```json
{ "access_token": "eyJhbGciOiJSUzI1NiIs…", "token_type": "Bearer", "expires_in": 900 }
```

**Decisión de autorización (interna)**
```http
POST /internal/authorization/check
X-Service-Token: <secreto de servicio>
Content-Type: application/json

{ "subject_token": "<JWT del usuario>", "action": "steganography.analyze", "resource_id": null }
```
```json
{ "subject_id": "…uuid…", "action": "steganography.analyze", "allowed": true,
  "reason": "active_role_grants_permission", "can_read_any": false }
```

**Análisis**
```http
POST /api/steganography/analyze
Authorization: Bearer <JWT>
Content-Type: multipart/form-data; boundary=…

file=@samples/stego_lsb_full.png
```

Respuesta real (`200`, S6, 2026-11-04, AUTH simulado con `allowed:true`; `limitations` abreviado aquí, el texto completo está en `app/detection/classifier.py`). La corrida de I2 contra los contenedores (AUTH real) devolvió para esta muestra el mismo `sha256`, `status`, `action` e indicadores; solo cambian `analysis_id`, `user_id` y `created_at`:
```json
{"analysis_id":"474873f2-f8bf-4649-b265-05efee3b84bb","user_id":"577a34f2-4f55-4487-878f-d03d5b85936a",
 "filename":"stego_lsb_full.png","sha256":"a2bd3818a82fce168e662871a6eaf3eb022106fb4c71da395ef6a322831ad2fd",
 "technique":"lsb_chi_square","status":"sospechoso",
 "indicators":{"p_values":{
   "R":[0.999967,0.999999,0.999997,0.999966,0.999632,0.999472,0.999729,0.999901,0.999939,0.999992],
   "G":[0.999973,0.999971,0.99991,0.999999,1.0,1.0,1.0,1.0,1.0,1.0],
   "B":[0.999957,0.999993,1.0,1.0,1.0,1.0,1.0,0.999999,1.0,1.0]},
   "portions":[10,20,30,40,50,60,70,80,90,100],"p_value_first_max":0.999973,"p_value_max":1.0,
   "embedding_estimate":100,"threshold":0.95,"width":512,"height":512},
 "action":"cuarentena",
 "limitations":"Resultado indicativo, no concluyente: 'sospechoso' es un indicio estadístico, no una prueba. …",
 "created_at":"2026-11-04T07:21:31Z"}
```

Notas del endpoint: el multipart se parsea **después** de la autorización (401/503/403 no leen el archivo); `user_id` sale siempre del `sub` del token; errores `413`/`415`/`422` con `{detail}` genérico; un multipart mal formado → `400 {detail:"Solicitud inválida"}`; `422` deja un registro `error`/`rechazo`. Solo `sospechoso` guarda el archivo (`/data/quarantine/<uuid hex>`).

## 4.3 Colección REST

`postman/backend-v1.postman_collection.json` reproduce los escenarios T02–T12 en orden y con aserciones; `postman/backend-v1-manual.postman_collection.json` cubre T01 y T08, que requieren detener AUTH. Ver [pruebas y evidencias](07-pruebas-evidencias.md).
