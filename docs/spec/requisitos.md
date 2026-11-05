# Especificación — Backend V1

## Escenarios minimos
| ID | Escenario | Esperado |
|---|---|---|
| T01 | Iniciar y detener AUTH y STEGO por separado | Procesos y APIs autónomos |
| T02 | Login con contraseña válida e inválida | JWT firmado / rechazo |
| T03 | STEGO sin JWT, con JWT manipulado o vencido | 401 |
| T04 | Usuario con rol USER intenta analizar | 403 |
| T05 | Dos roles a un usuario; un rol a dos usuarios | N:M persistida |
| T06 | Repetir una asignación usuario–rol | Sin duplicado (409) |
| T07 | Retirar un rol y reusar un JWT vigente | Nueva operación denegada |
| T08 | AUTH inaccesible | STEGO no procesa |
| T09 | Imagen original vs. imagen con carga LSB | Métricas, clasificación y limitaciones |
| T10 | Archivo inválido, corrupto o muy grande | Rechazo seguro |
| T11 | Consultar un análisis ajeno | Denegado |
| T12 | Revisar bitácoras | Trazabilidad sin secretos ni JWT completos |

