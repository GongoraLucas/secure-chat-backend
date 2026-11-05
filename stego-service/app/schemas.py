"""Modelos de respuesta y descripción OpenAPI de STEGO (§7, §11). Solo documentación y forma de salida."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Formato de error de STEGO (§11): nunca incluye trazas ni detalles internos."""

    detail: str = Field(examples=["Permiso denegado"])


class AnalysisResult(BaseModel):
    analysis_id: str = Field(description="UUID del análisis", examples=["3f2b8c1e-5a47-4d0e-9c1f-2b7a6d4e8f90"])
    user_id: str = Field(description="UUID del dueño; sale del `sub` del JWT, nunca del cliente")
    filename: str = Field(description="Nombre saneado, solo para mostrar (nunca se usa como ruta)", examples=["muestra.png"])
    sha256: str = Field(description="SHA-256 hexadecimal del archivo recibido")
    technique: str = Field(examples=["lsb_chi_square"])
    status: Literal["sin_indicios", "sospechoso", "no_concluyente", "error"] = Field(
        description="`sospechoso` es un indicio, no una prueba"
    )
    indicators: dict[str, Any] = Field(
        description="p_values, portions, p_value_first_max, p_value_max, embedding_estimate, threshold, "
        "width, height. Vacío si el análisis terminó en `error`.",
        examples=[{"p_value_max": 0.98, "threshold": 0.95}],
    )
    action: Literal["rechazo", "cuarentena", "advertencia"] | None = Field(
        description="Política aplicada; `null` cuando no hay indicios"
    )
    limitations: str = Field(examples=["Resultado indicativo, no concluyente"])
    created_at: str = Field(description="Instante UTC ISO 8601", examples=["2026-11-04T15:30:00Z"])


def err(description: str, example: str) -> dict[str, Any]:
    return {"model": ErrorResponse, "description": description, "content": {"application/json": {"example": {"detail": example}}}}


R401 = err("Sin token, token inválido, manipulado o vencido (`WWW-Authenticate: Bearer`)", "No autenticado")
R403 = err("AUTH deniega la acción al usuario (RBAC vigente en BD)", "Permiso denegado")
R503 = err("AUTH no responde o su respuesta no es válida: deny by default, el archivo no se procesa",
           "Servicio de autorización no disponible")

ANALYZE_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {"description": "Análisis completado y registrado"},
    400: err("Multipart mal formado", "Solicitud inválida"),
    401: R401,
    403: R403,
    413: err("Archivo mayor que `MAX_UPLOAD_BYTES` (5 MiB por defecto)", "Archivo demasiado grande"),
    415: err("Extensión, firma (magic bytes) o Content-Type no admitidos o incoherentes; solo PNG y BMP",
             "Formato no admitido"),
    422: err("Imagen corrupta o que excede `MAX_PIXELS` (se registra como `error`/`rechazo`)", "Imagen corrupta o inválida"),
    503: R503,
}

RESULTS_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {"description": "Análisis del dueño (`read_own`) o cualquiera con `read_any`"},
    401: R401,
    403: R403,
    404: err("Id inválido, inexistente o ajeno sin `read_any`: mismo mensaje en los tres casos para no revelar existencia",
             "Análisis no encontrado"),
    503: R503,
}

ANALYZE_REQUEST_BODY: dict[str, Any] = {
    "required": True,
    "content": {
        "multipart/form-data": {
            "schema": {
                "type": "object",
                "required": ["file"],
                "properties": {
                    "file": {"type": "string", "format": "binary", "description": "Imagen PNG o BMP"}
                },
            }
        }
    },
}
