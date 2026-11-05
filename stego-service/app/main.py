"""STEGO · FastAPI. Arranque, manejadores de error y rutas."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.logging_conf import configure_logging
from app.repository import init_db
from app.routes import analysis, health

logger = logging.getLogger("stego")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    settings.quarantine_dir.mkdir(parents=True, exist_ok=True)
    init_db(settings.db_path)
    logger.info("stego listo data_dir=%s", settings.data_dir)
    yield


app = FastAPI(
    title="STEGO · Secure Chat",
    version="1.0.0",
    description="Análisis estadístico LSB (chi-cuadrado) de imágenes PNG/BMP. Deny by default: cada petición "
    "protegida exige JWT RS256 válido y una decisión afirmativa de AUTH. Errores: `{\"detail\": \"...\"}`. "
    "El resultado `sospechoso` es un indicio, no una prueba.",
    lifespan=lifespan,
)


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    # Sin stack traces ni detalles internos en la respuesta.
    logger.error("error no controlado en %s %s: %s", request.method, request.url.path, type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Error interno"})


app.include_router(health.router)
app.include_router(analysis.router)


def _openapi() -> dict:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(title=app.title, version=app.version, description=app.description, routes=app.routes)
    # El 422 automático de validación no aplica: /analyze usa 422 para imagen inválida (documentado a mano)
    # y /results/{id} nunca responde 422 (id inválido → 404).
    for path, item in schema["paths"].items():
        for op in item.values():
            if path != "/api/steganography/analyze":
                op.get("responses", {}).pop("422", None)
    for name in ("HTTPValidationError", "ValidationError"):
        schema.get("components", {}).get("schemas", {}).pop(name, None)
    app.openapi_schema = schema
    return schema


app.openapi = _openapi  # type: ignore[method-assign]
