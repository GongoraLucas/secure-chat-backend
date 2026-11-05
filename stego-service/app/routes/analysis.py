"""POST /api/steganography/analyze (§7, §11). Orden fijado en la skill stego-fastapi:

1-2. `require_permission` → 401 / 503 / 403 (el cuerpo aún NO se ha parseado)
3.   lectura acotada → 413
4.   extensión + firma + MIME → 415
5.   píxeles + integridad → 422 (se registra como error/rechazo)
6.   sha256 + política (cuarentena con nombre UUID o nada en disco)
7.   detector → clasificador → persistir → auditar → 200
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile

from app.config import Settings, get_settings
from app.detection.chi_square import analyze
from app.detection.classifier import LIMITATIONS, TECHNIQUE, classify
from app.files.storage import quarantine
from app.files.validation import (
    FileTooLarge,
    FileValidationError,
    InvalidImage,
    UnsupportedFormat,
    detect_format,
    load_image,
    read_limited,
    sanitize_filename,
)
from app.repository import get_analysis, insert_analysis
from app.security.authz_client import AuthzDecision
from app.security.dependencies import require_permission, safe_audit
from app.schemas import ANALYZE_REQUEST_BODY, ANALYZE_RESPONSES, RESULTS_RESPONSES, AnalysisResult
from app.security.jwt_verifier import VerifiedToken

logger = logging.getLogger("stego.analysis")

router = APIRouter(prefix="/api/steganography", tags=["steganography"])

ANALYZE = "steganography.analyze"
RESULTS_READ = "steganography.results.read"
_MULTIPART_OVERHEAD = 64 * 1024  # margen para cabeceras y boundaries del multipart

_REJECT_CODES: dict[type[FileValidationError], str] = {
    FileTooLarge: "too_large",
    UnsupportedFormat: "unsupported_format",
    InvalidImage: "invalid_image",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _reject(exc: FileValidationError, user_id: str, analysis_id: str | None = None) -> HTTPException:
    code = _REJECT_CODES.get(type(exc), "invalid_file")
    logger.info("analysis_rejected user=%s reason=%s", user_id, code)
    safe_audit("analysis_rejected", user_id=user_id, analysis_id=analysis_id, detail=code)
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


def _declared_too_large(request: Request, max_bytes: int) -> bool:
    raw = request.headers.get("content-length")
    try:
        return raw is not None and int(raw) > max_bytes + _MULTIPART_OVERHEAD
    except ValueError:
        return False  # la lectura acotada sigue siendo la barrera real


def _detect(data: bytes, fmt: str, s: Settings) -> tuple[dict[str, Any], str, str | None]:
    img = load_image(data, fmt, s.max_pixels)  # type: ignore[arg-type]
    try:
        indicators = analyze(img, s.suspicious_threshold)
    finally:
        img.close()
    status_, action = classify(indicators, s.suspicious_threshold, s.inconclusive_threshold, s.min_dimension)
    return indicators, status_, action


@router.post(
    "/analyze",
    summary="Analizar una imagen PNG/BMP en busca de LSB",
    description="Requiere Bearer JWT y el permiso `steganography.analyze` (AUTH lo decide en cada petición). "
    "Orden: 401 → 503/403 → 413 → 415 → 422. Sin decisión verificable de AUTH el archivo no se lee.",
    response_model=AnalysisResult,
    responses=ANALYZE_RESPONSES,
    openapi_extra={"requestBody": ANALYZE_REQUEST_BODY},
)
async def analyze_image(
    request: Request,
    ctx: tuple[VerifiedToken, AuthzDecision] = Depends(require_permission(ANALYZE)),
    s: Settings = Depends(get_settings),
) -> dict[str, Any]:
    token, _decision = ctx
    user_id = token.sub  # nunca de un campo enviado por el cliente

    # 3. Solo ahora, ya autorizado, se toca el cuerpo.
    if _declared_too_large(request, s.max_upload_bytes):
        raise _reject(FileTooLarge(), user_id)
    try:
        form = await request.form(max_files=1, max_fields=8)
    except HTTPException:
        logger.info("analysis_rejected user=%s reason=bad_multipart", user_id)
        safe_audit("analysis_rejected", user_id=user_id, detail="bad_multipart")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Solicitud inválida") from None

    upload = form.get("file")
    if not isinstance(upload, UploadFile):
        raise _reject(UnsupportedFormat(), user_id)

    try:
        data = await read_limited(upload, s.max_upload_bytes)
        fmt = detect_format(upload.filename, upload.content_type, data)
    except FileValidationError as exc:
        raise _reject(exc, user_id) from None
    finally:
        await upload.close()

    # 5-7. Integridad, detector y clasificación (CPU: fuera del event loop).
    analysis_id = str(uuid.uuid4())
    record: dict[str, Any] = {
        "analysis_id": analysis_id,
        "user_id": user_id,
        "filename": sanitize_filename(upload.filename),
        "sha256": hashlib.sha256(data).hexdigest(),
        "technique": TECHNIQUE,
        "limitations": LIMITATIONS,
        "created_at": _now(),
    }
    try:
        indicators, status_, action = await run_in_threadpool(_detect, data, fmt, s)
    except InvalidImage as exc:
        insert_analysis(s.db_path, {**record, "indicators": {}, "status": "error", "action": "rechazo"})
        raise _reject(exc, user_id, analysis_id) from None

    record.update(indicators=indicators, status=status_, action=action)

    # 6. Política: solo `sospechoso` conserva el archivo (cuarentena); el resto no toca el disco.
    if action == "cuarentena":
        quarantine(s.quarantine_dir, analysis_id, data)
    insert_analysis(s.db_path, record)

    logger.info("analysis_completed id=%s user=%s status=%s", analysis_id, user_id, status_)
    safe_audit("analysis_completed", user_id=user_id, analysis_id=analysis_id,
               detail=f"status={status_} action={action}")

    return {k: record[k] for k in ("analysis_id", "user_id", "filename", "sha256", "technique", "status",
                                   "indicators", "action", "limitations", "created_at")}


@router.get(
    "/results/{analysis_id}",
    summary="Consultar un análisis",
    response_model=AnalysisResult,
    responses=RESULTS_RESPONSES,
)
async def get_result(
    analysis_id: str,
    ctx: tuple[VerifiedToken, AuthzDecision] = Depends(require_permission(RESULTS_READ)),
    s: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Dueño con read_own o cualquiera con read_any. Ajeno, inexistente o id inválido → el mismo 404
    (§11: no revela si el análisis existe). El dueño sale de `sub`, nunca del cliente."""
    token, decision = ctx
    not_found = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Análisis no encontrado")

    try:
        canonical = str(uuid.UUID(analysis_id))
    except ValueError:
        safe_audit("result_not_found", user_id=token.sub, detail="invalid_id")
        raise not_found from None

    record = get_analysis(s.db_path, canonical)
    if record is None:
        safe_audit("result_not_found", user_id=token.sub, detail="missing")
        raise not_found
    if record["user_id"] != token.sub and decision.can_read_any is not True:
        logger.info("result_not_owner id=%s user=%s jti=%s", canonical, token.sub, token.jti)
        safe_audit("result_not_found", user_id=token.sub, analysis_id=canonical, detail="not_owner")
        raise not_found

    safe_audit("result_read", user_id=token.sub, analysis_id=canonical,
               detail="owner" if record["user_id"] == token.sub else "read_any")
    return record
