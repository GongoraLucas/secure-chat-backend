"""Dependencias FastAPI de seguridad: paso 1 (JWT local → 401) y paso 2 (AUTH → 503/403) de /analyze."""

import logging
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings
from app.repository import audit
from app.security.authz_client import AuthzClient, AuthzDecision, AuthzUnavailable
from app.security.jwt_verifier import JwtVerifier, TokenError, VerifiedToken

logger = logging.getLogger("stego.security")

_bearer = HTTPBearer(auto_error=False)


def safe_audit(event: str, user_id: str | None = None, analysis_id: str | None = None,
               detail: str | None = None) -> None:
    """Escribe en `audit_log` sin alterar nunca la decisión de seguridad si la bitácora falla."""
    try:
        audit(get_settings().db_path, event, user_id, analysis_id, detail)
    except Exception as exc:  # noqa: BLE001 — la denegación/respuesta sigue igual
        logger.error("audit_failed event=%s error=%s", event, type(exc).__name__)


@lru_cache
def get_jwt_verifier() -> JwtVerifier:
    s = get_settings()
    return JwtVerifier(s.jwt_public_key_path.read_bytes(), issuer=s.jwt_issuer, audience=s.jwt_audience)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No autenticado",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_token(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    verifier: JwtVerifier = Depends(get_jwt_verifier),
) -> VerifiedToken:
    if creds is None or not creds.credentials:
        logger.info("token_invalid reason=missing")
        safe_audit("token_invalid", detail="missing")
        raise _unauthorized()
    try:
        return verifier.verify(creds.credentials)
    except TokenError as exc:
        # Nunca el JWT completo: solo los últimos 6 caracteres.
        logger.info("token_invalid reason=%s token_tail=%s", exc, creds.credentials[-6:])
        safe_audit("token_invalid", detail="invalid")
        raise _unauthorized() from None


@lru_cache
def get_authz_client() -> AuthzClient:
    s = get_settings()
    return AuthzClient(str(s.auth_url), s.service_token, s.auth_timeout_seconds)


def require_permission(action: str):
    """Paso 2 de /analyze: JWT local (401) → decisión de AUTH (503 / 403). Deny by default."""

    async def _dep(
        token: VerifiedToken = Depends(require_token),
        authz: AuthzClient = Depends(get_authz_client),
    ) -> tuple[VerifiedToken, AuthzDecision]:
        try:
            decision = await authz.check(token, action)
        except AuthzUnavailable as exc:
            logger.warning("authz_unavailable action=%s jti=%s reason=%s", action, token.jti, exc)
            safe_audit("authz_unavailable", user_id=token.sub, detail=f"action={action} jti={token.jti}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Servicio de autorización no disponible",
            ) from None
        if decision.allowed is not True:
            logger.info("authz_denied action=%s jti=%s reason=%s", action, token.jti, decision.reason)
            safe_audit("authz_denied", user_id=token.sub,
                       detail=f"action={action} jti={token.jti} reason={decision.reason}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permiso denegado")
        return token, decision

    return _dep
