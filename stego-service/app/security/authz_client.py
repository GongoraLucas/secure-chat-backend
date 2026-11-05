"""Cliente de autorización hacia AUTH (§6). Paso 2 del orden de /analyze.

Deny by default: fallo de red, timeout, status ≠ 200 o cuerpo que no cumple el
contrato de §11 → `AuthzUnavailable` (el llamador responde 503 y NO procesa nada).
Solo `allowed is True` (booleano estricto) habilita la operación.
"""

from dataclasses import dataclass

import httpx

from app.security.jwt_verifier import VerifiedToken

CHECK_PATH = "/internal/authorization/check"


class AuthzUnavailable(Exception):
    """AUTH no dio una decisión verificable. El motivo es solo para logs internos."""


@dataclass(frozen=True)
class AuthzDecision:
    allowed: bool
    reason: str
    can_read_any: bool = False


class AuthzClient:
    def __init__(self, base_url: str, service_token: str, timeout: float) -> None:
        self._url = base_url.rstrip("/") + CHECK_PATH
        self._service_token = service_token
        self._timeout = timeout

    async def check(self, token: VerifiedToken, action: str, resource_id: str | None = None) -> AuthzDecision:
        payload = {"subject_token": token.raw, "action": action, "resource_id": resource_id}
        try:
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=False) as client:
                resp = await client.post(
                    self._url, json=payload, headers={"X-Service-Token": self._service_token}
                )
        except httpx.HTTPError as exc:  # red, DNS, timeout (connect/read/write/pool)
            raise AuthzUnavailable(type(exc).__name__) from None

        if resp.status_code != 200:
            raise AuthzUnavailable(f"status {resp.status_code}")
        try:
            body = resp.json()
        except ValueError:
            raise AuthzUnavailable("cuerpo no JSON") from None
        return _parse(body, token, action)


def _parse(body: object, token: VerifiedToken, action: str) -> AuthzDecision:
    if not isinstance(body, dict):
        raise AuthzUnavailable("cuerpo no objeto")

    allowed = body.get("allowed")
    if type(allowed) is not bool:
        raise AuthzUnavailable("allowed no booleano")
    if body.get("action") != action:
        raise AuthzUnavailable("action no coincide")
    reason = body.get("reason")
    if not isinstance(reason, str):
        raise AuthzUnavailable("reason no string")
    can_read_any = body.get("can_read_any", False)
    if type(can_read_any) is not bool:
        raise AuthzUnavailable("can_read_any no booleano")
    # Un permiso solo vale para el sujeto del token que enviamos.
    if allowed and body.get("subject_id") != token.sub:
        raise AuthzUnavailable("subject_id no coincide")

    return AuthzDecision(allowed=allowed, reason=reason, can_read_any=allowed and can_read_any)
