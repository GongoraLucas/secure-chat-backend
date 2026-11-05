"""Verificación LOCAL del JWT emitido por AUTH (§6). Solo clave pública; RS256 fijo."""

import uuid
from dataclasses import dataclass, field

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

ALGORITHM = "RS256"
REQUIRED_CLAIMS = ["exp", "iat", "sub", "jti", "iss", "aud"]


class TokenError(Exception):
    """Token rechazado. El motivo es solo para logs internos, nunca para el cliente."""


@dataclass(frozen=True)
class VerifiedToken:
    sub: str
    jti: str
    exp: int
    raw: str = field(repr=False)  # S3 lo reenvía a AUTH; no se loguea.


def _is_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


class JwtVerifier:
    def __init__(self, public_key_pem: bytes, issuer: str, audience: str) -> None:
        key = load_pem_public_key(public_key_pem)
        if not isinstance(key, RSAPublicKey):
            raise ValueError("La clave pública del JWT debe ser RSA")
        self._key = key
        self._issuer = issuer
        self._audience = audience

    def verify(self, token: str) -> VerifiedToken:
        try:
            claims = jwt.decode(
                token,
                self._key,
                algorithms=[ALGORITHM],  # lista cerrada: rechaza none/HS*/otros
                audience=self._audience,
                issuer=self._issuer,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.InvalidTokenError as exc:
            raise TokenError(type(exc).__name__) from None

        if not _is_uuid(claims["sub"]) or not _is_uuid(claims["jti"]):
            raise TokenError("sub/jti no UUID")
        if not isinstance(claims["exp"], int):
            raise TokenError("exp no entero")
        return VerifiedToken(sub=claims["sub"], jti=claims["jti"], exp=claims["exp"], raw=token)
