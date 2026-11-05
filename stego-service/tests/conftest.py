import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import get_settings

ISSUER = "auth-service"
AUDIENCE = "secure-chat"


def _gen_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_keys():
    """Par RSA de test (nunca las claves reales de keys/)."""
    private = _gen_rsa()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public_pem


@pytest.fixture
def public_key_file(tmp_path, rsa_keys):
    path = tmp_path / "public.pem"
    path.write_bytes(rsa_keys[1])
    return path


@pytest.fixture
def make_token(rsa_keys):
    """Firma un JWT RS256 como AUTH. `drop` quita claims; el resto los sobreescribe."""

    def _make(drop=(), key=None, **overrides):
        now = int(time.time())
        claims = {
            "sub": str(uuid.uuid4()),
            "jti": str(uuid.uuid4()),
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + 900,
        }
        claims.update(overrides)
        for name in drop:
            claims.pop(name, None)
        return jwt.encode(claims, key or rsa_keys[0], algorithm="RS256", headers={"typ": "JWT"})

    return _make


@pytest.fixture
def client(tmp_path, monkeypatch, public_key_file):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SERVICE_TOKEN", "t" * 32)
    monkeypatch.setenv("JWT_PUBLIC_KEY_PATH", str(public_key_file))
    get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()
