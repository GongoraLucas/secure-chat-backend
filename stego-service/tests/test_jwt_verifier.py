"""S2 · Verificación local del JWT (§6, T03). Sin llamar a AUTH."""

import base64
import hashlib
import hmac
import json
import logging
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.security.dependencies import get_jwt_verifier, require_token
from app.security.jwt_verifier import JwtVerifier, TokenError, VerifiedToken
from tests.conftest import AUDIENCE, ISSUER


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _segment(obj: dict) -> str:
    return _b64(json.dumps(obj, separators=(",", ":")).encode())


@pytest.fixture
def verifier(rsa_keys):
    return JwtVerifier(rsa_keys[1], issuer=ISSUER, audience=AUDIENCE)


def _payload(token: str) -> dict:
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


# ---------- JwtVerifier ----------

def test_valid_token(verifier, make_token):
    token = make_token()
    claims = _payload(token)
    out = verifier.verify(token)
    assert isinstance(out, VerifiedToken)
    assert out.sub == claims["sub"]
    assert out.jti == claims["jti"]
    assert out.exp == claims["exp"]
    assert out.raw == token


def test_tampered_payload_rejected(verifier, make_token):
    header, _, sig = make_token().split(".")
    forged = _segment({**_payload(make_token()), "sub": "00000000-0000-4000-8000-000000000000"})
    with pytest.raises(TokenError):
        verifier.verify(f"{header}.{forged}.{sig}")


def test_signed_with_other_rsa_key_rejected(verifier, make_token):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(TokenError):
        verifier.verify(make_token(key=other))


def test_alg_none_rejected(verifier, make_token):
    unsigned = f"{_segment({'alg': 'none', 'typ': 'JWT'})}.{_segment(_payload(make_token()))}."
    with pytest.raises(TokenError):
        verifier.verify(unsigned)


def test_hs256_with_public_key_as_secret_rejected(verifier, make_token, rsa_keys):
    # Ataque de confusión de algoritmo: HMAC firmado con la PEM pública.
    signing_input = f"{_segment({'alg': 'HS256', 'typ': 'JWT'})}.{_segment(_payload(make_token()))}"
    sig = hmac.new(rsa_keys[1], signing_input.encode(), hashlib.sha256).digest()
    with pytest.raises(TokenError):
        verifier.verify(f"{signing_input}.{_b64(sig)}")


def test_expired_rejected(verifier, make_token):
    now = int(time.time())
    with pytest.raises(TokenError):
        verifier.verify(make_token(iat=now - 1000, exp=now - 10))


@pytest.mark.parametrize("claim,value", [("iss", "otro-emisor"), ("aud", "otra-audiencia")])
def test_wrong_iss_or_aud_rejected(verifier, make_token, claim, value):
    with pytest.raises(TokenError):
        verifier.verify(make_token(**{claim: value}))


@pytest.mark.parametrize("claim", ["sub", "jti", "exp", "iss", "aud", "iat"])
def test_missing_required_claim_rejected(verifier, make_token, claim):
    with pytest.raises(TokenError):
        verifier.verify(make_token(drop=(claim,)))


@pytest.mark.parametrize("claim", ["sub", "jti"])
def test_non_uuid_sub_or_jti_rejected(verifier, make_token, claim):
    with pytest.raises(TokenError):
        verifier.verify(make_token(**{claim: "admin"}))


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c", "x" * 5000])
def test_garbage_rejected(verifier, garbage):
    with pytest.raises(TokenError):
        verifier.verify(garbage)


def test_non_rsa_public_key_refused_at_construction():
    ec_pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(ValueError):
        JwtVerifier(ec_pem, issuer=ISSUER, audience=AUDIENCE)


# ---------- Dependencia require_token (401) ----------

@pytest.fixture
def app_client(verifier):
    app = FastAPI()

    @app.get("/protected")
    def protected(tok: VerifiedToken = Depends(require_token)):
        return {"sub": tok.sub}

    app.dependency_overrides[get_jwt_verifier] = lambda: verifier
    return TestClient(app)


def test_dependency_valid_token(app_client, make_token):
    token = make_token()
    r = app_client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"sub": _payload(token)["sub"]}


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Basic dXNlcjpwYXNz"}, {"Authorization": "Bearer"}])
def test_dependency_missing_or_wrong_scheme_401(app_client, headers):
    r = app_client.get("/protected", headers=headers)
    assert r.status_code == 401
    assert r.json() == {"detail": "No autenticado"}
    assert r.headers.get("www-authenticate") == "Bearer"


def test_dependency_invalid_token_401_without_leaking_token(app_client, make_token, caplog):
    now = int(time.time())
    token = make_token(iat=now - 1000, exp=now - 10)
    with caplog.at_level(logging.INFO):
        r = app_client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"detail": "No autenticado"}
    assert "token_invalid" in caplog.text
    assert token not in caplog.text
    assert token.split(".")[1] not in caplog.text
