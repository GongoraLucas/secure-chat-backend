"""S3 · Cliente de autorización deny-by-default (§6) [T04, T07, T08]."""

import asyncio
import json
import uuid

import httpx
import pytest
import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.security.authz_client import AuthzClient, AuthzDecision, AuthzUnavailable
from app.security.dependencies import get_authz_client, get_jwt_verifier, require_permission
from app.security.jwt_verifier import JwtVerifier, VerifiedToken
from tests.conftest import AUDIENCE, ISSUER

AUTH = "http://auth.test:3000"
CHECK_URL = f"{AUTH}/internal/authorization/check"
SERVICE_TOKEN = "s" * 32
ANALYZE = "steganography.analyze"


@pytest.fixture
def token():
    return VerifiedToken(sub=str(uuid.uuid4()), jti=str(uuid.uuid4()), exp=0, raw="hdr.payload.firma123")


@pytest.fixture
def authz():
    # Barra final como la que agrega pydantic HttpUrl.
    return AuthzClient(AUTH + "/", SERVICE_TOKEN, timeout=3.0)


def _body(token, **overrides):
    body = {
        "subject_id": token.sub,
        "action": ANALYZE,
        "allowed": True,
        "reason": "active_role_grants_permission",
        "can_read_any": False,
    }
    body.update(overrides)
    return body


def _check(authz, token, action=ANALYZE):
    return asyncio.run(authz.check(token, action))


# ---------- Cliente ----------


@respx.mock
def test_allowed_true_devuelve_decision_y_envia_contrato(authz, token):
    route = respx.post(CHECK_URL).mock(return_value=httpx.Response(200, json=_body(token)))

    decision = _check(authz, token)

    assert decision == AuthzDecision(allowed=True, reason="active_role_grants_permission", can_read_any=False)
    req = route.calls.last.request
    assert req.headers["X-Service-Token"] == SERVICE_TOKEN
    assert json.loads(req.content) == {"subject_token": token.raw, "action": ANALYZE, "resource_id": None}


@respx.mock
def test_allowed_false_devuelve_denegacion_con_reason(authz, token):
    respx.post(CHECK_URL).mock(
        return_value=httpx.Response(
            200, json=_body(token, allowed=False, reason="no_active_role_grants_permission")
        )
    )
    decision = _check(authz, token)
    assert decision.allowed is False
    assert decision.reason == "no_active_role_grants_permission"


@respx.mock
def test_denegacion_con_subject_id_null_es_valida(authz, token):
    respx.post(CHECK_URL).mock(
        return_value=httpx.Response(
            200, json=_body(token, subject_id=None, allowed=False, reason="invalid_subject_token")
        )
    )
    assert _check(authz, token).allowed is False


@respx.mock
def test_can_read_any_se_propaga(authz, token):
    action = "steganography.results.read"
    respx.post(CHECK_URL).mock(
        return_value=httpx.Response(200, json=_body(token, action=action, can_read_any=True))
    )
    assert _check(authz, token, action).can_read_any is True


@pytest.mark.parametrize(
    "side_effect",
    [httpx.ReadTimeout("t"), httpx.ConnectTimeout("t"), httpx.ConnectError("refused")],
    ids=["read_timeout", "connect_timeout", "connect_error"],
)
@respx.mock
def test_fallo_de_red_o_timeout_es_unavailable(authz, token, side_effect):
    respx.post(CHECK_URL).mock(side_effect=side_effect)
    with pytest.raises(AuthzUnavailable):
        _check(authz, token)


@pytest.mark.parametrize("status", [201, 400, 401, 500, 502])
@respx.mock
def test_status_distinto_de_200_es_unavailable(authz, token, status):
    respx.post(CHECK_URL).mock(return_value=httpx.Response(status, json=_body(token)))
    with pytest.raises(AuthzUnavailable):
        _check(authz, token)


@pytest.mark.parametrize(
    "content",
    [b"no es json", b"[]", b"null", b'"allowed"'],
    ids=["texto", "lista", "null", "string"],
)
@respx.mock
def test_cuerpo_no_objeto_es_unavailable(authz, token, content):
    respx.post(CHECK_URL).mock(return_value=httpx.Response(200, content=content))
    with pytest.raises(AuthzUnavailable):
        _check(authz, token)


@pytest.mark.parametrize(
    "overrides",
    [
        {"allowed": "true"},
        {"allowed": 1},
        {"allowed": None},
        {"action": "steganography.results.read"},
        {"subject_id": str(uuid.uuid4())},
        {"subject_id": None},
        {"can_read_any": "yes"},
        {"reason": 5},
    ],
    ids=[
        "allowed_string",
        "allowed_int",
        "allowed_null",
        "action_distinta",
        "subject_distinto",
        "subject_null_con_allowed",
        "can_read_any_no_bool",
        "reason_no_string",
    ],
)
@respx.mock
def test_cuerpo_invalido_es_unavailable(authz, token, overrides):
    respx.post(CHECK_URL).mock(return_value=httpx.Response(200, json=_body(token, **overrides)))
    with pytest.raises(AuthzUnavailable):
        _check(authz, token)


@respx.mock
def test_allowed_ausente_es_unavailable(authz, token):
    body = _body(token)
    del body["allowed"]
    respx.post(CHECK_URL).mock(return_value=httpx.Response(200, json=body))
    with pytest.raises(AuthzUnavailable):
        _check(authz, token)


# ---------- Dependencia require_permission ----------


@pytest.fixture
def app_client(public_key_file):
    app = FastAPI()

    @app.post("/protegido")
    def protegido(ctx=Depends(require_permission(ANALYZE))):
        token, decision = ctx
        return {"sub": token.sub, "allowed": decision.allowed}

    verifier = JwtVerifier(public_key_file.read_bytes(), issuer=ISSUER, audience=AUDIENCE)
    app.dependency_overrides[get_jwt_verifier] = lambda: verifier
    app.dependency_overrides[get_authz_client] = lambda: AuthzClient(AUTH, SERVICE_TOKEN, timeout=3.0)
    return TestClient(app)


@respx.mock
def test_dep_sin_token_401_sin_llamar_a_auth(app_client):
    route = respx.post(CHECK_URL).mock(return_value=httpx.Response(200, json={}))
    r = app_client.post("/protegido")
    assert r.status_code == 401
    assert route.called is False


@respx.mock
def test_dep_token_invalido_401_sin_llamar_a_auth(app_client, make_token):
    route = respx.post(CHECK_URL).mock(return_value=httpx.Response(200, json={}))
    r = app_client.post("/protegido", headers={"Authorization": f"Bearer {make_token(iss='otro')}"})
    assert r.status_code == 401
    assert route.called is False


@respx.mock
def test_dep_allowed_true_200(app_client, make_token):
    sub = str(uuid.uuid4())
    route = respx.post(CHECK_URL).mock(
        return_value=httpx.Response(
            200,
            json={"subject_id": sub, "action": ANALYZE, "allowed": True,
                  "reason": "active_role_grants_permission", "can_read_any": False},
        )
    )
    jwt_ = make_token(sub=sub)
    r = app_client.post("/protegido", headers={"Authorization": f"Bearer {jwt_}"})
    assert r.status_code == 200
    assert r.json() == {"sub": sub, "allowed": True}
    assert json.loads(route.calls.last.request.content)["subject_token"] == jwt_


@respx.mock
def test_dep_allowed_false_403(app_client, make_token):
    """T04 (rol USER) y T07 (rol retirado): AUTH responde allowed:false → 403."""
    sub = str(uuid.uuid4())
    respx.post(CHECK_URL).mock(
        return_value=httpx.Response(
            200,
            json={"subject_id": sub, "action": ANALYZE, "allowed": False,
                  "reason": "no_active_role_grants_permission", "can_read_any": False},
        )
    )
    r = app_client.post("/protegido", headers={"Authorization": f"Bearer {make_token(sub=sub)}"})
    assert r.status_code == 403
    assert r.json() == {"detail": "Permiso denegado"}


@pytest.mark.parametrize(
    "mock",
    [{"side_effect": httpx.ConnectError("down")}, {"side_effect": httpx.ReadTimeout("t")},
     {"return_value": httpx.Response(500, json={})}],
    ids=["caido", "timeout", "error_500"],
)
@respx.mock
def test_dep_auth_no_disponible_503(app_client, make_token, mock):
    """T08: AUTH inaccesible → 503, deny by default."""
    respx.post(CHECK_URL).mock(**mock)
    r = app_client.post("/protegido", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 503
    assert r.json() == {"detail": "Servicio de autorización no disponible"}


def test_get_authz_client_usa_settings(monkeypatch, tmp_path):
    from app.config import get_settings

    monkeypatch.setenv("SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("AUTH_URL", AUTH)
    monkeypatch.setenv("AUTH_TIMEOUT_SECONDS", "2.5")
    get_settings.cache_clear()
    get_authz_client.cache_clear()
    try:
        client = get_authz_client()
        assert isinstance(client, AuthzClient)
        assert client._timeout == 2.5
    finally:
        get_settings.cache_clear()
        get_authz_client.cache_clear()
