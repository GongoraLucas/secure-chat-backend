"""S7 · GET /api/steganography/results/{id}: RBAC vía AUTH + propiedad, 404 si es ajeno (§5, §7, §11) [T11]."""

import json
import sqlite3
import uuid

import httpx
import pytest
import respx

from app.config import get_settings
from app.repository import insert_analysis
from app.security.dependencies import get_authz_client

URL = "/api/steganography/results/{}"
READ = "steganography.results.read"
CHECK_URL = "http://auth.test:3000/internal/authorization/check"
NOT_FOUND = {"detail": "Análisis no encontrado"}
FIELDS = {"analysis_id", "user_id", "filename", "sha256", "technique", "status", "indicators", "action",
          "limitations", "created_at"}


@pytest.fixture
def api(client):
    from app.main import app
    from app.security.authz_client import AuthzClient

    app.dependency_overrides[get_authz_client] = lambda: AuthzClient("http://auth.test:3000", "t" * 32, 3.0)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def db():
    return get_settings().db_path


def _audit(db):
    conn = sqlite3.connect(db)
    try:
        return [r[0] for r in conn.execute("SELECT event FROM audit_log ORDER BY id")]
    finally:
        conn.close()


def _store(db, owner):
    analysis_id = str(uuid.uuid4())
    insert_analysis(db, {
        "analysis_id": analysis_id,
        "user_id": owner,
        "filename": "muestra.png",
        "sha256": "ab" * 32,
        "technique": "lsb_chi_square",
        "indicators": {"p_value_max": 0.98, "threshold": 0.95},
        "status": "sospechoso",
        "action": "cuarentena",
        "limitations": "Resultado indicativo, no concluyente",
        "created_at": "2026-11-04T10:00:00Z",
    })
    return analysis_id


def _auth(sub, allowed=True, can_read_any=False, action=READ, reason="active_role_grants_permission"):
    return respx.post(CHECK_URL).mock(
        return_value=httpx.Response(
            200,
            json={"subject_id": sub, "action": action, "allowed": allowed, "reason": reason,
                  "can_read_any": can_read_any},
        )
    )


def _get(api, token, analysis_id):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return api.get(URL.format(analysis_id), headers=headers)


# ---------- Camino feliz ----------


@respx.mock
def test_dueno_con_read_own_200(api, db, make_token):
    owner = str(uuid.uuid4())
    aid = _store(db, owner)
    route = _auth(owner)
    r = _get(api, make_token(sub=owner), aid)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == FIELDS
    assert body["analysis_id"] == aid and body["user_id"] == owner
    assert body["indicators"] == {"p_value_max": 0.98, "threshold": 0.95}
    assert body["status"] == "sospechoso" and body["action"] == "cuarentena"
    sent = json.loads(route.calls.last.request.content)
    assert sent["action"] == READ
    assert _audit(db)[-1] == "result_read"


@respx.mock
def test_ajeno_con_read_any_200(api, db, make_token):
    admin = str(uuid.uuid4())
    aid = _store(db, str(uuid.uuid4()))
    _auth(admin, can_read_any=True)
    r = _get(api, make_token(sub=admin), aid)
    assert r.status_code == 200
    assert r.json()["analysis_id"] == aid


# ---------- 404 que no revela existencia ----------


@respx.mock
def test_ajeno_sin_read_any_404_igual_que_inexistente(api, db, make_token):
    beto = str(uuid.uuid4())
    aid = _store(db, str(uuid.uuid4()))
    _auth(beto)
    ajeno = _get(api, make_token(sub=beto), aid)
    inexistente = _get(api, make_token(sub=beto), str(uuid.uuid4()))
    assert ajeno.status_code == inexistente.status_code == 404
    assert ajeno.json() == inexistente.json() == NOT_FOUND
    assert _audit(db)[-2:] == ["result_not_found", "result_not_found"]


@pytest.mark.parametrize("bad_id", ["123", "no-es-uuid", "' OR 1=1 --"])
@respx.mock
def test_id_no_uuid_404(api, db, make_token, bad_id):
    sub = str(uuid.uuid4())
    _auth(sub, can_read_any=True)
    r = _get(api, make_token(sub=sub), bad_id)
    assert r.status_code == 404
    assert r.json() == NOT_FOUND


# ---------- Denegaciones ----------


@respx.mock
def test_sin_token_401_sin_llamar_a_auth(api, db):
    route = respx.post(CHECK_URL).mock(return_value=httpx.Response(200, json={}))
    r = _get(api, None, _store(db, str(uuid.uuid4())))
    assert r.status_code == 401
    assert r.json() == {"detail": "No autenticado"}
    assert route.called is False


@respx.mock
def test_token_manipulado_401(api, db, make_token):
    route = respx.post(CHECK_URL).mock(return_value=httpx.Response(200, json={}))
    owner = str(uuid.uuid4())
    h, p, s = make_token(sub=owner).split(".")
    r = _get(api, f"{h}.{p}x.{s}", _store(db, owner))
    assert r.status_code == 401
    assert route.called is False


@respx.mock
def test_sin_permiso_403_aunque_sea_dueno(api, db, make_token):
    """carla (USER): AUTH niega `results.read` → 403, antes de mirar la BD."""
    owner = str(uuid.uuid4())
    aid = _store(db, owner)
    _auth(owner, allowed=False, reason="no_active_role_grants_permission")
    r = _get(api, make_token(sub=owner), aid)
    assert r.status_code == 403
    assert r.json() == {"detail": "Permiso denegado"}
    assert _audit(db)[-1] == "authz_denied"


@pytest.mark.parametrize(
    "mock",
    [{"side_effect": httpx.ReadTimeout("t")}, {"return_value": httpx.Response(500, json={})}],
    ids=["timeout", "error_500"],
)
@respx.mock
def test_auth_no_disponible_503(api, db, make_token, mock):
    owner = str(uuid.uuid4())
    aid = _store(db, owner)
    respx.post(CHECK_URL).mock(**mock)
    r = _get(api, make_token(sub=owner), aid)
    assert r.status_code == 503
    assert r.json() == {"detail": "Servicio de autorización no disponible"}


@respx.mock
def test_decision_para_otra_accion_503(api, db, make_token):
    owner = str(uuid.uuid4())
    aid = _store(db, owner)
    _auth(owner, action="steganography.analyze")
    assert _get(api, make_token(sub=owner), aid).status_code == 503
