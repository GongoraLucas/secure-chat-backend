"""S6 · POST /api/steganography/analyze: orden, política, persistencia y auditoría (§7, §11) [T09, T10, T12]."""

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path

import httpx
import pytest
import respx

from app.config import get_settings
from app.security.dependencies import get_authz_client

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
URL = "/api/steganography/analyze"
ANALYZE = "steganography.analyze"
CHECK_URL = "http://auth.test:3000/internal/authorization/check"


@pytest.fixture
def api(client):
    """TestClient con AUTH apuntando a una URL simulada por respx."""
    from app.main import app
    from app.security.authz_client import AuthzClient

    app.dependency_overrides[get_authz_client] = lambda: AuthzClient("http://auth.test:3000", "t" * 32, 3.0)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def data_dir():
    return get_settings().data_dir


def _rows(data_dir, table):
    conn = sqlite3.connect(data_dir / "stego.db")
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table}")]  # noqa: S608 (tabla fija)
    finally:
        conn.close()


def _quarantined(data_dir):
    return sorted(p.name for p in (data_dir / "quarantine").iterdir())


def _allow(sub, allowed=True, reason="active_role_grants_permission"):
    return respx.post(CHECK_URL).mock(
        return_value=httpx.Response(
            200,
            json={"subject_id": sub, "action": ANALYZE, "allowed": allowed, "reason": reason,
                  "can_read_any": False},
        )
    )


def _upload(api, token, name, data=None, mime="image/png", field="file", extra=None):
    data = (SAMPLES / name).read_bytes() if data is None else data
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return api.post(URL, headers=headers, files={field: (name, data, mime)}, data=extra or {})


# ---------- Denegaciones antes de tocar el archivo ----------


@respx.mock
def test_sin_token_401_sin_llamar_a_auth_y_audita(api, data_dir):
    route = respx.post(CHECK_URL).mock(return_value=httpx.Response(200, json={}))
    r = _upload(api, None, "stego_lsb_full.png")
    assert r.status_code == 401
    assert r.json() == {"detail": "No autenticado"}
    assert route.called is False
    assert _rows(data_dir, "analyses") == []
    assert [e["event"] for e in _rows(data_dir, "audit_log")] == ["token_invalid"]


@respx.mock
def test_token_manipulado_401(api, data_dir, make_token):
    route = respx.post(CHECK_URL).mock(return_value=httpx.Response(200, json={}))
    h, p, s = make_token().split(".")
    r = _upload(api, f"{h}.{p}x.{s}", "stego_lsb_full.png")
    assert r.status_code == 401
    assert route.called is False
    assert _rows(data_dir, "analyses") == []


@respx.mock
def test_allowed_false_403_no_procesa(api, data_dir, make_token):
    sub = str(uuid.uuid4())
    _allow(sub, allowed=False, reason="no_active_role_grants_permission")
    r = _upload(api, make_token(sub=sub), "stego_lsb_full.png")
    assert r.status_code == 403
    assert r.json() == {"detail": "Permiso denegado"}
    assert _rows(data_dir, "analyses") == []
    assert _quarantined(data_dir) == []
    audit = _rows(data_dir, "audit_log")
    assert [(e["event"], e["user_id"]) for e in audit] == [("authz_denied", sub)]


@pytest.mark.parametrize(
    "mock",
    [{"side_effect": httpx.ReadTimeout("t")}, {"return_value": httpx.Response(500, json={})}],
    ids=["timeout", "error_500"],
)
@respx.mock
def test_auth_no_disponible_503_no_procesa(api, data_dir, make_token, mock):
    """T08: deny by default; el archivo no se analiza ni se guarda."""
    respx.post(CHECK_URL).mock(**mock)
    r = _upload(api, make_token(), "stego_lsb_full.png")
    assert r.status_code == 503
    assert r.json() == {"detail": "Servicio de autorización no disponible"}
    assert _rows(data_dir, "analyses") == []
    assert _quarantined(data_dir) == []
    assert [e["event"] for e in _rows(data_dir, "audit_log")] == ["authz_unavailable"]


# ---------- Validación (T10) ----------


@respx.mock
def test_archivo_grande_413(api, data_dir, make_token, monkeypatch):
    sub = str(uuid.uuid4())
    _allow(sub)
    big = b"\x89PNG\r\n\x1a\n" + b"\0" * (get_settings().max_upload_bytes + 10)
    r = _upload(api, make_token(sub=sub), "big.png", data=big)
    assert r.status_code == 413
    assert r.json() == {"detail": "Archivo demasiado grande"}
    assert _rows(data_dir, "analyses") == []
    audit = _rows(data_dir, "audit_log")
    assert [(e["event"], e["detail"]) for e in audit] == [("analysis_rejected", "too_large")]


@respx.mock
def test_fake_png_415(api, data_dir, make_token):
    sub = str(uuid.uuid4())
    _allow(sub)
    r = _upload(api, make_token(sub=sub), "fake.png")
    assert r.status_code == 415
    assert r.json() == {"detail": "Formato no admitido"}
    assert _rows(data_dir, "analyses") == []
    assert [(e["event"], e["detail"]) for e in _rows(data_dir, "audit_log")] == [
        ("analysis_rejected", "unsupported_format")
    ]


@respx.mock
def test_mime_incoherente_415(api, make_token):
    sub = str(uuid.uuid4())
    _allow(sub)
    r = _upload(api, make_token(sub=sub), "clean_noise.png", mime="image/bmp")
    assert r.status_code == 415


@respx.mock
def test_campo_file_ausente_415_sin_detalles_internos(api, make_token):
    sub = str(uuid.uuid4())
    _allow(sub)
    r = _upload(api, make_token(sub=sub), "clean_noise.png", field="otro")
    assert r.status_code == 415
    assert r.json() == {"detail": "Formato no admitido"}


@respx.mock
def test_corrupto_422_registra_error_rechazo(api, data_dir, make_token):
    sub = str(uuid.uuid4())
    _allow(sub)
    data = (SAMPLES / "corrupt.png").read_bytes()
    r = _upload(api, make_token(sub=sub), "corrupt.png")
    assert r.status_code == 422
    assert r.json() == {"detail": "Imagen corrupta o inválida"}
    [row] = _rows(data_dir, "analyses")
    assert (row["status"], row["action"], row["user_id"]) == ("error", "rechazo", sub)
    assert row["sha256"] == hashlib.sha256(data).hexdigest()
    assert _quarantined(data_dir) == []
    [ev] = _rows(data_dir, "audit_log")
    assert (ev["event"], ev["analysis_id"], ev["detail"]) == ("analysis_rejected", row["id"], "invalid_image")


# ---------- Análisis, política y persistencia (T09) ----------


@respx.mock
def test_stego_lsb_full_sospechoso_cuarentena(api, data_dir, make_token):
    sub = str(uuid.uuid4())
    _allow(sub)
    data = (SAMPLES / "stego_lsb_full.png").read_bytes()
    r = _upload(api, make_token(sub=sub), "stego_lsb_full.png")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"analysis_id", "user_id", "filename", "sha256", "technique", "status",
                         "indicators", "action", "limitations", "created_at"}
    assert (body["status"], body["action"]) == ("sospechoso", "cuarentena")
    assert body["technique"] == "lsb_chi_square"
    assert body["user_id"] == sub
    assert body["sha256"] == hashlib.sha256(data).hexdigest()
    assert body["indicators"]["p_value_max"] > body["indicators"]["threshold"]
    analysis_id = body["analysis_id"]
    assert str(uuid.UUID(analysis_id)) == analysis_id

    # Cuarentena con nombre UUID (nunca el original) y mismo contenido.
    assert _quarantined(data_dir) == [uuid.UUID(analysis_id).hex]
    stored = (data_dir / "quarantine" / uuid.UUID(analysis_id).hex).read_bytes()
    assert hashlib.sha256(stored).hexdigest() == body["sha256"]

    [row] = _rows(data_dir, "analyses")
    assert row["id"] == analysis_id
    assert json.loads(row["indicators"]) == body["indicators"]
    assert (row["status"], row["action"], row["filename"]) == ("sospechoso", "cuarentena", "stego_lsb_full.png")
    [ev] = _rows(data_dir, "audit_log")
    assert (ev["event"], ev["user_id"], ev["analysis_id"]) == ("analysis_completed", sub, analysis_id)


@respx.mock
def test_clean_noise_sin_indicios_no_queda_en_disco(api, data_dir, make_token):
    sub = str(uuid.uuid4())
    _allow(sub)
    r = _upload(api, make_token(sub=sub), "clean_noise.png")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("sin_indicios", "no_concluyente")
    assert _quarantined(data_dir) == []
    assert len(_rows(data_dir, "analyses")) == 1


@respx.mock
def test_user_id_sale_del_token_no_del_cliente(api, make_token):
    sub = str(uuid.uuid4())
    _allow(sub)
    r = _upload(api, make_token(sub=sub), "clean_noise.png", extra={"user_id": str(uuid.uuid4())})
    assert r.status_code == 200
    assert r.json()["user_id"] == sub


@respx.mock
def test_filename_saneado(api, data_dir, make_token):
    sub = str(uuid.uuid4())
    _allow(sub)
    data = (SAMPLES / "clean_noise.png").read_bytes()
    r = _upload(api, make_token(sub=sub), "../../x y.png", data=data)
    assert r.status_code == 200
    assert r.json()["filename"] == "x_y.png"
    assert _rows(data_dir, "analyses")[0]["filename"] == "x_y.png"


# ---------- Bitácora sin secretos (T12) ----------


@respx.mock
def test_bitacora_no_contiene_jwt(api, data_dir, make_token):
    sub = str(uuid.uuid4())
    _allow(sub)
    tokens = [make_token(sub=sub) for _ in range(3)]
    _upload(api, tokens[0], "stego_lsb_full.png")
    _upload(api, tokens[1], "fake.png")
    _upload(api, tokens[2][:-4] + "AAAA", "clean_noise.png")  # firma inválida → token_invalid
    audit = _rows(data_dir, "audit_log")
    assert {e["event"] for e in audit} == {"analysis_completed", "analysis_rejected", "token_invalid"}
    dump = json.dumps(audit)
    for t in tokens:
        assert t not in dump
        assert t.split(".")[1] not in dump  # ni siquiera el payload
