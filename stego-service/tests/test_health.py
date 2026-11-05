import sqlite3

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_startup_creates_db_and_quarantine(client, tmp_path):
    assert (tmp_path / "quarantine").is_dir()
    with sqlite3.connect(tmp_path / "stego.db") as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"analyses", "audit_log"} <= tables


def test_unknown_route_uses_detail_format(client):
    r = client.get("/nope")
    assert r.status_code == 404
    assert "detail" in r.json()


def test_settings_reject_short_service_token(monkeypatch):
    monkeypatch.setenv("SERVICE_TOKEN", "corto")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_reject_timeout_over_3s(monkeypatch):
    monkeypatch.setenv("SERVICE_TOKEN", "t" * 32)
    monkeypatch.setenv("AUTH_TIMEOUT_SECONDS", "10")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_detector_defaults_and_order(monkeypatch):
    monkeypatch.setenv("SERVICE_TOKEN", "t" * 32)
    s = Settings(_env_file=None)
    assert (s.suspicious_threshold, s.inconclusive_threshold, s.min_dimension) == (0.95, 0.5, 64)
    monkeypatch.setenv("INCONCLUSIVE_THRESHOLD", "0.97")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_openapi_documents_contract(client):
    spec = client.get("/openapi.json").json()
    analyze = spec["paths"]["/api/steganography/analyze"]["post"]
    results = spec["paths"]["/api/steganography/results/{analysis_id}"]["get"]
    assert {"200", "400", "401", "403", "413", "415", "422", "503"} <= set(analyze["responses"])
    assert {"200", "401", "403", "404", "503"} == set(results["responses"])
    body = analyze["requestBody"]["content"]["multipart/form-data"]["schema"]
    assert body["required"] == ["file"] and body["properties"]["file"]["format"] == "binary"
    assert analyze["security"] and results["security"]
    assert "AnalysisResult" in spec["components"]["schemas"]
