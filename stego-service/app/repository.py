"""Persistencia de STEGO en SQLite propio (aislado de la BD de AUTH)."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    filename    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    technique   TEXT NOT NULL,
    indicators  TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('sin_indicios','sospechoso','no_concluyente','error')),
    action      TEXT CHECK (action IS NULL OR action IN ('rechazo','cuarentena','advertencia')),
    limitations TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_user ON analyses(user_id);
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    event       TEXT NOT NULL,
    user_id     TEXT,
    analysis_id TEXT,
    detail      TEXT
);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
    # `with` en sqlite3 solo hace commit; cerramos explícitamente.
    conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def audit(
    db_path: Path,
    event: str,
    user_id: str | None = None,
    analysis_id: str | None = None,
    detail: str | None = None,
) -> None:
    """Bitácora de seguridad (T12). `detail` nunca lleva tokens, claves ni contenido del archivo."""
    conn = connect(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT INTO audit_log (ts, event, user_id, analysis_id, detail) VALUES (?, ?, ?, ?, ?)",
                (_now(), event, user_id, analysis_id, detail),
            )
    finally:
        conn.close()


def insert_analysis(db_path: Path, record: dict[str, Any]) -> None:
    conn = connect(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT INTO analyses (id, user_id, filename, sha256, technique, indicators, status,"
                " action, limitations, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record["analysis_id"],
                    record["user_id"],
                    record["filename"],
                    record["sha256"],
                    record["technique"],
                    json.dumps(record["indicators"], separators=(",", ":")),
                    record["status"],
                    record["action"],
                    record["limitations"],
                    record["created_at"],
                ),
            )
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Fila de `analyses` → forma de respuesta de §7."""
    return {
        "analysis_id": row["id"],
        "user_id": row["user_id"],
        "filename": row["filename"],
        "sha256": row["sha256"],
        "technique": row["technique"],
        "status": row["status"],
        "indicators": json.loads(row["indicators"]),
        "action": row["action"],
        "limitations": row["limitations"],
        "created_at": row["created_at"],
    }


def get_analysis(db_path: Path, analysis_id: str) -> dict[str, Any] | None:
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    finally:
        conn.close()
    return row_to_dict(row) if row is not None else None
