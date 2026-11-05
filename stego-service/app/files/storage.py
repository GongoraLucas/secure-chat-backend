"""Almacenamiento de archivos en cuarentena (§7, docs/05 §5.3).

Nombre = UUID hex del análisis (nunca el nombre original), dentro de DATA_DIR/quarantine,
fuera de cualquier ruta servida. Solo lectura/escritura para el usuario del proceso.
"""

import os
import uuid
from pathlib import Path


def quarantine(quarantine_dir: Path, analysis_id: str, data: bytes) -> Path:
    name = uuid.UUID(analysis_id).hex  # valida y normaliza: solo [0-9a-f]{32}
    path = quarantine_dir / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path
