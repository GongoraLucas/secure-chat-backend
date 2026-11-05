#!/usr/bin/env python3
"""Genera las muestras de prueba de STEGO de forma determinista (semilla fija).

Uso (desde la raíz del repo):  stego-service/.venv/bin/python scripts/make_samples.py [DIR]
Por defecto escribe en samples/. Los nombres son contrato: la colección Postman los usa.
Imágenes sintéticas (numpy), sin derechos de terceros.
"""

import io
import sys
from pathlib import Path

import numpy as np
from PIL import Image

SEED = 20261104
SIZE = 512
TOO_BIG_BYTES = 5 * 1024 * 1024 + 512 * 1024  # > MAX_UPLOAD_BYTES (5 MiB)
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _rng(offset: int) -> np.random.Generator:
    return np.random.default_rng(SEED + offset)


def _png(arr: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG")
    return buf.getvalue()


def clean_gradient() -> np.ndarray:
    """Degradado suave con corrección gamma (como una imagen codificada para pantalla)."""
    y, x = np.mgrid[0:SIZE, 0:SIZE] / SIZE
    rgb = np.stack([255 * x**2.2, 255 * (0.5 * x + 0.5 * y) ** 1.8, 255 * (1 - y) ** 2.0], axis=-1)
    return np.clip(np.round(rgb), 0, 255).astype(np.uint8)


def clean_noise() -> np.ndarray:
    """Ruido 'natural' simulado: campo suave + ruido de sensor, cuantizado y con ajuste de contraste."""
    rng = _rng(1)
    fields = []
    for low in rng.normal(size=(3, 16, 16)):
        norm = ((low - low.min()) / (low.max() - low.min()) * 255).astype(np.float32)
        fields.append(np.asarray(Image.fromarray(norm, "F").resize((SIZE, SIZE), Image.BICUBIC)))
    field = np.stack(fields, axis=-1)
    raw = np.round(40 + field * 0.55 + rng.normal(0, 6, (SIZE, SIZE, 3)))  # captura (8 bits)
    return np.clip(np.round((raw - 30) * 1.45), 0, 255).astype(np.uint8)  # realce de contraste


def lsb_sequential(cover: np.ndarray, fraction: float, offset: int) -> np.ndarray:
    """Reemplazo LSB secuencial (orden de escaneo, R,G,B intercalados) con bits aleatorios."""
    flat = cover.ravel().copy()
    n = int(flat.size * fraction)
    bits = _rng(offset).integers(0, 2, n, dtype=np.uint8)
    flat[:n] = (flat[:n] & 0xFE) | bits
    return flat.reshape(cover.shape)


def generate(out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    noise = clean_noise()
    files = {
        "clean_gradient.png": _png(clean_gradient()),
        "clean_noise.png": _png(noise),
        "stego_lsb_50.png": _png(lsb_sequential(noise, 0.5, 2)),
        "stego_lsb_full.png": _png(lsb_sequential(noise, 1.0, 3)),
        "fake.png": b"Esto es texto plano con extension .png; no es una imagen.\n",
    }
    files["corrupt.png"] = files["clean_noise.png"][: len(files["clean_noise.png"]) // 2]
    files["too_big.png"] = PNG_SIGNATURE + _rng(4).bytes(TOO_BIG_BYTES)
    for name, data in files.items():
        (out_dir / name).write_bytes(data)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "samples"
    generate(target)
    print(f"Muestras escritas en {target}")
