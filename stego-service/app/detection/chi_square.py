"""Ataque chi-cuadrado sobre pares de valores (Westfeld y Pfitzmann, 2000).

El reemplazo LSB solo mueve un valor dentro de su par (2k, 2k+1); con un mensaje
aleatorio las frecuencias del par se igualan. p cercano a 1 ⇒ pares igualados ⇒
compatible con incrustación LSB. Ver docs/05-detector-esteganografia.md.
"""

from typing import Any

import numpy as np
from PIL import Image
from scipy.stats import chi2

PORTIONS = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
MIN_EXPECTED = 4  # E_k > 4: condición de validez del test χ²
MIN_VALID_PAIRS = 2  # gl = pares − 1 ≥ 1


def pov_p_value(values: np.ndarray) -> float | None:
    """p-value de incrustación para una secuencia de valores uint8; None si el test no es válido."""
    hist = np.bincount(np.asarray(values, dtype=np.uint8).ravel(), minlength=256).astype(np.float64)
    observed = hist[0::2]
    expected = (hist[0::2] + hist[1::2]) / 2.0
    valid = expected > MIN_EXPECTED
    n_pairs = int(valid.sum())
    if n_pairs < MIN_VALID_PAIRS:
        return None
    stat = float(np.sum((observed[valid] - expected[valid]) ** 2 / expected[valid]))
    # sf = 1 − cdf, numéricamente estable en las colas
    return float(chi2.sf(stat, n_pairs - 1))


def _channels(img: Image.Image) -> dict[str, np.ndarray]:
    """Escala de grises → un canal L; el resto (RGB, RGBA, P, …) → R, G, B (alfa descartado)."""
    if img.mode in ("L", "LA", "I", "I;16", "F"):
        gray = img.getchannel("L") if img.mode == "LA" else img.convert("L")
        return {"L": np.asarray(gray, dtype=np.uint8).ravel()}
    rgb = np.asarray(img.convert("RGB"), dtype=np.uint8)
    return {name: rgb[:, :, i].ravel() for i, name in enumerate("RGB")}


def analyze(img: Image.Image, threshold: float) -> dict[str, Any]:
    """p-values por canal y por porción acumulada (orden de escaneo) + indicadores resumen."""
    channels = _channels(img)
    p_values: dict[str, list[float | None]] = {}
    estimate = 0
    for name, flat in channels.items():
        series: list[float | None] = []
        for pct in PORTIONS:
            n = (flat.size * pct) // 100
            p = pov_p_value(flat[:n]) if n > 0 else None
            series.append(None if p is None else round(p, 6))
            if p is not None and p > threshold:
                estimate = max(estimate, pct)
        p_values[name] = series

    all_p = [p for s in p_values.values() for p in s if p is not None]
    first = [s[0] for s in p_values.values() if s[0] is not None]
    width, height = img.size
    return {
        "p_values": p_values,
        "portions": PORTIONS,
        "p_value_first_max": max(first) if first else None,
        "p_value_max": max(all_p) if all_p else None,
        "embedding_estimate": estimate,
        "threshold": threshold,
        "width": width,
        "height": height,
    }
