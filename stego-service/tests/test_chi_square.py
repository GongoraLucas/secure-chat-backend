"""S5 · Detector chi-cuadrado LSB (Westfeld–Pfitzmann) y clasificación. §7 [T09]."""

import hashlib
import importlib.util
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from app.detection.chi_square import PORTIONS, analyze, pov_p_value
from app.detection.classifier import LIMITATIONS, classify

REPO = Path(__file__).resolve().parents[2]
SAMPLES = REPO / "samples"
SUSP, INCONC, MIN_DIM = 0.95, 0.5, 64


def _classify(img: Image.Image):
    return classify(analyze(img, SUSP), SUSP, INCONC, MIN_DIM)


def _sample(name: str) -> Image.Image:
    path = SAMPLES / name
    if not path.exists():
        pytest.fail(f"Falta {path}: ejecuta python scripts/make_samples.py")
    with Image.open(path) as img:
        img.load()
        return img.copy()


# ---------- pov_p_value ----------

def test_pares_igualados_dan_p_cercano_a_1():
    values = np.repeat(np.arange(256, dtype=np.uint8), 100)  # h[2k] == h[2k+1]
    assert pov_p_value(values) > 0.99


def test_pares_desiguales_dan_p_cercano_a_0():
    values = np.repeat(np.arange(0, 256, 2, dtype=np.uint8), 100)  # solo valores pares
    assert pov_p_value(values) < 0.01


def test_menos_de_dos_pares_validos_devuelve_none():
    assert pov_p_value(np.full(1000, 7, dtype=np.uint8)) is None
    assert pov_p_value(np.array([], dtype=np.uint8)) is None


# ---------- analyze ----------

def test_indicadores_por_canal_y_porcion():
    rng = np.random.default_rng(1)
    img = Image.fromarray(rng.integers(0, 256, (100, 100, 3), dtype=np.uint8), "RGB")
    ind = analyze(img, SUSP)
    assert PORTIONS == [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    assert set(ind["p_values"]) == {"R", "G", "B"}
    assert all(len(v) == 10 for v in ind["p_values"].values())
    assert ind["width"] == 100 and ind["height"] == 100
    assert ind["threshold"] == SUSP
    assert 0.0 <= ind["p_value_max"] <= 1.0


@pytest.mark.parametrize("mode", ["L", "RGBA", "P"])
def test_acepta_otros_modos(mode):
    rng = np.random.default_rng(2)
    base = Image.fromarray(rng.integers(0, 256, (80, 80, 3), dtype=np.uint8), "RGB")
    img = base.convert(mode)
    ind = analyze(img, SUSP)
    expected = {"L"} if mode == "L" else {"R", "G", "B"}
    assert set(ind["p_values"]) == expected


# ---------- classify ----------

def test_imagen_pequena_es_no_concluyente():
    rng = np.random.default_rng(3)
    img = Image.fromarray(rng.integers(0, 256, (32, 32, 3), dtype=np.uint8), "RGB")
    assert _classify(img) == ("no_concluyente", "advertencia")


def test_imagen_plana_sin_pares_validos_es_no_concluyente():
    img = Image.new("RGB", (128, 128), (10, 20, 30))
    assert _classify(img) == ("no_concluyente", "advertencia")


def test_limitaciones_no_vacias():
    assert "indicio" in LIMITATIONS.lower()


# ---------- muestras reales (T09) ----------

def test_stego_lsb_full_es_sospechoso():
    img = _sample("stego_lsb_full.png")
    ind = analyze(img, SUSP)
    assert classify(ind, SUSP, INCONC, MIN_DIM) == ("sospechoso", "cuarentena")
    assert ind["embedding_estimate"] == 100


def test_stego_lsb_50_es_sospechoso_con_carga_estimada_media():
    img = _sample("stego_lsb_50.png")
    ind = analyze(img, SUSP)
    assert classify(ind, SUSP, INCONC, MIN_DIM)[0] == "sospechoso"
    assert 40 <= ind["embedding_estimate"] <= 60


@pytest.mark.parametrize("name", ["clean_noise.png", "clean_gradient.png"])
def test_muestras_limpias_no_son_sospechosas(name):
    status, _ = _classify(_sample(name))
    assert status in {"sin_indicios", "no_concluyente"}


# ---------- make_samples.py ----------

def _load_make_samples():
    spec = importlib.util.spec_from_file_location("make_samples", REPO / "scripts" / "make_samples.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_make_samples_es_determinista(tmp_path):
    mod = _load_make_samples()
    a, b = tmp_path / "a", tmp_path / "b"
    mod.generate(a)
    mod.generate(b)
    names = sorted(p.name for p in a.iterdir())
    assert names == sorted([
        "clean_gradient.png", "clean_noise.png", "stego_lsb_50.png", "stego_lsb_full.png",
        "fake.png", "corrupt.png", "too_big.png",
    ])
    for n in names:
        assert hashlib.sha256((a / n).read_bytes()).hexdigest() == \
            hashlib.sha256((b / n).read_bytes()).hexdigest(), n
    assert (a / "too_big.png").stat().st_size > 5 * 1024 * 1024
    for n in names:
        if n != "too_big.png":
            assert (a / n).stat().st_size < 5 * 1024 * 1024, n
