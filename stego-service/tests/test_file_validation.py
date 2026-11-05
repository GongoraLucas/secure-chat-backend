"""S4 · Validación de archivos: tamaño (413), formato (415), integridad y píxeles (422). §7 [T10]."""

import asyncio
import io

import numpy as np
import pytest
from PIL import Image

from app.files.validation import (
    FileTooLarge,
    InvalidImage,
    UnsupportedFormat,
    detect_format,
    load_image,
    read_limited,
    sanitize_filename,
)


def _img_bytes(fmt: str, size=(32, 32), mode="RGB") -> bytes:
    rng = np.random.default_rng(0)
    channels = 3 if mode == "RGB" else 1
    arr = rng.integers(0, 256, size=(size[1], size[0], channels), dtype=np.uint8)
    img = Image.fromarray(arr.squeeze() if channels == 1 else arr, mode)
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


PNG = _img_bytes("PNG")
BMP = _img_bytes("BMP")


class FakeUpload:
    """Imita UploadFile.read(size) y cuenta cuántos bytes se leyeron."""

    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)
        self.bytes_read = 0

    async def read(self, size: int = -1) -> bytes:
        chunk = self._buf.read(size)
        self.bytes_read += len(chunk)
        return chunk


# ---------- 413 · tamaño ----------

def test_read_limited_accepts_exactly_max():
    data = b"x" * 1000
    assert asyncio.run(read_limited(FakeUpload(data), max_bytes=1000, chunk_size=64)) == data


def test_read_limited_rejects_over_max():
    with pytest.raises(FileTooLarge) as exc:
        asyncio.run(read_limited(FakeUpload(b"x" * 1001), max_bytes=1000, chunk_size=64))
    assert exc.value.status_code == 413


def test_read_limited_stops_reading_after_limit():
    up = FakeUpload(b"x" * 1_000_000)
    with pytest.raises(FileTooLarge):
        asyncio.run(read_limited(up, max_bytes=1000, chunk_size=64))
    assert up.bytes_read <= 1001


def test_read_limited_rejects_empty_file():
    with pytest.raises(UnsupportedFormat):
        asyncio.run(read_limited(FakeUpload(b""), max_bytes=1000))


# ---------- 415 · formato ----------

@pytest.mark.parametrize(
    ("filename", "ctype", "data", "expected"),
    [
        ("a.png", "image/png", PNG, "png"),
        ("A.PNG", "IMAGE/PNG; charset=binary", PNG, "png"),
        ("b.bmp", "image/bmp", BMP, "bmp"),
        ("b.bmp", "image/x-ms-bmp", BMP, "bmp"),
        ("b.BMP", "image/x-bmp", BMP, "bmp"),
    ],
)
def test_detect_format_accepts_coherent_files(filename, ctype, data, expected):
    assert detect_format(filename, ctype, data) == expected


@pytest.mark.parametrize(
    ("filename", "ctype", "data"),
    [
        ("fake.png", "image/png", b"esto es texto, no una imagen\n"),  # fake.png
        ("foto.jpg", "image/jpeg", _img_bytes("JPEG")),  # formato no admitido
        ("foto.png", "image/png", _img_bytes("JPEG")),  # extensión miente
        ("a.png", "image/png", BMP),  # firma BMP con extensión .png
        ("a.bmp", "image/bmp", PNG),  # firma PNG con extensión .bmp
        ("a.png", "image/jpeg", PNG),  # MIME incoherente
        ("a.png", "image/bmp", PNG),  # MIME de otro formato admitido
        ("a.png", None, PNG),  # MIME ausente
        ("a.png", "", PNG),
        ("sin_extension", "image/png", PNG),
        ("a.png.exe", "image/png", PNG),
        (None, "image/png", PNG),
        ("a.png", "image/png", b""),
        ("a.png", "image/png", b"\x89PN"),  # firma incompleta
    ],
)
def test_detect_format_rejects_unsupported_or_incoherent(filename, ctype, data):
    with pytest.raises(UnsupportedFormat) as exc:
        detect_format(filename, ctype, data)
    assert exc.value.status_code == 415


# ---------- 422 · integridad y píxeles ----------

def test_load_image_valid_png_and_bmp():
    for data, fmt in ((PNG, "png"), (BMP, "bmp")):
        img = load_image(data, fmt, max_pixels=16_000_000)
        assert img.size == (32, 32)
        assert np.asarray(img).shape == (32, 32, 3)


def test_load_image_truncated_png():
    with pytest.raises(InvalidImage) as exc:
        load_image(PNG[: len(PNG) // 2], "png", max_pixels=16_000_000)
    assert exc.value.status_code == 422


def test_load_image_signature_plus_garbage():
    with pytest.raises(InvalidImage):
        load_image(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200, "png", max_pixels=16_000_000)


def test_load_image_truncated_bmp():
    with pytest.raises(InvalidImage):
        load_image(BMP[:60], "bmp", max_pixels=16_000_000)


def test_load_image_rejects_too_many_pixels_before_decoding():
    big = _img_bytes("PNG", size=(100, 100))
    with pytest.raises(InvalidImage):
        load_image(big, "png", max_pixels=100 * 100 - 1)
    assert load_image(big, "png", max_pixels=100 * 100).size == (100, 100)


def test_load_image_rejects_decompression_bomb():
    # 6000x6000 = 36 Mpx en pocos KB: excede MAX_PIXELS por defecto (16 M).
    buf = io.BytesIO()
    Image.new("L", (6000, 6000)).save(buf, format="PNG")
    assert len(buf.getvalue()) < 200_000
    with pytest.raises(InvalidImage):
        load_image(buf.getvalue(), "png", max_pixels=16_000_000)


def test_load_image_format_mismatch_is_invalid():
    with pytest.raises(InvalidImage):
        load_image(PNG, "bmp", max_pixels=16_000_000)


# ---------- nombre para mostrar ----------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("muestra.png", "muestra.png"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\x\\a.png", "a.png"),
        ("mi foto <script>.png", "mi_foto__script_.png"),
        ("", "archivo"),
        (None, "archivo"),
        ("..", "archivo"),
        ("a" * 300 + ".png", "a" * 100),
    ],
)
def test_sanitize_filename(raw, expected):
    assert sanitize_filename(raw) == expected
