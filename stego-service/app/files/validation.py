"""Validación de archivos subidos (§7): tamaño → formato → integridad/píxeles.

Se usa DESPUÉS de la autorización (S3). Las excepciones llevan `status_code` y un
`detail` genérico: nunca exponen detalles internos de Pillow.
"""

import io
import re
from typing import Literal, Protocol

from PIL import Image

Format = Literal["png", "bmp"]

_SIGNATURES: dict[Format, bytes] = {"png": b"\x89PNG\r\n\x1a\n", "bmp": b"BM"}
_EXTENSIONS: dict[str, Format] = {".png": "png", ".bmp": "bmp"}
_MIME_TYPES: dict[Format, frozenset[str]] = {
    "png": frozenset({"image/png"}),
    "bmp": frozenset({"image/bmp", "image/x-bmp", "image/x-ms-bmp"}),
}
_PIL_FORMATS: dict[Format, str] = {"png": "PNG", "bmp": "BMP"}

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]")
_MAX_DISPLAY_NAME = 100


class FileValidationError(Exception):
    status_code = 400
    detail = "Archivo inválido"


class FileTooLarge(FileValidationError):
    status_code = 413
    detail = "Archivo demasiado grande"


class UnsupportedFormat(FileValidationError):
    status_code = 415
    detail = "Formato no admitido"


class InvalidImage(FileValidationError):
    status_code = 422
    detail = "Imagen corrupta o inválida"


class _Readable(Protocol):
    async def read(self, size: int = -1) -> bytes: ...


async def read_limited(upload: _Readable, max_bytes: int, chunk_size: int = 64 * 1024) -> bytes:
    """Lee en trozos y corta en cuanto se supera `max_bytes` (nunca lee más de max_bytes + 1)."""
    buf = bytearray()
    while True:
        chunk = await upload.read(min(chunk_size, max_bytes + 1 - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise FileTooLarge()
    if not buf:
        raise UnsupportedFormat()
    return bytes(buf)


def _basename(name: str) -> str:
    return re.split(r"[\\/]", name)[-1]


def detect_format(filename: str | None, content_type: str | None, data: bytes) -> Format:
    """Extensión, firma real y Content-Type deben indicar el MISMO formato admitido."""
    if not filename or not content_type:
        raise UnsupportedFormat()
    base = _basename(filename)
    dot = base.rfind(".")
    fmt = _EXTENSIONS.get(base[dot:].lower()) if dot > 0 else None
    if fmt is None:
        raise UnsupportedFormat()
    if not data.startswith(_SIGNATURES[fmt]):
        raise UnsupportedFormat()
    mime = content_type.split(";", 1)[0].strip().lower()
    if mime not in _MIME_TYPES[fmt]:
        raise UnsupportedFormat()
    return fmt


def load_image(data: bytes, fmt: Format, max_pixels: int) -> Image.Image:
    """Control de píxeles con la cabecera (antes de decodificar), verify() y carga completa."""
    Image.MAX_IMAGE_PIXELS = max_pixels  # segunda barrera; Pillow solo lanza a 2× este valor
    formats = [_PIL_FORMATS[fmt]]
    try:
        with Image.open(io.BytesIO(data), formats=formats) as probe:
            width, height = probe.size
            if width <= 0 or height <= 0 or width * height > max_pixels:
                raise InvalidImage()
            probe.verify()
        img = Image.open(io.BytesIO(data), formats=formats)
        img.load()
    except InvalidImage:
        raise
    except (OSError, SyntaxError, ValueError, Image.DecompressionBombError) as exc:
        raise InvalidImage() from exc
    return img


def sanitize_filename(name: str | None) -> str:
    """Nombre solo para MOSTRAR y registrar. Nunca se usa para construir rutas."""
    if not name:
        return "archivo"
    clean = _UNSAFE_CHARS.sub("_", _basename(name))[:_MAX_DISPLAY_NAME]
    return "archivo" if clean.strip(".") == "" else clean
