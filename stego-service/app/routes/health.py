from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health", summary="Estado del servicio")
def health() -> dict[str, str]:
    # Sin dependencias externas: STEGO está vivo aunque AUTH no lo esté (T01/T08).
    return {"status": "ok"}
