"""Configuración de STEGO desde el entorno. Falla al arrancar si algo es inválido."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, HttpUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    data_dir: Path = Path("/data")

    jwt_public_key_path: Path = Path("/run/keys/public.pem")
    jwt_issuer: str = Field(default="auth-service", min_length=1)
    jwt_audience: str = Field(default="secure-chat", min_length=1)

    auth_url: HttpUrl = HttpUrl("http://auth:3000")
    auth_timeout_seconds: float = Field(default=3.0, gt=0, le=3.0)
    service_token: str = Field(min_length=32, repr=False)

    max_upload_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    max_pixels: int = Field(default=16_000_000, gt=0)

    # Detector chi-cuadrado (docs/05 §5.3): p > suspicious → sospechoso; p > inconclusive → no_concluyente
    suspicious_threshold: float = Field(default=0.95, gt=0, lt=1)
    inconclusive_threshold: float = Field(default=0.5, gt=0, lt=1)
    min_dimension: int = Field(default=64, ge=8)

    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")

    @model_validator(mode="after")
    def _thresholds_ordered(self) -> "Settings":
        if self.inconclusive_threshold >= self.suspicious_threshold:
            raise ValueError("INCONCLUSIVE_THRESHOLD debe ser menor que SUSPICIOUS_THRESHOLD")
        return self

    @property
    def db_path(self) -> Path:
        return self.data_dir / "stego.db"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"


@lru_cache
def get_settings() -> Settings:
    return Settings()
