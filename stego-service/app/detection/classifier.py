"""Clasificación del resultado del detector y política asociada (§7, docs/05 §5.3).

`error`/`rechazo` no sale de aquí: lo asigna el endpoint cuando la imagen no es válida.
`sin_indicios` no lleva acción: el archivo se elimina tras el análisis.
"""

from typing import Any

TECHNIQUE = "lsb_chi_square"

LIMITATIONS = (
    "Resultado indicativo, no concluyente: 'sospechoso' es un indicio estadístico, no una prueba. "
    "El ataque chi-cuadrado detecta reemplazo LSB secuencial con tasas medias o altas; "
    "pierde sensibilidad con incrustación dispersa o de baja tasa, no detecta LSB matching (±1), "
    "técnicas en frecuencia ni datos en metadatos; imágenes planas, con paleta o pequeñas pueden "
    "dar falsos positivos o resultados no concluyentes. 'sin_indicios' no garantiza ausencia de datos ocultos."
)


def classify(
    indicators: dict[str, Any],
    suspicious_threshold: float,
    inconclusive_threshold: float,
    min_dimension: int,
) -> tuple[str, str | None]:
    """Devuelve (status, action)."""
    if min(indicators["width"], indicators["height"]) < min_dimension:
        return "no_concluyente", "advertencia"
    p_first = indicators["p_value_first_max"]
    if p_first is None:  # sin pares válidos en la primera porción de ningún canal
        return "no_concluyente", "advertencia"
    if p_first > suspicious_threshold:
        return "sospechoso", "cuarentena"
    if p_first > inconclusive_threshold:
        return "no_concluyente", "advertencia"
    return "sin_indicios", None
