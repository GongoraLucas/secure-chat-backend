"""Logging a stdout. Nunca registrar tokens, claves ni secretos (ver AGENTS.md)."""

import logging


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        force=True,
    )
