import logging
from collections.abc import Mapping
from typing import IO, Any

from .excepthook import install_excepthook
from .formatter import JsonFormatter
from .handler import SafeStreamHandler
from .secrets import SecretsMasker


def setup_logging(
    secrets: Mapping[str, Any] | None = None,
    *,
    level: int | str = logging.INFO,
    stream: IO[str] | None = None,
    excepthook: bool = True,
) -> SecretsMasker:
    """Configure the root logger: JSON lines to the stream (stderr by default), every line masked.

    `secrets` is the mapping of private variables (the PRIVATE_ENV_VARS of a bot). Existing handlers of the root
    logger are replaced. Returns the masker: secrets read later are added with `masker.add()`, and the same masker
    serves a structlog processor or masks text by hand.
    """
    masker = SecretsMasker(secrets or {})

    handler = SafeStreamHandler(stream, masker=masker)
    handler.setFormatter(JsonFormatter(masker))
    logging.basicConfig(level=level, handlers=[handler], force=True)

    if excepthook:
        install_excepthook(masker=masker)
    return masker
