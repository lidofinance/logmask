import logging
import threading
from collections.abc import Mapping
from typing import IO

from .excepthook import install_excepthook
from .formatter import JsonFormatter
from .handler import SafeStreamHandler
from .secrets import SecretsMasker

# One masker per process: a second call adds its secrets to the same masker, so the secrets of the first call stay
# masked after a library or a test configures logging again.
_masker: SecretsMasker | None = None
_lock = threading.Lock()


def setup_logging(secrets: Mapping[str, object], *, level: int | str = logging.INFO, stream: IO[str] | None = None) -> SecretsMasker:
    """Configure the root logger: JSON lines to the stream (stderr by default), every line masked.

    `secrets` is the mapping of private variables (the PRIVATE_ENV_VARS of a bot); a service that reads its secrets
    later passes `{}` and calls `add()` on the returned masker. Existing handlers of the root logger are replaced,
    warnings are routed through the logger, and the exception hooks of the main thread, of the other threads and of
    the unraisable exceptions are installed, so every traceback is masked too. The same masker serves a structlog
    processor or masks text by hand. `level` is a logging level or its name in any case.
    """
    global _masker
    with _lock:
        if _masker is None:
            _masker = SecretsMasker(secrets)
        else:
            _masker.add(secrets)
        masker = _masker
    if isinstance(level, str):
        level = level.upper()

    handler = SafeStreamHandler(stream, masker=masker)
    handler.setFormatter(JsonFormatter(masker))
    logging.basicConfig(level=level, handlers=[handler], force=True)
    # warnings.warn() prints to stderr by default; a warning text may carry a URL.
    logging.captureWarnings(True)

    install_excepthook(masker=masker)
    return masker
