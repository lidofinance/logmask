import logging
from collections.abc import Mapping
from typing import IO, Any

from .excepthook import install_excepthook
from .formatter import JsonFormatter
from .secrets import SecretsMasker, secrets_from_env


def setup_logging(
    secrets: Mapping[str, Any] | None = None,
    *,
    level: int | str = logging.INFO,
    stream: IO[str] | None = None,
    env_heuristic: bool = False,
    excepthook: bool = True,
) -> SecretsMasker:
    """Configure the root logger: JSON lines to the stream (stderr by default), every line masked.

    `secrets` is the explicit mapping of private variables (the PRIVATE_ENV_VARS of a bot). With `env_heuristic` the
    values of every environment variable with SECRET, TOKEN, PASSWORD, PASS, PRIVATE, CREDENTIALS or KEY in its name
    are masked too. Existing handlers of the root logger are replaced. Returns the masker, for a structlog processor or
    for masking text by hand.
    """
    all_secrets: dict[str, Any] = dict(secrets or {})
    if env_heuristic:
        # Under own keys: the raw text from the environment and the parsed explicit value (a list, a stripped text)
        # of the same variable are both masked.
        all_secrets.update({f'env:{name}': value for name, value in secrets_from_env().items()})
    masker = SecretsMasker(all_secrets)

    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter(masker))
    logging.basicConfig(level=level, handlers=[handler], force=True)

    if excepthook:
        install_excepthook()
    return masker
