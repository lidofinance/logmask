from collections.abc import Callable
from typing import Any

from .secrets import SecretsMasker

Processor = Callable[[Any, str, Any], Any]


def mask_secrets_processor(masker: SecretsMasker) -> Processor:
    """A structlog processor that masks the rendered line.

    Put it last, after the renderer: it then masks the whole line, keys and JSON-escaped forms included. It accepts
    the output of a renderer, a `str` or `bytes`, and raises TypeError for anything else (an event dict): placed
    before the renderer it could not mask the objects inside the event, and a silent partial masking is worse than a
    failure at the first log call. The module does not import structlog: the processor is a plain function with the
    `(logger, method_name, event_dict)` contract, the service brings its own structlog.
    """

    def processor(logger: Any, method_name: str, event: Any) -> Any:
        if isinstance(event, str):
            return masker.mask(event)
        if isinstance(event, bytes):
            text = event.decode('utf-8', errors='surrogateescape')
            return masker.mask(text).encode('utf-8', errors='surrogateescape')
        raise TypeError(f'mask_secrets_processor must be the last processor, after the renderer; got {type(event).__name__}')

    return processor
