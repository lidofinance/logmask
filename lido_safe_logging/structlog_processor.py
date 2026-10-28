from collections.abc import Callable, Mapping
from typing import Any

from .secrets import SecretsMasker

Processor = Callable[[Any, str, Any], Any]


def mask_secrets_processor(masker: SecretsMasker) -> Processor:
    """A structlog processor that masks the event.

    Put it last, after the renderer: it then masks the rendered line, keys and JSON-escaped forms included.
    Before the renderer it masks the string values of the event dict, nested lists and dicts too.
    The module does not import structlog; install the `structlog` extra to pin a tested version.
    """

    def processor(logger: Any, method_name: str, event: Any) -> Any:
        return _mask(masker, event)

    return processor


def _mask(masker: SecretsMasker, value: Any) -> Any:
    if isinstance(value, str):
        return masker.mask(value)
    if isinstance(value, bytes):
        text = value.decode('utf-8', errors='surrogateescape')
        masked = masker.mask(text)
        return value if masked == text else masked.encode('utf-8', errors='surrogateescape')
    if isinstance(value, Mapping):
        return {key: _mask(masker, item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_mask(masker, item) for item in value]
    return value
