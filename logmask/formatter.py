import dataclasses
import json
import logging
from collections.abc import Callable, Iterator, Mapping
from typing import Any

from .secrets import LIBRARY_TAG, SecretsMasker

UNPRINTABLE = '<unprintable>'


def json_default(value: object) -> Any:
    """Values json.dumps does not know: bytes as 0x-hex, dataclasses as dicts, sets and iterators as lists, the rest as text."""
    if isinstance(value, bytes | bytearray):
        return '0x' + bytes(value).hex()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, set | frozenset | Iterator):
        return list(value)
    return str(value)


def _safe(convert: Callable[[Any], str], value: Any) -> str:
    try:
        return convert(value)
    except Exception:  # noqa: BLE001 - a __str__ or __repr__ that raises must not break the fallback line
        return UNPRINTABLE


class JsonFormatter(logging.Formatter):
    """One JSON object per line with a fixed set of record fields; every line goes through the masker.

    `format()` never raises: a record that cannot be formatted becomes a line with an `error` field. Otherwise the
    handler would report the error with the raw message and arguments, without masking.
    """

    def __init__(self, masker: SecretsMasker):
        super().__init__()
        self._masker = masker

    def format(self, record: logging.LogRecord) -> str:
        try:
            text = json.dumps(self._line(record), default=json_default)
        except Exception as error:  # noqa: BLE001 - any formatting error must become a masked line, see the class docstring
            text = json.dumps(self._fallback_line(record, error))
        # Secrets are hidden in every log line, including messages from third-party libraries.
        masked = self._masker.mask(text)
        try:
            json.loads(masked)
        except ValueError:
            # A secret made of JSON syntax (a quote, a brace, `true`) was replaced outside the strings. Mask the
            # strings one by one instead; the JSON-escaped forms are then not needed, and the syntax stays.
            masked = json.dumps(self._mask_leaves(json.loads(text)))
        return masked

    def _mask_leaves(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._masker.mask(value)
        if isinstance(value, dict):
            return {self._masker.mask(key): self._mask_leaves(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._mask_leaves(item) for item in value]
        return value

    def _base(self, record: logging.LogRecord) -> dict[str, Any]:
        return {
            'name': record.name,
            'levelname': record.levelname,
            'funcName': record.funcName,
            'lineno': record.lineno,
            'module': record.module,
            'pathname': record.pathname,
            'timestamp': int(record.created),
        }

    def _line(self, record: logging.LogRecord) -> dict[str, Any]:
        message = record.msg if isinstance(record.msg, dict) else {'msg': record.getMessage()}
        line = self._base(record)
        for key, value in message.items():
            # The record fields win: a message key `name` or `timestamp` would break every query on them.
            line[f'msg_{key}' if key in line else key] = value
        if record.exc_info:
            line['exc_info'] = self.formatException(record.exc_info)
        return line

    def _fallback_line(self, record: logging.LogRecord, error: Exception) -> dict[str, Any]:
        line = {
            **self._base(record),
            'msg': _safe(str, record.msg),
            'error': f'{LIBRARY_TAG} Log record could not be formatted: {_safe(repr, error)}',
        }
        if record.args:
            line['args'] = _safe(repr, record.args)
        return line
