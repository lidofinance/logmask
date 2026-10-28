import dataclasses
import json
import logging
from collections.abc import Iterator, Mapping
from typing import Any

from .secrets import SecretsMasker


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


class JsonFormatter(logging.Formatter):
    """One JSON object per line with the fields the Lido bots use; every line goes through the masker."""

    def __init__(self, masker: SecretsMasker | None = None):
        super().__init__()
        self._masker = masker

    def format(self, record: logging.LogRecord) -> str:
        try:
            text = json.dumps(self._line(record), default=json_default)
        except Exception as error:
            # A record that cannot be formatted must not reach stderr through Handler.handleError, which prints the raw
            # message and arguments without masking. The fallback line keeps the text, masked like every other line.
            text = json.dumps(self._fallback_line(record, error), default=str)
        # Secrets are hidden in every log line, including messages from third-party libraries.
        return self._masker.mask(text) if self._masker else text

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
        line = {**self._base(record), **message}
        if record.exc_info:
            line['exc_info'] = self.formatException(record.exc_info)
        return line

    def _fallback_line(self, record: logging.LogRecord, error: Exception) -> dict[str, Any]:
        line = {**self._base(record), 'msg': str(record.msg), 'error': f'Log record could not be formatted: {error!r}'}
        if record.args:
            line['args'] = repr(record.args)
        return line
