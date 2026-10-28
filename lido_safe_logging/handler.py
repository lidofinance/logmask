import contextlib
import logging
import sys
from typing import IO

from .secrets import SecretsMasker


class SafeStreamHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """A StreamHandler whose error report does not show the record.

    When a handler cannot write a record (a closed stream, a broken pipe), the standard `handleError` prints the raw
    message and the arguments to stderr, without masking. This handler reports the error and where the record came
    from, nothing from the record itself.
    """

    def __init__(self, stream: IO[str] | None = None, *, masker: SecretsMasker | None = None):
        super().__init__(stream)
        self._masker = masker

    def handleError(self, record: logging.LogRecord) -> None:
        if not logging.raiseExceptions:
            return
        error = sys.exc_info()[1]
        text = f'--- Logging error: {error!r} (record from {record.name}, {record.pathname}:{record.lineno}) ---\n'
        if self._masker is not None:
            text = self._masker.mask(text)
        # stderr may be the stream that failed; there is nowhere else to report.
        with contextlib.suppress(Exception):
            sys.stderr.write(text)
