import contextlib
import logging
import sys
from typing import IO

from .secrets import LIBRARY_TAG, SecretsMasker


class SafeStreamHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """A StreamHandler whose error report does not show the record.

    When a handler cannot write a record (a closed stream, a broken pipe), the standard `handleError` prints the raw
    message and the arguments to stderr, without masking. This handler reports the error and where the record came
    from, masked, and nothing else from the record.
    """

    def __init__(self, stream: IO[str] | None = None, *, masker: SecretsMasker):
        super().__init__(stream)
        self._masker = masker

    def handleError(self, record: logging.LogRecord) -> None:
        if not logging.raiseExceptions:
            return
        error = sys.exc_info()[1]
        text = f'--- {LIBRARY_TAG} Logging error: {error!r} (record from {record.name}, {record.pathname}:{record.lineno}) ---\n'
        # stderr may be the stream that failed; there is nowhere else to report.
        with contextlib.suppress(Exception):
            sys.stderr.write(self._masker.mask(text))
