import logging
import sys
import threading
import traceback
from types import TracebackType

from .formatter import JsonFormatter
from .handler import SafeStreamHandler
from .secrets import SecretsMasker

DEFAULT_LOGGER_NAME = 'unhandled'


def _format(exc_type: type[BaseException], exc_value: BaseException | None, exc_traceback: TracebackType | None) -> str:
    if exc_value is None:
        return f'{exc_type.__name__}\n' + ''.join(traceback.format_tb(exc_traceback))
    return ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))


def log_unhandled_exception(
    exc_type: type[BaseException],
    exc_value: BaseException | None,
    exc_traceback: TracebackType | None,
    *,
    logger_name: str = DEFAULT_LOGGER_NAME,
    thread_name: str | None = None,
    masker: SecretsMasker | None = None,
) -> None:
    """Send the traceback of an unhandled exception through the logger, so that it is formatted and masked too.

    A stop by Ctrl-C is not an error: for KeyboardInterrupt the traceback goes to stderr as plain text, like the
    default hook prints it, but masked. The chained exceptions in it (`__context__`) may carry a URL or a key.
    When the logger has no handler, the line is written to stderr by this module, masked, instead of the raw record
    that `logging.lastResort` would print.
    """
    error = _format(exc_type, exc_value, exc_traceback)
    if issubclass(exc_type, KeyboardInterrupt):
        sys.stderr.write(masker.mask(error) if masker is not None else error)
        return

    message: dict[str, object] = {'msg': 'Unhandled exception. Shut down.', 'error': error}
    if thread_name is not None:
        message['thread'] = thread_name

    logger = logging.getLogger(logger_name)
    if logger.hasHandlers():
        logger.critical(message)
        return
    record = logger.makeRecord(logger.name, logging.CRITICAL, '(unknown file)', 0, message, (), None)
    handler = SafeStreamHandler(sys.stderr, masker=masker)
    handler.setFormatter(JsonFormatter(masker))
    handler.handle(record)


def install_excepthook(*, logger_name: str = DEFAULT_LOGGER_NAME, threads: bool = True, masker: SecretsMasker | None = None) -> None:
    """Route the unhandled exceptions of the main thread, and of the other threads, through the logger.

    `masker` is used for the output that cannot go through the logger: a KeyboardInterrupt traceback, or any exception
    when no handler is configured. The logger's own handler masks the rest.
    """

    def hook(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
        log_unhandled_exception(exc_type, exc_value, exc_traceback, logger_name=logger_name, masker=masker)

    def thread_hook(args: threading.ExceptHookArgs) -> None:
        if issubclass(args.exc_type, SystemExit):
            # The default thread hook ignores sys.exit() in a thread; so do we.
            return
        thread_name = args.thread.name if args.thread is not None else None
        log_unhandled_exception(
            args.exc_type, args.exc_value, args.exc_traceback, logger_name=logger_name, thread_name=thread_name, masker=masker
        )

    sys.excepthook = hook
    if threads:
        threading.excepthook = thread_hook
