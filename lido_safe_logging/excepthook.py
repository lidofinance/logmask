import logging
import sys
import threading
import traceback
from types import TracebackType

DEFAULT_LOGGER_NAME = 'unhandled'


def log_unhandled_exception(
    exc_type: type[BaseException],
    exc_value: BaseException | None,
    exc_traceback: TracebackType | None,
    *,
    logger_name: str = DEFAULT_LOGGER_NAME,
    thread_name: str | None = None,
) -> None:
    """Send the traceback of an unhandled exception through the logger, so that it is formatted and masked too.

    KeyboardInterrupt goes to the default hook: a stop by Ctrl-C is not an error.
    """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value or exc_type(), exc_traceback)
        return

    if exc_value is None:
        error = f'{exc_type.__name__}\n' + ''.join(traceback.format_tb(exc_traceback))
    else:
        error = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))

    message: dict[str, object] = {'msg': 'Unhandled exception. Shut down.', 'error': error}
    if thread_name is not None:
        message['thread'] = thread_name
    logging.getLogger(logger_name).critical(message)


def install_excepthook(*, logger_name: str = DEFAULT_LOGGER_NAME, threads: bool = True) -> None:
    """Route the unhandled exceptions of the main thread, and of the other threads, through the logger."""

    def hook(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
        log_unhandled_exception(exc_type, exc_value, exc_traceback, logger_name=logger_name)

    def thread_hook(args: threading.ExceptHookArgs) -> None:
        if issubclass(args.exc_type, SystemExit):
            # The default thread hook ignores sys.exit() in a thread; so do we.
            return
        thread_name = args.thread.name if args.thread is not None else None
        log_unhandled_exception(args.exc_type, args.exc_value, args.exc_traceback, logger_name=logger_name, thread_name=thread_name)

    sys.excepthook = hook
    if threads:
        threading.excepthook = thread_hook
