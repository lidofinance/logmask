import contextlib
import logging
import sys
import threading
import traceback
from types import TracebackType

from .formatter import JsonFormatter
from .handler import SafeStreamHandler
from .secrets import SecretsMasker

LOGGER_NAME = 'unhandled'


def _format(exc_type: type[BaseException], exc_value: BaseException | None, exc_traceback: TracebackType | None) -> str:
    if exc_value is None:
        return f'{exc_type.__name__}\n' + ''.join(traceback.format_tb(exc_traceback))
    return ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))


def _log_exception(
    exc_type: type[BaseException],
    exc_value: BaseException | None,
    exc_traceback: TracebackType | None,
    *,
    masker: SecretsMasker,
    message: str,
    thread_name: str | None = None,
    context: str | None = None,
) -> None:
    """Send the traceback through the logger, so that it is formatted and masked too.

    A stop by Ctrl-C is not an error: for KeyboardInterrupt the traceback goes to stderr as plain text, like the
    default hook prints it, but masked. The chained exceptions in it (`__context__`) may carry a URL or a key.
    The traceback text is masked before it enters the record: a handler that is not the masking one (added by a
    library after the setup) would otherwise print it raw. When the logger has no handler, the line is written to
    stderr by this module, masked, instead of the raw record that `logging.lastResort` would print. When anything in
    here fails, one masked line goes to stderr: the interpreter would otherwise print the hook's error together with
    the original traceback, unmasked.
    """
    try:
        error = masker.mask(_format(exc_type, exc_value, exc_traceback))
        if issubclass(exc_type, KeyboardInterrupt):
            sys.stderr.write(error)
            return

        record_message: dict[str, object] = {'msg': message, 'error': error}
        if thread_name is not None:
            record_message['thread'] = masker.mask(thread_name)
        if context is not None:
            record_message['context'] = masker.mask(context)

        logger = logging.getLogger(LOGGER_NAME)
        if logger.hasHandlers():
            logger.critical(record_message)
            return
        record = logger.makeRecord(logger.name, logging.CRITICAL, '(unknown file)', 0, record_message, (), None)
        handler = SafeStreamHandler(sys.stderr, masker=masker)
        handler.setFormatter(JsonFormatter(masker))
        handler.handle(record)
    except BaseException as failure:  # noqa: BLE001 - the hook must not raise, see the docstring
        with contextlib.suppress(Exception):
            sys.stderr.write(masker.mask(f'--- {exc_type.__name__} could not be logged: {type(failure).__name__} ---\n'))


def install_excepthook(*, masker: SecretsMasker) -> None:
    """Route the unhandled exceptions of the main thread, of the other threads, and the unraisable ones through the logger.

    `masker` covers the output that cannot go through the logger: a KeyboardInterrupt traceback, any exception when
    no handler is configured, and a failure of the hook itself. The logger's own handler masks the rest.
    """

    def hook(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
        _log_exception(exc_type, exc_value, exc_traceback, masker=masker, message='Unhandled exception. Shut down.')

    def thread_hook(args: threading.ExceptHookArgs) -> None:
        if issubclass(args.exc_type, SystemExit):
            # The default thread hook ignores sys.exit() in a thread; so do we.
            return
        thread_name = args.thread.name if args.thread is not None else None
        _log_exception(
            args.exc_type,
            args.exc_value,
            args.exc_traceback,
            masker=masker,
            message='Unhandled exception in a thread.',
            thread_name=thread_name,
        )

    def unraisable_hook(args: sys.UnraisableHookArgs) -> None:
        # An exception in __del__, in a weakref callback or in a GC hook: the default hook prints it to stderr.
        # err_msg says where ("Exception ignored in: ..."); the object itself is not logged, its repr is unknown text.
        _log_exception(
            args.exc_type, args.exc_value, args.exc_traceback, masker=masker, message='Unraisable exception.', context=args.err_msg
        )

    sys.excepthook = hook
    threading.excepthook = thread_hook
    sys.unraisablehook = unraisable_hook
