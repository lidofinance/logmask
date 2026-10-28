import gc
import io
import json
import logging
import sys
import threading
from collections.abc import Iterator

import pytest

from lido_safe_logging.excepthook import install_excepthook
from lido_safe_logging.formatter import JsonFormatter
from lido_safe_logging.secrets import SecretsMasker
from tests.conftest import RPC, SECRETS, assert_no_secret

MASKER = SecretsMasker(SECRETS)


@pytest.fixture
def unhandled_log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter(MASKER))
    logger = logging.getLogger('unhandled')
    logger.addHandler(handler)
    logger.propagate = False
    try:
        yield stream
    finally:
        logger.removeHandler(handler)
        logger.propagate = True


def raise_connection_error() -> ConnectionError:
    try:
        raise ConnectionError(f'Max retries exceeded with url: {RPC}')
    except ConnectionError as error:
        return error


class RaisesOnDelete:
    def __del__(self) -> None:
        raise ConnectionError(f'Max retries exceeded with url: {RPC}')


def raise_unraisable_connection_error() -> None:
    # An exception in __del__ cannot be raised to anyone: the interpreter hands it to sys.unraisablehook.
    RaisesOnDelete()
    gc.collect()


def raise_keyboard_interrupt_during_error_handling() -> KeyboardInterrupt:
    try:
        try:
            raise ConnectionError(f'Max retries exceeded with url: {RPC}')
        except ConnectionError:
            # Ctrl-C while an error is handled: the traceback prints both, the context carries the URL.
            raise KeyboardInterrupt  # noqa: B904 - the implicit context is the point of this helper
    except KeyboardInterrupt as interrupt:
        return interrupt


def test_unhandled_exception_goes_through_the_masked_logger(restore_logging, unhandled_log):
    install_excepthook(masker=MASKER)
    error = raise_connection_error()

    sys.excepthook(type(error), error, error.__traceback__)

    line = json.loads(unhandled_log.getvalue())
    assert line['levelname'] == 'CRITICAL'
    assert line['name'] == 'unhandled'
    assert line['msg'] == 'Unhandled exception. Shut down.'
    assert 'Traceback' in line['error']
    assert_no_secret(line['error'])


def test_keyboard_interrupt_is_printed_masked_and_not_logged(capsys, restore_logging, unhandled_log):
    install_excepthook(masker=MASKER)
    interrupt = raise_keyboard_interrupt_during_error_handling()

    sys.excepthook(type(interrupt), interrupt, interrupt.__traceback__)

    report = capsys.readouterr().err
    assert 'KeyboardInterrupt' in report
    assert 'ConnectionError' in report
    assert_no_secret(report)
    assert unhandled_log.getvalue() == ''


def test_unhandled_exception_without_a_handler_is_written_masked_to_stderr(capsys, restore_logging):
    logging.getLogger().handlers[:] = []
    install_excepthook(masker=MASKER)
    error = raise_connection_error()

    sys.excepthook(type(error), error, error.__traceback__)

    line = json.loads(capsys.readouterr().err)
    assert line['name'] == 'unhandled'
    assert line['levelname'] == 'CRITICAL'
    assert 'ConnectionError' in line['error']
    assert_no_secret(line['error'])


def test_secrets_added_after_install_are_masked_by_the_hooks(capsys, restore_logging, unhandled_log):
    masker = SecretsMasker({})
    install_excepthook(masker=masker)
    masker.add(SECRETS)
    interrupt = raise_keyboard_interrupt_during_error_handling()

    sys.excepthook(type(interrupt), interrupt, interrupt.__traceback__)

    assert_no_secret(capsys.readouterr().err)


def test_install_excepthook_sets_the_three_hooks(restore_logging, unhandled_log):
    hooks_before = sys.excepthook, threading.excepthook, sys.unraisablehook

    install_excepthook(masker=MASKER)

    assert all(
        hook is not before for hook, before in zip((sys.excepthook, threading.excepthook, sys.unraisablehook), hooks_before, strict=True)
    )

    error = raise_connection_error()
    sys.excepthook(type(error), error, error.__traceback__)
    threading.excepthook(threading.ExceptHookArgs([type(error), error, error.__traceback__, threading.current_thread()]))
    raise_unraisable_connection_error()

    lines = [json.loads(line) for line in unhandled_log.getvalue().splitlines()]
    assert [line['msg'] for line in lines] == [
        'Unhandled exception. Shut down.',
        'Unhandled exception in a thread.',
        'Unraisable exception.',
    ]
    assert all(line['levelname'] == 'CRITICAL' for line in lines)
    assert lines[1]['thread'] == threading.current_thread().name
    assert 'Exception ignored' in lines[2]['context']
    for line in lines:
        assert_no_secret(line['error'])


def test_system_exit_in_a_thread_is_not_logged(restore_logging, unhandled_log):
    install_excepthook(masker=MASKER)

    threading.excepthook(threading.ExceptHookArgs([SystemExit, SystemExit(0), None, threading.current_thread()]))

    assert unhandled_log.getvalue() == ''


class FailingHandler(logging.Handler):
    def handle(self, record: logging.LogRecord) -> bool:
        raise OSError(f'handler failed for {record.getMessage()}')


def test_a_failure_inside_the_hook_prints_one_masked_line_and_does_not_raise(capsys, restore_logging):
    logging.getLogger().handlers[:] = [FailingHandler()]
    install_excepthook(masker=MASKER)
    error = raise_connection_error()

    sys.excepthook(type(error), error, error.__traceback__)

    report = capsys.readouterr().err
    assert '[lido-safe-logging] ConnectionError could not be logged' in report
    assert 'Traceback' not in report
    assert_no_secret(report)


def test_a_foreign_handler_on_the_root_logger_receives_the_traceback_masked(restore_logging):
    stream = io.StringIO()
    logging.getLogger().handlers[:] = [logging.StreamHandler(stream)]
    install_excepthook(masker=MASKER)
    error = raise_connection_error()

    sys.excepthook(type(error), error, error.__traceback__)

    assert 'ConnectionError' in stream.getvalue()
    assert_no_secret(stream.getvalue())
