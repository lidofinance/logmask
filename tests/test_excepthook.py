import io
import json
import logging
import sys
import threading
from collections.abc import Iterator

import pytest

from lido_safe_logging.excepthook import install_excepthook, log_unhandled_exception
from lido_safe_logging.formatter import JsonFormatter
from lido_safe_logging.secrets import SecretsMasker
from tests.conftest import RPC, SECRETS, assert_no_secret


@pytest.fixture
def unhandled_log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter(SecretsMasker(SECRETS)))
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


def test_unhandled_exception_goes_through_the_masked_logger(unhandled_log):
    error = raise_connection_error()

    log_unhandled_exception(type(error), error, error.__traceback__)

    line = json.loads(unhandled_log.getvalue())
    assert line['levelname'] == 'CRITICAL'
    assert line['name'] == 'unhandled'
    assert line['msg'] == 'Unhandled exception. Shut down.'
    assert 'Traceback' in line['error']
    assert_no_secret(line['error'])


def test_logger_name_is_configurable():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger('my-app')
    logger.addHandler(handler)
    logger.propagate = False
    try:
        log_unhandled_exception(ValueError, ValueError('x'), None, logger_name='my-app')
    finally:
        logger.removeHandler(handler)
        logger.propagate = True

    assert json.loads(stream.getvalue())['name'] == 'my-app'


def raise_keyboard_interrupt_during_error_handling() -> KeyboardInterrupt:
    try:
        try:
            raise ConnectionError(f'Max retries exceeded with url: {RPC}')
        except ConnectionError:
            # Ctrl-C while an error is handled: the traceback prints both, the context carries the URL.
            raise KeyboardInterrupt  # noqa: B904 - the implicit context is the point of this helper
    except KeyboardInterrupt as interrupt:
        return interrupt


def test_keyboard_interrupt_is_printed_masked_and_not_logged(capsys, unhandled_log):
    interrupt = raise_keyboard_interrupt_during_error_handling()

    log_unhandled_exception(type(interrupt), interrupt, interrupt.__traceback__, masker=SecretsMasker(SECRETS))

    report = capsys.readouterr().err
    assert 'KeyboardInterrupt' in report
    assert 'ConnectionError' in report
    assert_no_secret(report)
    assert unhandled_log.getvalue() == ''


def test_keyboard_interrupt_without_a_masker_is_printed_as_is(capsys, unhandled_log):
    log_unhandled_exception(KeyboardInterrupt, KeyboardInterrupt(), None)

    assert capsys.readouterr().err.rstrip() == 'KeyboardInterrupt'
    assert unhandled_log.getvalue() == ''


def test_unhandled_exception_without_a_handler_is_written_masked_to_stderr(capsys, restore_logging):
    logging.getLogger().handlers[:] = []
    error = raise_connection_error()

    log_unhandled_exception(type(error), error, error.__traceback__, logger_name='no-handler', masker=SecretsMasker(SECRETS))

    line = json.loads(capsys.readouterr().err)
    assert line['name'] == 'no-handler'
    assert line['levelname'] == 'CRITICAL'
    assert 'ConnectionError' in line['error']
    assert_no_secret(line['error'])


def test_install_excepthook_passes_the_masker_to_the_hooks(capsys, restore_logging, unhandled_log):
    masker = SecretsMasker({})
    install_excepthook(masker=masker)
    masker.add(SECRETS)
    interrupt = raise_keyboard_interrupt_during_error_handling()

    sys.excepthook(type(interrupt), interrupt, interrupt.__traceback__)

    assert_no_secret(capsys.readouterr().err)


def test_install_excepthook_sets_sys_and_threading_hooks(restore_logging, unhandled_log):
    sys_hook_before, thread_hook_before = sys.excepthook, threading.excepthook

    install_excepthook()

    assert sys.excepthook is not sys_hook_before
    assert threading.excepthook is not thread_hook_before

    error = raise_connection_error()
    sys.excepthook(type(error), error, error.__traceback__)
    threading.excepthook(threading.ExceptHookArgs([type(error), error, error.__traceback__, threading.current_thread()]))

    lines = [json.loads(line) for line in unhandled_log.getvalue().splitlines()]
    assert len(lines) == 2
    assert all(line['levelname'] == 'CRITICAL' for line in lines)
    assert lines[1]['thread'] == threading.current_thread().name
    for line in lines:
        assert_no_secret(line['error'])


def test_install_excepthook_can_leave_threads_alone(restore_logging):
    # pytest installs its own thread hook, so the check is "unchanged", not "default".
    sys_hook_before, thread_hook_before = sys.excepthook, threading.excepthook

    install_excepthook(threads=False)

    assert sys.excepthook is not sys_hook_before
    assert threading.excepthook is thread_hook_before


def test_system_exit_in_a_thread_is_not_logged(restore_logging, unhandled_log):
    install_excepthook()

    threading.excepthook(threading.ExceptHookArgs([SystemExit, SystemExit(0), None, threading.current_thread()]))

    assert unhandled_log.getvalue() == ''
