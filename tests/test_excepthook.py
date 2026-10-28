import gc
import io
import json
import logging
import sys
import threading
from collections.abc import Iterator

import pytest

from logmask.excepthook import install_excepthook
from logmask.formatter import JsonFormatter
from logmask.secrets import MASKED_VALUE, SecretsMasker
from tests.conftest import RPC, RPC_2, SECRETS, assert_no_secret

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
    assert '[logmask] ConnectionError could not be logged' in report
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


def test_thread_hook_without_an_exception_value_and_with_a_secret_in_the_thread_name(restore_logging, unhandled_log):
    install_excepthook(masker=MASKER)
    thread = threading.Thread(name=f'worker-{RPC}', target=lambda: None)

    threading.excepthook(threading.ExceptHookArgs([ConnectionError, None, None, thread]))

    line = json.loads(unhandled_log.getvalue())
    assert line['error'].startswith('ConnectionError')
    assert line['thread'].startswith('worker-')
    assert_no_secret(json.dumps(line))


def test_keyboard_interrupt_notes_and_exception_groups_are_masked(capsys, restore_logging, unhandled_log):
    install_excepthook(masker=MASKER)
    interrupt = KeyboardInterrupt()
    interrupt.add_note(f'while connecting to {RPC}')
    group = ExceptionGroup('providers failed', [ConnectionError(f'cannot reach {RPC}'), TimeoutError(RPC_2)])

    sys.excepthook(type(interrupt), interrupt, None)
    sys.excepthook(type(group), group, None)

    report = capsys.readouterr().err
    assert 'while connecting to' in report
    assert_no_secret(report)
    line = json.loads(unhandled_log.getvalue())
    assert 'providers failed' in line['error']
    assert_no_secret(line['error'])


def test_an_exception_whose_str_raises_is_still_reported_masked(capsys, restore_logging, unhandled_log):
    class Broken(Exception):
        def __str__(self) -> str:
            raise RuntimeError(f'str failed for {RPC}')

    install_excepthook(masker=MASKER)

    sys.excepthook(Broken, Broken(), None)

    output = capsys.readouterr().err + unhandled_log.getvalue()
    assert 'Broken' in output
    assert_no_secret(output)


def test_keyboard_interrupt_with_a_closed_stderr_does_not_raise(restore_logging, monkeypatch):
    class Closed(io.StringIO):
        def write(self, text: str) -> int:
            raise ValueError('I/O operation on closed file')

    monkeypatch.setattr('sys.stderr', Closed())
    install_excepthook(masker=MASKER)
    interrupt = raise_keyboard_interrupt_during_error_handling()

    sys.excepthook(type(interrupt), interrupt, interrupt.__traceback__)


def test_unraisable_hook_keeps_the_interpreter_message_when_it_is_given(restore_logging, unhandled_log):
    from types import SimpleNamespace
    from typing import Any, cast

    install_excepthook(masker=MASKER)
    error = raise_connection_error()
    args = SimpleNamespace(
        exc_type=type(error), exc_value=error, exc_traceback=error.__traceback__, err_msg=f'Exception ignored on {RPC}', object=None
    )

    sys.unraisablehook(cast(Any, args))

    line = json.loads(unhandled_log.getvalue())
    assert line['context'] == f'Exception ignored on {MASKED_VALUE}'
    assert_no_secret(line['error'])
