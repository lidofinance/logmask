import io
import json
import logging
import sys
import threading
import uuid
import warnings

import pytest

from logmask.configure import setup_logging
from logmask.handler import SafeStreamHandler
from logmask.secrets import MASKED_VALUE, SecretsMasker
from tests.conftest import KEY, RPC, SECRETS, assert_no_secret


def test_setup_logging_configures_the_root_logger_with_masked_json(restore_logging):
    stream = io.StringIO()

    masker = setup_logging(SECRETS, stream=stream)
    logging.getLogger('web3').warning('cannot reach %s', RPC)
    logging.getLogger('bot').info({'msg': 'Bot env variables', 'value': {'KEY': KEY}})

    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [line['name'] for line in lines] == ['web3', 'bot']
    assert lines[0]['msg'] == f'cannot reach {MASKED_VALUE}'
    assert lines[1]['value'] == {'KEY': MASKED_VALUE}
    assert_no_secret(stream.getvalue())
    assert isinstance(masker, SecretsMasker)


def test_setup_logging_replaces_existing_handlers_and_sets_the_level(restore_logging):
    old_stream, stream = io.StringIO(), io.StringIO()
    logging.basicConfig(handlers=[logging.StreamHandler(old_stream)], level=logging.WARNING, force=True)

    setup_logging(SECRETS, level='DEBUG', stream=stream)
    logging.getLogger('bot').debug('debug line')

    assert logging.getLogger().level == logging.DEBUG
    assert len(logging.getLogger().handlers) == 1
    assert old_stream.getvalue() == ''
    assert json.loads(stream.getvalue())['msg'] == 'debug line'


def test_setup_logging_refuses_a_one_shot_iterator_before_touching_the_root_logger(restore_logging):
    handlers = list(logging.getLogger().handlers)

    with pytest.raises(TypeError, match='one-shot iterator'):
        setup_logging({'K': iter(['secret-key-1'])}, stream=io.StringIO())

    assert logging.getLogger().handlers == handlers


def test_setup_logging_with_an_empty_mapping_masks_nothing_until_add(restore_logging):
    stream = io.StringIO()

    masker = setup_logging({}, stream=stream)
    logging.getLogger('bot').info('before: late-secret-9')
    masker.add({'LATE_TOKEN': 'late-secret-9'})
    logging.getLogger('bot').info('after: late-secret-9')

    lines = [json.loads(line)['msg'] for line in stream.getvalue().splitlines()]
    assert lines == ['before: late-secret-9', f'after: {MASKED_VALUE}']
    assert isinstance(logging.getLogger().handlers[0], SafeStreamHandler)


def test_a_logger_without_handlers_that_does_not_propagate_is_masked_too(restore_logging):
    stream = io.StringIO()
    setup_logging(SECRETS, stream=stream)
    # A fresh name: pytest attaches its capture handlers to every non-propagating logger that exists when a session
    # starts, and mutmut runs several sessions in one process. A logger with handlers never reaches lastResort.
    isolated = logging.getLogger(f'isolated-{uuid.uuid4().hex}')
    isolated.propagate = False

    isolated.warning('cannot reach %s', RPC)
    isolated.info('below the level of the last resort %s', RPC)

    lines = stream.getvalue().splitlines()
    assert [json.loads(line)['msg'] for line in lines] == [f'cannot reach {MASKED_VALUE}']
    assert isinstance(logging.lastResort, SafeStreamHandler)


def test_the_last_resort_handler_reports_a_write_error_masked_and_without_the_record(restore_logging, capsys):
    class Broken(io.StringIO):
        def write(self, text: str) -> int:
            raise OSError('disk full')

    setup_logging(SECRETS, stream=Broken())
    isolated = logging.getLogger(f'isolated-{uuid.uuid4().hex}-{RPC}')
    isolated.propagate = False

    isolated.warning('cannot reach %s', RPC)

    report = capsys.readouterr().err
    assert '[logmask] Logging error: OSError' in report
    assert MASKED_VALUE in report
    assert_no_secret(report)


def test_setup_logging_refuses_a_secret_of_an_unsupported_type(restore_logging):
    with pytest.raises(TypeError, match='object is not supported'):
        setup_logging({'OPAQUE': object()})


def test_setup_logging_installs_the_exception_hooks(restore_logging):
    hooks_before = sys.excepthook, threading.excepthook, sys.unraisablehook

    setup_logging(SECRETS, stream=io.StringIO())

    assert sys.excepthook is not hooks_before[0]
    assert threading.excepthook is not hooks_before[1]
    assert sys.unraisablehook is not hooks_before[2]


def test_setup_logging_routes_warnings_through_the_masked_logger(restore_logging, capsys):
    stream = io.StringIO()
    setup_logging(SECRETS, stream=stream)

    with warnings.catch_warnings():
        warnings.simplefilter('always')
        warnings.warn(f'insecure request to {RPC}', stacklevel=1)

    line = json.loads(stream.getvalue())
    assert line['name'] == 'py.warnings'
    assert 'insecure request' in line['msg']
    assert_no_secret(line['msg'])
    assert capsys.readouterr().err == ''


def test_a_second_setup_logging_keeps_the_secrets_of_the_first(restore_logging):
    first, second = io.StringIO(), io.StringIO()

    setup_logging({'A': 'first-secret-1'}, stream=first)
    setup_logging({'B': 'second-secret-2'}, stream=second)
    logging.getLogger('bot').info('first-secret-1 second-secret-2')

    assert first.getvalue() == ''
    assert json.loads(second.getvalue())['msg'] == f'{MASKED_VALUE} {MASKED_VALUE}'


def test_setup_logging_accepts_a_level_name_in_any_case(restore_logging):
    setup_logging(SECRETS, level='debug', stream=io.StringIO())

    assert logging.getLogger().level == logging.DEBUG


def test_the_masker_and_the_secrets_are_required():
    import logmask
    from logmask import JsonFormatter, SafeStreamHandler, install_excepthook

    for call in (JsonFormatter, SafeStreamHandler, install_excepthook, setup_logging):
        with pytest.raises(TypeError):
            call()  # type: ignore[call-arg]
    assert set(logmask.__all__) == {
        'MASKED_VALUE',
        'JsonFormatter',
        'SafeStreamHandler',
        'SecretsMasker',
        'install_excepthook',
        'mask_secrets_processor',
        'masked_config',
        'setup_logging',
    }
    assert not hasattr(SecretsMasker({'K': KEY}), 'values')


def test_setup_logging_takes_a_numeric_level_and_writes_to_stderr_by_default(restore_logging, capsys):
    setup_logging(SECRETS, level=logging.WARNING)
    logging.getLogger('bot').info('hidden')
    logging.getLogger('bot').warning('shown %s', RPC)

    err = capsys.readouterr().err
    assert logging.getLogger().level == logging.WARNING
    assert 'hidden' not in err
    assert json.loads(err)['msg'] == f'shown {MASKED_VALUE}'


def test_a_warning_with_the_secret_in_its_filename_and_category_is_masked(restore_logging, capsys):
    stream = io.StringIO()
    setup_logging(SECRETS, stream=stream)

    class LeakyWarning(UserWarning):
        pass

    LeakyWarning.__name__ = f'Warning{KEY}'
    with warnings.catch_warnings():
        warnings.simplefilter('always')
        warnings.warn_explicit('insecure request', LeakyWarning, filename=f'/app/{KEY}.py', lineno=1)

    line = json.loads(stream.getvalue())
    assert 'insecure request' in line['msg']
    assert_no_secret(stream.getvalue())
    assert capsys.readouterr().err == ''


class BrokenStream(io.StringIO):
    def write(self, text: str) -> int:
        raise OSError(32, 'Broken pipe')


def test_setup_logging_wires_the_masker_into_the_handler_error_report_and_the_hooks(restore_logging, capsys):
    setup_logging(SECRETS, stream=BrokenStream())
    logging.getLogger('bot').error('key %s', KEY)

    report = capsys.readouterr().err
    assert '[logmask] Logging error' in report
    assert 'Broken pipe' in report
    assert_no_secret(report)

    stream = io.StringIO()
    setup_logging(SECRETS, stream=stream)
    try:
        raise ConnectionError(f'Max retries exceeded with url: {RPC}')
    except ConnectionError as error:
        sys.excepthook(type(error), error, error.__traceback__)

    line = json.loads(stream.getvalue())
    assert line['msg'] == 'Unhandled exception. Shut down.'
    assert 'ConnectionError' in line['error']
    assert_no_secret(stream.getvalue())
