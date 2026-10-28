import io
import json
import logging
import sys
import threading
import warnings

import pytest

from lido_safe_logging.configure import setup_logging
from lido_safe_logging.handler import SafeStreamHandler
from lido_safe_logging.secrets import MASKED_VALUE, SecretsMasker
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


def test_setup_logging_with_an_empty_mapping_masks_nothing_until_add(restore_logging):
    stream = io.StringIO()

    masker = setup_logging({}, stream=stream)
    logging.getLogger('bot').info('before: late-secret-9')
    masker.add({'LATE_TOKEN': 'late-secret-9'})
    logging.getLogger('bot').info('after: late-secret-9')

    lines = [json.loads(line)['msg'] for line in stream.getvalue().splitlines()]
    assert lines == ['before: late-secret-9', f'after: {MASKED_VALUE}']
    assert isinstance(logging.getLogger().handlers[0], SafeStreamHandler)


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
    import lido_safe_logging
    from lido_safe_logging import JsonFormatter, SafeStreamHandler, install_excepthook

    for call in (JsonFormatter, SafeStreamHandler, install_excepthook, setup_logging):
        with pytest.raises(TypeError):
            call()  # type: ignore[call-arg]
    assert set(lido_safe_logging.__all__) == {
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
