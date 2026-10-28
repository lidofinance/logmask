import io
import json
import logging
import sys
import threading

from lido_safe_logging.configure import setup_logging
from lido_safe_logging.handler import SafeStreamHandler
from lido_safe_logging.secrets import MASKED_VALUE, SecretsMasker
from tests.conftest import KEY, RPC, SECRETS, assert_no_secret


def test_setup_logging_configures_the_root_logger_with_masked_json(restore_logging):
    stream = io.StringIO()

    masker = setup_logging(SECRETS, stream=stream, excepthook=False)
    logging.getLogger('web3').warning('cannot reach %s', RPC)
    logging.getLogger('bot').info({'msg': 'Bot env variables', 'value': {'KEY': KEY}})

    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [line['name'] for line in lines] == ['web3', 'bot']
    assert lines[0]['msg'] == f'cannot reach {MASKED_VALUE}'
    assert lines[1]['value'] == {'KEY': MASKED_VALUE}
    assert_no_secret(stream.getvalue())
    assert isinstance(masker, SecretsMasker)
    assert KEY in masker.values


def test_setup_logging_replaces_existing_handlers_and_sets_the_level(restore_logging):
    old_stream, stream = io.StringIO(), io.StringIO()
    logging.basicConfig(handlers=[logging.StreamHandler(old_stream)], level=logging.WARNING, force=True)

    setup_logging(SECRETS, level='DEBUG', stream=stream, excepthook=False)
    logging.getLogger('bot').debug('debug line')

    assert logging.getLogger().level == logging.DEBUG
    assert len(logging.getLogger().handlers) == 1
    assert old_stream.getvalue() == ''
    assert json.loads(stream.getvalue())['msg'] == 'debug line'


def test_setup_logging_without_secrets_masks_nothing(restore_logging):
    stream = io.StringIO()

    setup_logging(stream=stream, excepthook=False)
    logging.getLogger('bot').info(RPC)

    assert json.loads(stream.getvalue())['msg'] == RPC


def test_setup_logging_installs_the_exception_hooks_by_default(restore_logging):
    sys_hook_before, thread_hook_before = sys.excepthook, threading.excepthook

    setup_logging(SECRETS, stream=io.StringIO())

    assert sys.excepthook is not sys_hook_before
    assert threading.excepthook is not thread_hook_before


def test_setup_logging_can_skip_the_exception_hooks(restore_logging):
    sys_hook_before, thread_hook_before = sys.excepthook, threading.excepthook

    setup_logging(SECRETS, stream=io.StringIO(), excepthook=False)

    assert sys.excepthook is sys_hook_before
    assert threading.excepthook is thread_hook_before


def test_setup_logging_uses_the_safe_handler_and_secrets_added_later_are_masked(restore_logging):
    stream = io.StringIO()

    masker = setup_logging(stream=stream, excepthook=False)
    logging.getLogger('bot').info('before: late-secret-9')
    masker.add({'LATE_TOKEN': 'late-secret-9'})
    logging.getLogger('bot').info('after: late-secret-9')

    lines = [json.loads(line)['msg'] for line in stream.getvalue().splitlines()]
    assert lines == ['before: late-secret-9', f'after: {MASKED_VALUE}']
    assert isinstance(logging.getLogger().handlers[0], SafeStreamHandler)
