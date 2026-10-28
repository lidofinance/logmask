import io
import json

import pytest

from lido_safe_logging.secrets import MASKED_VALUE, SecretsMasker
from lido_safe_logging.structlog_processor import mask_secrets_processor
from tests.conftest import KEY, RPC, RPC_2, SECRETS, assert_no_secret

structlog = pytest.importorskip('structlog')


def make_logger(stream: io.StringIO, processors: list):
    return structlog.wrap_logger(structlog.PrintLogger(file=stream), processors=processors)


def test_processor_after_the_renderer_masks_the_rendered_line():
    stream = io.StringIO()
    log = make_logger(
        stream, [structlog.processors.add_log_level, structlog.processors.JSONRenderer(), mask_secrets_processor(SecretsMasker(SECRETS))]
    )

    log.info('Connect', url=RPC, key=KEY, quoted='pa"ss')

    line = json.loads(stream.getvalue())
    assert line['event'] == 'Connect'
    assert line['level'] == 'info'
    assert line['url'] == MASKED_VALUE
    assert line['key'] == MASKED_VALUE
    assert_no_secret(stream.getvalue())


def test_processor_before_the_renderer_masks_nested_values():
    stream = io.StringIO()
    log = make_logger(stream, [mask_secrets_processor(SecretsMasker(SECRETS)), structlog.processors.JSONRenderer()])

    log.info(f'Failed to reach {RPC}', urls=[RPC, RPC_2], nested={'key': KEY, 'port': 8545}, pair=(KEY, 1))

    line = json.loads(stream.getvalue())
    assert line['event'] == f'Failed to reach {MASKED_VALUE}'
    assert line['urls'] == [MASKED_VALUE, MASKED_VALUE]
    assert line['nested'] == {'key': MASKED_VALUE, 'port': 8545}
    assert line['pair'] == [MASKED_VALUE, 1]
    assert_no_secret(stream.getvalue())


def test_processor_before_the_renderer_keeps_the_container_types():
    processor = mask_secrets_processor(SecretsMasker(SECRETS))

    event = processor(None, 'info', {'set': {KEY, 'x'}, 'frozen': frozenset({RPC}), 'pair': (KEY, 1), 'list': [KEY]})

    assert event == {'set': {MASKED_VALUE, 'x'}, 'frozen': frozenset({MASKED_VALUE}), 'pair': (MASKED_VALUE, 1), 'list': [MASKED_VALUE]}
    assert isinstance(event['frozen'], frozenset)
    assert isinstance(event['pair'], tuple)


def test_processor_handles_bytes_and_leaves_other_types():
    processor = mask_secrets_processor(SecretsMasker(SECRETS))

    assert processor(None, 'info', f'key {KEY}'.encode()) == f'key {MASKED_VALUE}'.encode()
    assert processor(None, 'info', b'raw \xff byte') == b'raw \xff byte'
    assert (
        processor(None, 'info', f'key {KEY} \xff'.encode('utf-8', errors='surrogateescape') + b'\xff')
        == f'key {MASKED_VALUE} \xff'.encode() + b'\xff'
    )
    assert processor(None, 'info', 42) == 42
    assert processor(None, 'info', None) is None
