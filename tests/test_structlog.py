import io
import json

import pytest

from logmask.secrets import MASKED_VALUE, SecretsMasker
from logmask.structlog_processor import mask_secrets_processor
from tests.conftest import KEY, RPC, SECRETS, assert_no_secret

structlog = pytest.importorskip('structlog')


def make_logger(stream: io.StringIO, processors: list):
    return structlog.wrap_logger(structlog.PrintLogger(file=stream), processors=processors)


def test_processor_after_the_renderer_masks_the_rendered_line():
    stream = io.StringIO()
    log = make_logger(
        stream, [structlog.processors.add_log_level, structlog.processors.JSONRenderer(), mask_secrets_processor(SecretsMasker(SECRETS))]
    )

    log.info('Connect', url=RPC, key=KEY, quoted='pa"ss', error=ValueError(f'cannot reach {RPC}'), **{KEY: 'key as a key'})

    line = json.loads(stream.getvalue())
    assert line['event'] == 'Connect'
    assert line['level'] == 'info'
    assert line['url'] == MASKED_VALUE
    assert line['key'] == MASKED_VALUE
    assert line[MASKED_VALUE] == 'key as a key'
    assert_no_secret(stream.getvalue())


def test_processor_before_the_renderer_raises_at_the_first_log_call():
    log = make_logger(io.StringIO(), [mask_secrets_processor(SecretsMasker(SECRETS)), structlog.processors.JSONRenderer()])

    with pytest.raises(TypeError, match='must be the last processor'):
        log.info('Connect', url=RPC)


def test_processor_masks_bytes_from_a_bytes_renderer():
    processor = mask_secrets_processor(SecretsMasker(SECRETS))

    assert processor(None, 'info', f'key {KEY}'.encode()) == f'key {MASKED_VALUE}'.encode()
    assert processor(None, 'info', b'raw \xff byte') == b'raw \xff byte'
    assert (
        processor(None, 'info', f'key {KEY} \xff'.encode('utf-8', errors='surrogateescape') + b'\xff')
        == f'key {MASKED_VALUE} \xff'.encode() + b'\xff'
    )


def test_a_real_structlog_chain_masks_a_traceback_with_a_url():
    stream = io.StringIO()
    log = make_logger(
        stream,
        [
            structlog.processors.add_log_level,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
            mask_secrets_processor(SecretsMasker(SECRETS)),
        ],
    )

    try:
        raise ConnectionError(f'Max retries exceeded with url: {RPC}')
    except ConnectionError:
        log.exception('request failed')

    line = json.loads(stream.getvalue())
    assert 'Traceback' in line['exception']
    assert 'ConnectionError' in line['exception']
    assert_no_secret(stream.getvalue())


def test_processor_masks_a_bytes_event_in_upper_case():
    processor = mask_secrets_processor(SecretsMasker(SECRETS))

    assert processor(None, 'info', f'KEY {KEY.upper()}'.encode()) == f'KEY {MASKED_VALUE}'.encode()
