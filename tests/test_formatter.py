import dataclasses
import json
import logging
from decimal import Decimal

from lido_safe_logging.formatter import JsonFormatter, json_default
from lido_safe_logging.secrets import MASKED_VALUE, SecretsMasker
from tests.conftest import KEY, RPC, SECRETS, assert_no_secret, make_record


@dataclasses.dataclass
class Report:
    ref_slot: int
    root: bytes


def test_json_formatter_masks_secrets_in_dict_and_string_messages():
    formatter = JsonFormatter(SecretsMasker(SECRETS))

    for msg in ({'msg': 'Failed.', 'error': f'cannot reach {RPC}'}, f'Failed to reach {RPC}'):
        line = formatter.format(make_record(msg))

        assert_no_secret(line)
        assert MASKED_VALUE in line
        json.loads(line)


def test_json_formatter_masks_json_escaped_secret():
    secret = 'pass"word/with\\quote\nand newline'
    formatter = JsonFormatter(SecretsMasker({'TOKEN': secret}))

    line = formatter.format(make_record({'msg': secret}))

    assert 'word/with' not in line
    assert json.loads(line)['msg'] == MASKED_VALUE


def test_json_formatter_without_masker_keeps_the_text():
    line = JsonFormatter().format(make_record({'msg': RPC}))

    assert json.loads(line)['msg'] == RPC


def test_json_formatter_field_names_match_the_bots():
    record = make_record('hello %s', logging.WARNING)
    record.args = ('world',)

    line = json.loads(JsonFormatter().format(record))

    assert list(line) == ['name', 'levelname', 'funcName', 'lineno', 'module', 'pathname', 'timestamp', 'msg']
    assert line['name'] == 'test'
    assert line['levelname'] == 'WARNING'
    assert line['lineno'] == 1
    assert line['module'] == 'conftest'
    assert line['msg'] == 'hello world'


def test_json_formatter_timestamp_is_the_record_time_in_seconds():
    record = make_record('x')
    record.created = 1761600000.75

    assert json.loads(JsonFormatter().format(record))['timestamp'] == 1761600000


def test_json_formatter_keeps_message_keys():
    line = json.loads(JsonFormatter().format(make_record({'msg': 'Report', 'value': 10, 'slot': 42})))

    assert line['msg'] == 'Report'
    assert line['value'] == 10
    assert line['slot'] == 42


def test_json_default_converts_bytes_dataclasses_sets_and_unknown_values():
    assert json_default(b'\x01\x02') == '0x0102'
    assert json_default(bytearray(b'\xff')) == '0xff'
    assert json_default(Report(1, b'\x0a')) == {'ref_slot': 1, 'root': b'\x0a'}
    assert json_default({1, 2}) == [1, 2]
    assert json_default(iter([1, 2])) == [1, 2]
    assert json_default(Decimal('1.5')) == '1.5'


def test_json_formatter_serializes_values_the_bots_log():
    message = {'msg': 'Report', 'report': Report(1, b'\x0a'), 'raw': b'\x01', 'amount': Decimal('1.5'), 'ids': {3}}

    line = json.loads(JsonFormatter().format(make_record(message)))

    assert line['report'] == {'ref_slot': 1, 'root': '0x0a'}
    assert line['raw'] == '0x01'
    assert line['amount'] == '1.5'
    assert line['ids'] == [3]


def test_json_formatter_adds_masked_exc_info():
    try:
        raise ConnectionError(f'Max retries exceeded with url: {RPC}')
    except ConnectionError as error:
        record = make_record('Failed.', logging.ERROR, (type(error), error, error.__traceback__))

    line = json.loads(JsonFormatter(SecretsMasker(SECRETS)).format(record))

    assert line['msg'] == 'Failed.'
    assert 'Traceback' in line['exc_info']
    assert 'ConnectionError' in line['exc_info']
    assert_no_secret(line['exc_info'])


def test_json_formatter_has_no_exc_info_field_without_exception():
    assert 'exc_info' not in json.loads(JsonFormatter().format(make_record('x')))


def test_json_formatter_masks_a_record_that_cannot_be_formatted():
    record = make_record('rate %d of %s', logging.INFO)
    record.args = ('oops', KEY)

    line = json.loads(JsonFormatter(SecretsMasker(SECRETS)).format(record))

    assert line['msg'] == 'rate %d of %s'
    assert line['error'].startswith('Log record could not be formatted: TypeError')
    assert 'oops' in line['args']
    assert_no_secret(line['args'])
    assert list(line)[:7] == ['name', 'levelname', 'funcName', 'lineno', 'module', 'pathname', 'timestamp']


def test_json_formatter_masks_a_dict_message_json_cannot_serialize():
    record = make_record({'msg': 'x', 'value': {(1, 2): KEY}})

    line = json.loads(JsonFormatter(SecretsMasker(SECRETS)).format(record))

    assert 'Log record could not be formatted' in line['error']
    assert_no_secret(json.dumps(line))
