import dataclasses
import json
import logging
import sys
from decimal import Decimal

import pytest

from logmask.formatter import UNPRINTABLE, JsonFormatter, json_default
from logmask.secrets import MASKED_VALUE, SecretsMasker
from tests.conftest import KEY, RPC, SECRETS, assert_no_secret, make_record

PLAIN = JsonFormatter(SecretsMasker({}))


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


def test_json_formatter_with_no_secrets_keeps_the_text():
    line = PLAIN.format(make_record({'msg': RPC}))

    assert json.loads(line)['msg'] == RPC


def test_json_formatter_field_names_match_the_bots():
    record = make_record('hello %s', logging.WARNING)
    record.args = ('world',)

    line = json.loads(PLAIN.format(record))

    assert list(line) == ['name', 'levelname', 'funcName', 'lineno', 'module', 'pathname', 'timestamp', 'msg']
    assert line['name'] == 'test'
    assert line['levelname'] == 'WARNING'
    assert line['lineno'] == 1
    assert line['module'] == 'conftest'
    assert line['msg'] == 'hello world'


def test_json_formatter_timestamp_is_the_record_time_in_seconds():
    record = make_record('x')
    record.created = 1761600000.75

    assert json.loads(PLAIN.format(record))['timestamp'] == 1761600000


def test_json_formatter_keeps_message_keys():
    line = json.loads(PLAIN.format(make_record({'msg': 'Report', 'value': 10, 'slot': 42})))

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

    line = json.loads(PLAIN.format(make_record(message)))

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
    assert 'exc_info' not in json.loads(PLAIN.format(make_record('x')))


def test_json_formatter_masks_a_record_that_cannot_be_formatted():
    record = make_record('rate %d of %s', logging.INFO)
    record.args = ('oops', KEY)

    line = json.loads(JsonFormatter(SecretsMasker(SECRETS)).format(record))

    assert line['msg'] == 'rate %d of %s'
    assert line['error'].startswith('[logmask] Log record could not be formatted: TypeError')
    assert 'oops' in line['args']
    assert_no_secret(line['args'])
    assert list(line)[:7] == ['name', 'levelname', 'funcName', 'lineno', 'module', 'pathname', 'timestamp']


def test_message_keys_do_not_overwrite_the_record_fields():
    record = make_record({'msg': 'login', 'name': 'alice', 'timestamp': 'yesterday', 'user': 'bob'})

    line = json.loads(PLAIN.format(record))

    assert line['name'] == 'test'
    assert isinstance(line['timestamp'], int)
    assert line['msg_name'] == 'alice'
    assert line['msg_timestamp'] == 'yesterday'
    assert line['user'] == 'bob'


class Unprintable:
    def __str__(self) -> str:
        raise RuntimeError('no str')

    __repr__ = __str__


def test_fallback_line_survives_values_whose_repr_raises():
    record = make_record('rate %d of %s %s', logging.INFO)
    record.args = (Unprintable(), KEY, 'x')

    line = json.loads(JsonFormatter(SecretsMasker(SECRETS)).format(record))

    assert 'Log record could not be formatted' in line['error']
    assert line['args'] == '<unprintable>'

    record = make_record(Unprintable())
    line = json.loads(PLAIN.format(record))

    assert line['msg'] == '<unprintable>'


def test_json_formatter_masks_a_secret_logged_as_repr_or_as_json():
    secret = 'pa"ss\\w\nord-value'
    formatter = JsonFormatter(SecretsMasker({'PASSWORD': secret}))

    for message in (
        f'got {secret!r}',
        f'payload {json.dumps({"p": secret})}',
        f'error {KeyError(secret)!s}',
        f'config { ({"p": secret})!s}',
        f'resp {json.dumps({"p": secret})!r}',
    ):
        line = formatter.format(make_record(message))

        assert 'ord-value' not in line, line
        assert MASKED_VALUE in line


def test_json_formatter_masks_a_bytes_secret_logged_as_hex_or_as_repr():
    raw = bytes.fromhex('a1b2c3d4e5f6a7b8')
    formatter = JsonFormatter(SecretsMasker({'KEY': raw}))

    line = json.loads(formatter.format(make_record({'msg': 'key', 'raw': raw, 'hex': raw.hex().upper(), 'repr': repr(raw)})))

    assert line['raw'] == MASKED_VALUE
    assert line['hex'] == MASKED_VALUE
    assert line['repr'] == f"b'{MASKED_VALUE}'"


def test_json_formatter_masks_a_dict_message_json_cannot_serialize():
    record = make_record({'msg': 'x', 'value': {(1, 2): KEY}})

    line = json.loads(JsonFormatter(SecretsMasker(SECRETS)).format(record))

    assert 'Log record could not be formatted' in line['error']
    assert_no_secret(json.dumps(line))


@pytest.mark.parametrize('secret', ['"', '{', '}', ':', ',', 'true', 'null', 'n', 'u', '00', '\\', '", "'])
def test_masked_line_stays_valid_json_for_a_secret_made_of_json_syntax(secret):
    formatter = JsonFormatter(SecretsMasker({'S': secret}))

    line = formatter.format(make_record({'msg': f'got {secret} here', 'value': [secret, {'k': 'caf\u00e9'}]}))

    parsed = json.loads(line)
    assert secret not in parsed['msg']
    assert MASKED_VALUE in parsed['msg']


def test_a_secret_used_as_a_message_key_is_masked_and_the_line_stays_json():
    formatter = JsonFormatter(SecretsMasker({'S': 'key"secret-12345'}))

    line = formatter.format(make_record({'msg': 'weights', 'key"secret-12345': 1, 'nested': {'key"secret-12345': [2]}}))

    parsed = json.loads(line)
    assert 'secret-12345' not in line
    assert parsed[MASKED_VALUE] == 1
    assert parsed['nested'] == {MASKED_VALUE: [2]}


def test_json_formatter_serializes_a_mapping_that_is_not_a_dict():
    from types import MappingProxyType

    block = MappingProxyType({'number': 1, 'hash': b'\x0a'})

    line = json.loads(PLAIN.format(make_record({'msg': 'block', 'value': block})))

    assert line['value'] == {'number': 1, 'hash': '0x0a'}


def test_a_message_that_cannot_be_encoded_by_the_stream_does_not_leak_through_the_error_report(capsys):
    import io

    from logmask.handler import SafeStreamHandler

    class AsciiStream(io.StringIO):
        def write(self, text: str) -> int:
            # The error of a narrow stream carries the whole text being written.
            raise UnicodeEncodeError('ascii', text, 0, 1, 'ordinal not in range(128)')

    masker = SecretsMasker(SECRETS)
    handler = SafeStreamHandler(AsciiStream(), masker=masker)
    handler.setFormatter(JsonFormatter(masker))

    handler.handle(make_record({'msg': 'café', 'url': RPC}))

    report = capsys.readouterr().err
    assert 'UnicodeEncodeError' in report
    assert_no_secret(report)


def test_leaf_masking_keeps_the_other_values_of_the_line():
    formatter = JsonFormatter(SecretsMasker({'S': '"'}))

    parsed = json.loads(formatter.format(make_record({'msg': 'a " b', 'items': ['x', 1, None, {'k': 'y"z'}], 'n': 2})))

    assert parsed['msg'] == f'a {MASKED_VALUE} b'
    assert parsed['items'] == ['x', 1, None, {'k': f'y{MASKED_VALUE}z'}]
    assert parsed['n'] == 2


def test_a_message_nested_too_deep_for_the_leaf_masking_becomes_a_fallback_line():
    formatter = JsonFormatter(SecretsMasker({'PIN': 12345678}))
    message: dict[str, object] = {'msg': 'login', 'pin': 12345678}
    cursor = message
    for _ in range(sys.getrecursionlimit() * 2):
        cursor['next'] = {}
        cursor = cursor['next']  # type: ignore[assignment]
    cursor['pin'] = 'pin 12345678'

    line = formatter.format(make_record(message))

    parsed = json.loads(line)
    assert '12345678' not in line
    assert 'RecursionError' in parsed['error']
    # str() of the message raises on some Python versions and succeeds on others; both ways no secret is left.
    assert parsed['msg'] == UNPRINTABLE or parsed['msg'].startswith(f"{{'msg': 'login', 'pin': {MASKED_VALUE}")


@pytest.mark.parametrize(('secret', 'logged'), [(12345678, 12345678), ('12345678', 12345678), (12345678, '12345678'), (3.14159, 3.14159)])
def test_a_number_equal_to_a_secret_is_masked_in_a_dict_message(secret, logged):
    formatter = JsonFormatter(SecretsMasker({'PIN': secret}))

    line = formatter.format(make_record({'msg': 'login', 'pin': logged, 'items': [logged, {'deep': logged}], 'count': 7}))

    parsed = json.loads(line)
    assert str(secret) not in line
    assert parsed['pin'] == MASKED_VALUE
    assert parsed['items'] == [MASKED_VALUE, {'deep': MASKED_VALUE}]
    assert parsed['count'] == 7
