import json

from lido_safe_logging.secrets import MASKED_VALUE, SecretsMasker, secret_values, secrets_from_env
from tests.conftest import CL_URL, KEY, RPC, RPC_2, SECRETS, assert_no_secret


def test_secret_values_cover_list_items_and_url_without_trailing_slash():
    values = secret_values(SECRETS)

    assert KEY in values
    assert RPC in values
    assert RPC.rstrip('/') in values
    assert RPC_2 in values


def test_secret_values_cover_url_path_query_password_and_userinfo():
    values = secret_values(
        {
            'A': 'https://rpc.example/v3/secret-key-1/',
            'B': 'https://rpc.example/eth?apikey=secret-key-2',
            'C': CL_URL,
        }
    )

    assert '/v3/secret-key-1/' in values
    assert '/v3/secret-key-1' in values
    assert 'apikey=secret-key-2' in values
    assert 'secret-pass-3' in values
    assert 'user:secret-pass-3' in values
    assert '/eth' not in values


def test_url_route_without_a_key_like_segment_stays_readable():
    # A route (/eth/v1/beacon) is not a secret: masked, it would hide the request path in every line.
    for url in ('https://user:secret-pass-3@cl.example/eth/v1/beacon?slot=1234567', 'https://cl.example/eth/v1/beacon/'):
        values = secret_values({'CL': url})

        assert '/eth/v1/beacon' not in values
        assert '/eth/v1/beacon/' not in values
        assert 'slot=1234567' not in values
        assert SecretsMasker({'CL': url}).mask('GET /eth/v1/beacon/genesis') == 'GET /eth/v1/beacon/genesis'


def test_url_with_basic_auth_masks_a_key_like_path_and_query():
    url = 'https://user:secret-pass-3@rpc.example/v3/secret-key-1?apikey=secret-key-2&slot=1'
    masker = SecretsMasker({'RPC': url})

    masked = masker.mask(f'GET {url} | /v3/secret-key-1 | secret-key-1 | apikey=secret-key-2 | secret-key-2 | slot=1')

    assert masked == f'GET {MASKED_VALUE} | {MASKED_VALUE} | {MASKED_VALUE} | {MASKED_VALUE} | {MASKED_VALUE} | slot=1'
    assert 'secret-pass-3' in masker.values
    assert 'user:secret-pass-3' in masker.values


def test_percent_encoded_url_parts_are_masked_decoded_too():
    masker = SecretsMasker({'CL': 'https://user:p%40ss-word-3@cl.example/', 'RPC': 'https://rpc.example/v3/key%2Fwith-slash-1'})

    assert masker.mask('auth p@ss-word-3 and p%40ss-word-3') == f'auth {MASKED_VALUE} and {MASKED_VALUE}'
    assert masker.mask('path /v3/key/with-slash-1') == f'path {MASKED_VALUE}'


def test_bytes_and_numbers_are_masked_by_their_text_and_hex_forms():
    masker = SecretsMasker({'KEY': b'supersecretbytes', 'RAW': bytes.fromhex('a1b2c3d4e5f6a7b8'), 'PIN': 12345678})

    assert masker.mask('supersecretbytes 0x73757065727365637265746279746573') == f'{MASKED_VALUE} {MASKED_VALUE}'
    assert masker.mask('0xa1b2c3d4e5f6a7b8 A1B2C3D4E5F6A7B8') == f'{MASKED_VALUE} {MASKED_VALUE}'
    assert masker.mask('pin 12345678') == f'pin {MASKED_VALUE}'


def test_hex_secret_is_masked_in_both_cases_with_and_without_the_prefix():
    masker = SecretsMasker({'KEY': '0xABCDEF0123456789'})

    assert masker.mask('0xabcdef0123456789 abcdef0123456789 0XABCDEF0123456789') == f'{MASKED_VALUE} {MASKED_VALUE} 0X{MASKED_VALUE}'
    assert KEY.upper().replace('0X', '0x') in SecretsMasker({'KEY': KEY}).values


def test_repr_and_json_forms_of_a_secret_are_masked():
    secret = 'pa"ss\\w\nordé-value'
    masker = SecretsMasker({'PASSWORD': secret})

    for text in (repr(secret), str({'p': secret}), json.dumps({'p': secret}), str(KeyError(secret))):
        for line in (text, json.dumps({'msg': text})):
            masked = masker.mask(line)

            assert 'ord' not in masked, masked
            assert MASKED_VALUE in masked


def test_overlapping_secrets_are_masked_as_one_span():
    masker = SecretsMasker({'A': 'abcdefgh', 'B': 'efghijklmnop'})

    assert masker.mask('x abcdefghijklmnop y abcdefgh z efghijklmnop') == f'x {MASKED_VALUE} y {MASKED_VALUE} z {MASKED_VALUE}'


def test_empty_variant_is_never_a_secret():
    assert SecretsMasker({'A': '', 'B': '/'}, min_length=0).mask('abc') == 'abc'
    assert '' not in secret_values({'A': ''}, min_length=0)


def test_self_referencing_structure_does_not_recurse_forever():
    loop: dict[str, object] = {}
    loop['self'] = loop
    loop['list'] = [loop, 'secret-in-loop-1']

    assert SecretsMasker({'A': loop}).mask('secret-in-loop-1') == MASKED_VALUE


def test_add_masks_new_secrets_and_keeps_the_old_ones():
    masker = SecretsMasker({'A': 'first-secret-1'})
    masker.add({'B': 'second-secret-2'})
    masker.add({'B': 'third-secret-3'})

    assert masker.mask('first-secret-1 second-secret-2 third-secret-3') == f'{MASKED_VALUE} {MASKED_VALUE} {MASKED_VALUE}'


def test_add_does_not_grow_the_values_when_the_same_secret_is_added_again():
    masker = SecretsMasker({'TOKEN': 'pa"ss\\word/123'})
    before = masker.values

    masker.add({'TOKEN': 'pa"ss\\word/123'})
    masker.add({'OTHER': 'pa"ss\\word/123'})

    assert masker.values == before


def test_token_as_url_username_is_masked():
    masker = SecretsMasker({'RPC': 'https://token-value-abcdef@rpc.example/'})

    assert masker.mask('auth token-value-abcdef rejected') == f'auth {MASKED_VALUE} rejected'


def test_nested_structures_are_searched_for_strings():
    secrets = {'RPC': {'mainnet': RPC, 'hoodi': [RPC_2]}, 'KEYS': [[KEY], ('x',)], 'PORT': 8545}

    values = secret_values(secrets)

    assert RPC in values
    assert RPC_2 in values
    assert KEY in values
    assert '8545' not in values


def test_invalid_url_like_value_does_not_raise():
    secret = 'http://[bad-ipv6-literal/secret-key-5'

    assert SecretsMasker({'A': secret}).mask(f'got {secret}') == f'got {MASKED_VALUE}'


def test_secret_values_include_json_escaped_forms():
    secret = 'pa"ss\\word/123'

    values = secret_values({'TOKEN': secret})

    assert secret in values
    assert json.dumps(secret)[1:-1] in values


def test_secret_values_are_sorted_longest_first_and_deterministic():
    values = secret_values(SECRETS)

    assert values == sorted(values, key=lambda value: (-len(value), value))
    assert values == secret_values(dict(reversed(list(SECRETS.items()))))


def test_short_and_empty_values_are_not_masked():
    assert secret_values({'A': '', 'B': None, 'C': 'short', 'D': ['x'], 'E': 42}) == []


def test_min_length_is_configurable():
    assert 'short' in secret_values({'A': 'short'}, min_length=5)
    assert SecretsMasker({'A': 'short'}, min_length=5).mask('a short one') == f'a {MASKED_VALUE} one'


def test_masker_hides_url_path_logged_without_the_host():
    error = "HTTPSConnectionPool(host='rpc.example', port=443): Max retries exceeded with url: /v3/secret-key-1/"

    assert 'secret-key' not in SecretsMasker(SECRETS).mask(error)


def test_masker_hides_secrets_inside_text():
    text = f'HTTPConnectionPool(host={RPC.rstrip("/")}): error; key={KEY}'

    masked = SecretsMasker(SECRETS).mask(text)

    assert_no_secret(masked)
    assert masked.count(MASKED_VALUE) == 2


def test_masker_hides_every_consumer_shape():
    masker = SecretsMasker(SECRETS)

    for value in (RPC, RPC_2, KEY, CL_URL, 'secret-pass-3', 'eyJhbGciOiJIUzI1NiJ9.token-value-4'):
        assert_no_secret(masker.mask(f'value={value}'))


def test_secret_with_trailing_newline_is_masked_in_stripped_form():
    # A secret read from a file usually keeps the trailing newline; the log shows the stripped value.
    masker = SecretsMasker({'TOKEN': 'secret-from-file\n'})

    assert masker.mask('token=secret-from-file sent') == f'token={MASKED_VALUE} sent'
    assert masker.mask('token=secret-from-file\n') == f'token={MASKED_VALUE}'


def test_masked_value_is_configurable():
    assert SecretsMasker({'A': KEY}, masked_value='[hidden]').mask(f'k={KEY}') == 'k=[hidden]'
    assert SecretsMasker({'A': KEY}, masked_value='\\1 \\g<0>').mask(KEY) == '\\1 \\g<0>'


def test_regex_special_characters_in_secrets_are_literal():
    secret = 'a+b*c?d(e)f[g]h|i^j$k.l'

    assert SecretsMasker({'A': secret}).mask(f'v={secret} and abc') == f'v={MASKED_VALUE} and abc'


def test_masker_exposes_values_for_diagnostics():
    masker = SecretsMasker({'A': KEY})

    assert KEY in masker.values
    assert isinstance(masker.values, tuple)


def test_masker_without_secrets_keeps_the_text():
    assert SecretsMasker({}).mask(RPC) == RPC


def test_secrets_from_env_picks_marker_names_and_drops_empty():
    environ = {
        'WALLET_PRIVATE_KEY': KEY,
        'API_TOKEN': 'token-value',
        'db_password': 'pass-value',
        'EMPTY_SECRET': '',
        'PROMETHEUS_PORT': '9000',
        'LIDO_LOCATOR': '0xC1d0',
        # A marker inside a longer word is not a marker: these are public URLs.
        'KEYS_API_URL': 'https://keys.example',
        'COMPASS_URL': 'https://compass.example',
        'DB_PASS': 'pass-value-2',
    }

    assert secrets_from_env(environ) == {
        'WALLET_PRIVATE_KEY': KEY,
        'API_TOKEN': 'token-value',
        'db_password': 'pass-value',
        'DB_PASS': 'pass-value-2',
    }


def test_secrets_from_env_reads_os_environ_by_default(monkeypatch):
    monkeypatch.setenv('LSL_TEST_SECRET', 'value-from-env')

    assert secrets_from_env()['LSL_TEST_SECRET'] == 'value-from-env'


def test_secrets_from_env_markers_are_configurable():
    environ = {'MY_URI': 'https://x.example/key', 'MY_TOKEN': 'token-value'}

    assert secrets_from_env(environ, markers=('URI',)) == {'MY_URI': 'https://x.example/key'}
