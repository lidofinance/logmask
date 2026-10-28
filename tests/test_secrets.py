import base64
import dataclasses
import json
from urllib.parse import quote

import pytest

from logmask.secrets import MASKED_VALUE, SecretsMasker
from tests.conftest import CL_URL, KEY, RPC, RPC_2, SECRETS, assert_no_secret


def test_every_value_and_list_item_is_masked_with_and_without_the_trailing_slash():
    masker = SecretsMasker(SECRETS)

    assert masker.mask(f'{RPC} {RPC.rstrip("/")} {RPC_2} {KEY}') == ' '.join([MASKED_VALUE] * 4)


def test_url_path_query_password_and_userinfo_are_masked_on_their_own():
    masker = SecretsMasker({'A': 'https://rpc.example/v3/secret-key-1/', 'B': 'https://rpc.example/eth?apikey=secret-key-2', 'C': CL_URL})

    masked = masker.mask(
        '/v3/secret-key-1/ | /v3/secret-key-1 | /eth?apikey=secret-key-2 | apikey=secret-key-2 | secret-pass-3 | user:secret-pass-3'
    )

    assert masked == ' | '.join([MASKED_VALUE] * 6)


def test_key_like_url_host_is_masked_on_its_own():
    # Some providers put the key into the host name, and urllib3 logs the host without the path.
    masker = SecretsMasker({'RPC': 'https://a1b2c3d4e5f6.ethereum.rpc.example:8545/v3/key-0123456789', 'CL': CL_URL})

    masked = masker.mask(
        "HTTPSConnectionPool(host='a1b2c3d4e5f6.ethereum.rpc.example', port=8545) user:secret-pass-3@cl.example cl.example"
    )

    assert masked == f"HTTPSConnectionPool(host='{MASKED_VALUE}', port=8545) {MASKED_VALUE} cl.example"


def test_basic_auth_header_of_a_url_password_is_masked():
    masker = SecretsMasker({'CL': 'https://user:s3cret-pass-word@cl.example/'})
    header = base64.b64encode(b'user:s3cret-pass-word').decode()

    assert masker.mask(f'Authorization: Basic {header}') == f'Authorization: Basic {MASKED_VALUE}'


def test_whole_path_is_masked_but_a_plain_word_of_it_is_not():
    # The path of a private URL is masked whole (and with its query); a short word of it, such as `eth`, stays a
    # word everywhere else, otherwise `ethereum` would vanish from every line.
    masker = SecretsMasker({'CL': 'https://cl.example/eth/v1/beacon?network=ethereum'})

    assert masker.mask('GET /eth/v1/beacon?network=ethereum and /eth/v1/beacon') == f'GET {MASKED_VALUE} and {MASKED_VALUE}'
    assert masker.mask('chain ethereum, route eth') == 'chain ethereum, route eth'


def test_key_like_fragments_of_path_and_query_are_masked_on_their_own():
    masker = SecretsMasker({'RPC': 'https://rpc.example/v3/abcdefghijklmnop?dkey=KEY-0123&x=plain'})

    masked = masker.mask('project abcdefghijklmnop key KEY-0123 flag plain')

    assert masked == f'project {MASKED_VALUE} key {MASKED_VALUE} flag plain'


def test_percent_encoded_url_parts_are_masked_decoded_too():
    masker = SecretsMasker({'CL': 'https://user:p%40ss-word-3@cl.example/', 'RPC': 'https://rpc.example/v3/key%2Fwith-slash-1'})

    assert masker.mask('auth p@ss-word-3 and p%40ss-word-3') == f'auth {MASKED_VALUE} and {MASKED_VALUE}'
    assert masker.mask('path /v3/key/with-slash-1') == f'path {MASKED_VALUE}'


def test_raw_secret_is_masked_percent_encoded_and_base64_encoded():
    token = 'tok/en+value=12345'
    masker = SecretsMasker({'T': token})
    encoded = base64.b64encode(token.encode()).decode()

    masked = masker.mask(
        f'GET /?k={quote(token, safe="")} auth {encoded} and {encoded.rstrip("=")} and {base64.urlsafe_b64encode(token.encode()).decode()}'
    )

    assert masked == f'GET /?k={MASKED_VALUE} auth {MASKED_VALUE} and {MASKED_VALUE} and {MASKED_VALUE}'


def test_bytes_are_masked_as_text_hex_and_repr():
    raw = bytes(range(0xA0, 0xB0))
    masker = SecretsMasker({'KEY': b'supersecretbytes', 'RAW': raw})

    assert masker.mask('supersecretbytes 0x73757065727365637265746279746573') == f'{MASKED_VALUE} {MASKED_VALUE}'
    assert masker.mask(f'{raw.hex()} 0X{raw.hex().upper()} {raw!r}') == f"{MASKED_VALUE} {MASKED_VALUE} b'{MASKED_VALUE}'"


def test_hex_secret_is_masked_in_any_case_with_and_without_the_prefix():
    masker = SecretsMasker({'KEY': '0XABCDEF0123456789'})

    assert masker.mask('0xabcdef0123456789 abcdef0123456789 0XABCDEF0123456789 AbCdEf0123456789') == ' '.join([MASKED_VALUE] * 4)


def test_masking_ignores_the_case_of_any_value():
    masker = SecretsMasker({'TOKEN': 'tok_abcdef123456'})

    assert masker.mask('TOK_ABCDEF123456') == MASKED_VALUE


def test_repr_and_json_forms_of_a_secret_are_masked():
    secret = 'pa"ss\\w\nordé-value'
    masker = SecretsMasker({'PASSWORD': secret})

    for text in (repr(secret), str({'p': secret}), json.dumps({'p': secret}), str(KeyError(secret))):
        for line in (text, json.dumps({'msg': text})):
            masked = masker.mask(line)

            assert 'ord' not in masked, masked
            assert MASKED_VALUE in masked


def test_repr_with_a_single_quote_in_the_secret_is_masked():
    # repr() picks the quotes from the whole string: inside a string with a " the secret's ' becomes \'.
    secret = "pass'word-12345"
    masker = SecretsMasker({'P': secret})

    for text in (repr('user said "hi" pw=' + secret), repr(ValueError('bad "x" ' + secret)), repr({'k': '"' + secret + '"'})):
        assert 'word-12345' not in masker.mask(text), text


def test_two_layers_of_encoding_are_masked():
    secret = 'abc"d\\e\nfgh1234'
    masker = SecretsMasker({'P': secret})

    for text in (repr(str(KeyError(secret))), repr([repr(secret)]), json.dumps(json.dumps({'p': secret})), repr(json.dumps(secret))):
        assert 'fgh1234' not in masker.mask(text), text


def test_overlapping_and_adjacent_secrets_are_masked_as_one_span():
    masker = SecretsMasker({'A': 'abcdefgh', 'B': 'efghijklmnop'})

    assert (
        masker.mask('x abcdefghijklmnop y abcdefgh z efghijklmnop w abcdefghabcdefgh')
        == f'x {MASKED_VALUE} y {MASKED_VALUE} z {MASKED_VALUE} w {MASKED_VALUE}'
    )


def test_none_and_empty_values_are_not_secrets():
    masker = SecretsMasker({'A': '', 'B': None, 'C': b'', 'D': [''], 'E': False})

    assert masker.mask('abc None False') == 'abc None False'
    assert repr(masker) == 'SecretsMasker(0 forms)'


@pytest.mark.parametrize(('value', 'logged'), [('ab1', 'ab1'), (1234, '1234'), (['x1', 'secret-value-9'], 'x1'), ('é', 'é')])
def test_a_private_value_is_masked_whatever_its_length(value, logged):
    masker = SecretsMasker({'SHORT': value})

    assert masker.mask(f'v={logged} 5') == f'v={MASKED_VALUE} 5'


def test_short_url_parts_are_not_masked_on_their_own():
    # A host like `el` or a segment like `v3` cannot be masked alone; the whole URL and the whole path still are.
    masker = SecretsMasker({'EL': 'http://el:8545/v3', 'CL': 'https://user:secret-pass-3@cl.example/'})

    assert masker.mask('level el v3 http://el:8545/v3 el:8545 /v3 a/b') == f'level el v3 {MASKED_VALUE} el:8545 {MASKED_VALUE} a/b'
    assert masker.mask('cl.example / user:secret-pass-3@cl.example') == f'cl.example / {MASKED_VALUE}'


def test_self_referencing_structure_does_not_recurse_forever():
    loop: dict[str, object] = {}
    loop['self'] = loop
    loop['list'] = [loop, 'secret-in-loop-1']

    assert SecretsMasker({'A': loop}).mask('secret-in-loop-1') == MASKED_VALUE


def test_mapping_values_dataclass_fields_and_wrapped_secrets_are_secrets_too():
    @dataclasses.dataclass
    class Credentials:
        user: str
        password: str

    class Wrapped:
        def __str__(self) -> str:
            return '**********'

        def get_secret_value(self) -> str:
            return 'wrapped-secret-7'

    masker = SecretsMasker({'NESTED': {'level': {'inner': RPC}}, 'DB': Credentials('db-user-5', 'db-pass-6'), 'JWT': Wrapped()})

    assert masker.mask(f'{RPC} db-user-5 db-pass-6 wrapped-secret-7') == ' '.join([MASKED_VALUE] * 4)
    assert masker.mask('NESTED DB JWT **********') == 'NESTED DB JWT **********'


def test_keys_of_a_nested_mapping_are_secrets_and_the_top_level_keys_are_names():
    # A nested mapping may be keyed by the secret itself ({key: label}); the top-level keys are the variable names.
    masker = SecretsMasker({'KEYS': {'nested-key-1': 'label-1', ('tuple-key-2',): {'deeper-key-3': None}}})

    assert masker.mask('KEYS nested-key-1 label-1 tuple-key-2 deeper-key-3') == 'KEYS ' + ' '.join([MASKED_VALUE] * 4)


@pytest.mark.parametrize('separator', [',', ';', ' ', '\n', ', ', ' ;\t'])
def test_a_string_with_several_urls_is_searched_url_by_url(separator):
    masker = SecretsMasker({'RPC': separator.join([RPC, RPC_2])})

    assert masker.mask(f'connect {RPC} and {RPC_2}') == f'connect {MASKED_VALUE} and {MASKED_VALUE}'
    assert masker.mask('url /v3/secret-key-1 and /v3/secret-key-2') == f'url {MASKED_VALUE} and {MASKED_VALUE}'
    assert masker.mask('key secret-key-1 and secret-key-2') == f'key {MASKED_VALUE} and {MASKED_VALUE}'


def test_a_single_url_and_a_list_of_plain_words_are_not_split():
    masker = SecretsMasker({'RPC': RPC, 'WORDS': 'alpha, beta'})

    assert masker.mask('alpha beta alpha, beta') == f'alpha beta {MASKED_VALUE}'
    assert masker.mask(f'{RPC}') == MASKED_VALUE


def test_a_json_string_is_searched_as_the_container_it_encodes():
    account = json.dumps(
        {'type': 'service_account', 'private_key': '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n'}
    )
    masker = SecretsMasker({'RPC': json.dumps([RPC, RPC_2]), 'ACCOUNT': account, 'NOT_JSON': '[not json'})

    assert masker.mask(f'connect {RPC} path /v3/secret-key-2') == f'connect {MASKED_VALUE} path {MASKED_VALUE}'
    assert masker.mask('key MIIEvQIBADANBg of type service_account') == f'key {MASKED_VALUE} of {MASKED_VALUE} {MASKED_VALUE}'
    assert masker.mask(f'{account} [not json') == f'{MASKED_VALUE} {MASKED_VALUE}'


def test_every_line_of_a_multi_line_value_is_a_secret():
    masker = SecretsMasker({'PEM': '-----BEGIN KEY-----\nline-one-1\n  line-two-2  \n\n-----END KEY-----\n'})

    assert (
        masker.mask('got line-one-1 then line-two-2 after -----BEGIN KEY-----')
        == f'got {MASKED_VALUE} then {MASKED_VALUE} after {MASKED_VALUE}'
    )
    assert masker.mask('plain line') == 'plain line'


def test_add_masks_new_secrets_and_keeps_the_old_ones():
    masker = SecretsMasker({'A': 'first-secret-1'})
    masker.add({'B': 'second-secret-2'})
    masker.add({'B': 'third-secret-3'})

    assert masker.mask('first-secret-1 second-secret-2 third-secret-3') == f'{MASKED_VALUE} {MASKED_VALUE} {MASKED_VALUE}'


def test_add_of_the_same_secret_does_not_grow_the_masker():
    masker = SecretsMasker({'TOKEN': 'pa"ss\\word/123'})
    before = repr(masker)

    masker.add({'TOKEN': 'pa"ss\\word/123'})
    masker.add({'OTHER': 'pa"ss\\word/123'})

    assert repr(masker) == before


def test_add_after_a_failed_add_still_works():
    class Unreadable:
        def get_secret_value(self) -> str:
            raise RuntimeError('vault is down')

    masker = SecretsMasker({'A': 'first-secret-1'})
    with pytest.raises(RuntimeError):
        masker.add({'B': Unreadable()})
    masker.add({'C': 'other-secret-9'})

    assert masker.mask('first-secret-1 other-secret-9') == f'{MASKED_VALUE} {MASKED_VALUE}'


def test_repr_of_the_masker_shows_no_secret():
    masker = SecretsMasker({'A': KEY})

    assert KEY not in repr(masker)
    assert repr(masker).startswith('SecretsMasker(')


def test_invalid_url_like_value_does_not_raise():
    secret = 'http://[bad-ipv6-literal/secret-key-5'

    assert SecretsMasker({'A': secret}).mask(f'got {secret}') == f'got {MASKED_VALUE}'


def test_masker_hides_url_path_logged_without_the_host():
    error = "HTTPSConnectionPool(host='rpc.example', port=443): Max retries exceeded with url: /v3/secret-key-1/"

    assert 'secret-key' not in SecretsMasker(SECRETS).mask(error)


def test_masker_hides_every_consumer_shape():
    masker = SecretsMasker(SECRETS)

    for value in (RPC, RPC_2, KEY, CL_URL, 'secret-pass-3', 'eyJhbGciOiJIUzI1NiJ9.token-value-4'):
        assert_no_secret(masker.mask(f'value={value}'))


def test_secret_with_trailing_newline_is_masked_in_stripped_form():
    # A secret read from a file usually keeps the trailing newline; the log shows the stripped value.
    masker = SecretsMasker({'TOKEN': 'secret-from-file\n'})

    assert masker.mask('token=secret-from-file sent') == f'token={MASKED_VALUE} sent'
    assert masker.mask('token=secret-from-file\n') == f'token={MASKED_VALUE}'


def test_regex_special_characters_in_secrets_are_literal():
    secret = 'a+b*c?d(e)f[g]h|i^j$k.l'

    assert SecretsMasker({'A': secret}).mask(f'v={secret} and abc') == f'v={MASKED_VALUE} and abc'


def test_masker_without_secrets_keeps_the_text():
    assert SecretsMasker({}).mask(RPC) == RPC


def test_a_text_secret_is_masked_as_the_hex_and_repr_of_its_bytes():
    # json_default writes bytes as 0x-hex: a token inside a logged response body comes out as hex.
    token = 'lido-ipfs-token-0123456789'
    masker = SecretsMasker({'T': token, 'P': 'pässword-12'})

    masked = masker.mask(f'0x{token.encode().hex()} {token.encode().hex().upper()} {"pässword-12".encode()!r} {token.encode()!r}')

    assert masked == f"0x{MASKED_VALUE} {MASKED_VALUE} b'{MASKED_VALUE}' b'{MASKED_VALUE}'"


def test_a_hex_key_is_masked_as_the_bytes_it_encodes():
    masker = SecretsMasker({'K': '0x' + 'ab' * 32})

    assert masker.mask(repr(bytes.fromhex('ab' * 32))) == f"b'{MASKED_VALUE}'"


def test_a_value_with_a_lone_surrogate_is_accepted_and_masked():
    secret = 'abc\udcff-12345'

    assert SecretsMasker({'K': secret}).mask(f'got {secret} and abc') == f'got {MASKED_VALUE} and abc'


def test_bytes_that_are_not_utf8_are_masked_in_the_surrogateescape_form():
    raw = b'\xff\xfeKEYBYTES-1'
    masker = SecretsMasker({'K': raw})

    assert masker.mask(raw.decode('utf-8', errors='surrogateescape')) == MASKED_VALUE


def test_form_encoded_and_percent_encoded_secrets_are_masked_decoded_and_encoded():
    from urllib.parse import quote_plus

    masker = SecretsMasker({'A': 'a b&c=d-12345', 'B': 'p%40ss%2Fword-1234'})

    assert (
        masker.mask(f'{quote_plus("a b&c=d-12345")} p@ss/word-1234 p%40ss%2Fword-1234') == f'{MASKED_VALUE} {MASKED_VALUE} {MASKED_VALUE}'
    )


def test_other_iterables_are_searched_for_secrets():
    from collections import deque

    masker = SecretsMasker({'D': deque(['deque-secret-1']), 'I': iter(['iter-secret-1']), 'M': memoryview(b'view-secret-1')})

    assert masker.mask('deque-secret-1 iter-secret-1 view-secret-1') == ' '.join([MASKED_VALUE] * 3)


class Opaque:
    __slots__ = ('x',)


class Config:
    def __init__(self) -> None:
        self.key = 'object-secret-1'


@pytest.mark.parametrize(
    'value',
    [Opaque(), Config(), Config, lambda: 'closure-secret-1', pytest, object()],
    ids=['slots', 'object', 'class', 'function', 'module', 'plain'],
)
def test_a_value_of_an_unsupported_type_is_refused_at_init_and_in_add(value):
    # A plain object is searched through neither its __dict__ nor its slots: the masker cannot promise that it finds
    # every secret inside (a closure, a property, a slot), so it refuses the value instead of masking a part.
    with pytest.raises(TypeError, match=f'{type(value).__name__} is not supported'):
        SecretsMasker({'O': value})
    masker = SecretsMasker({})
    with pytest.raises(TypeError, match='pass str, bytes'):
        masker.add({'O': value})
    with pytest.raises(TypeError, match='is not supported'):
        masker.add({'nested': {'inner': [value]}})


def test_masking_works_on_non_ascii_text_too():
    masker = SecretsMasker({'K': 'KEY-0123456789'})

    assert masker.mask('Ünïcode key-0123456789 İstanbul') == f'Ünïcode {MASKED_VALUE} İstanbul'


@pytest.mark.parametrize(
    ('fragment', 'masked_alone'),
    [
        ('abcdefghijklmnop', True),  # 16 characters, no digit
        ('abcdefghijklmno', False),  # 15 characters, no digit
        ('abcdefg1', True),  # 8 characters with a digit
        ('abcdef1', False),  # 7 characters with a digit
    ],
)
def test_fragment_rule_boundaries_for_host_segment_and_query_value(fragment, masked_alone):
    # The host alone, one path segment and one query value are masked on their own only when key-like.
    masker = SecretsMasker({'U': f'https://{fragment}/{fragment}?k={fragment}'})
    expected = MASKED_VALUE if masked_alone else fragment

    assert masker.mask(f'host {fragment} segment {fragment} value {fragment}') == f'host {expected} segment {expected} value {expected}'
    assert masker.mask(f'path /{fragment} query k={fragment}') == f'path {MASKED_VALUE} query {MASKED_VALUE}'


def test_ipv6_host_empty_password_and_query_with_equals():
    masker = SecretsMasker({'A': 'https://user:@[::1]:8545/v3/key-0123456789', 'B': 'https://rpc.example/?token=a=b=c-0123456789'})

    assert (
        masker.mask('url https://user:@[::1]:8545/v3/key-0123456789 path /v3/key-0123456789') == f'url {MASKED_VALUE} path {MASKED_VALUE}'
    )
    assert masker.mask('q token=a=b=c-0123456789 v a=b=c-0123456789') == f'q {MASKED_VALUE} v {MASKED_VALUE}'


def test_dataclass_with_bytes_paths_decimals_and_wrapped_lists_are_searched():
    from decimal import Decimal
    from pathlib import PurePosixPath

    @dataclasses.dataclass
    class Keys:
        raw: bytes
        name: str

    class Wrapped:
        def __init__(self, value: str) -> None:
            self._value = value

        def get_secret_value(self) -> str:
            return self._value

    masker = SecretsMasker(
        {
            'K': Keys(b'raw-secret-bytes', 'named-secret-1'),
            'W': [Wrapped('wrapped-one-1'), Wrapped('wrapped-two-2')],
            'P': PurePosixPath('/run/secrets/token-file-9'),
            'D': Decimal('123456.789'),
        }
    )

    masked = masker.mask(
        'raw-secret-bytes 7261772d7365637265742d6279746573 named-secret-1 wrapped-one-1 wrapped-two-2 /run/secrets/token-file-9 123456.789'
    )

    assert masked == ' '.join([MASKED_VALUE] * 7)


def test_add_while_other_threads_mask():
    import threading

    masker = SecretsMasker({'A': 'first-secret-1'})
    errors: list[BaseException] = []
    stop = threading.Event()

    def worker() -> None:
        try:
            while not stop.is_set():
                assert 'first-secret-1' not in masker.mask('x first-secret-1 y late-secret-2')
        except BaseException as error:  # noqa: BLE001 - collected for the assertion below
            errors.append(error)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for index in range(50):
        masker.add({f'L{index}': f'late-secret-{index}'})
    stop.set()
    for thread in threads:
        thread.join()

    assert errors == []
    assert masker.mask('x first-secret-1 y late-secret-2') == f'x {MASKED_VALUE} y {MASKED_VALUE}'


def test_cycles_through_dataclasses_objects_and_iterables_stop():
    from collections import deque

    @dataclasses.dataclass
    class Node:
        secret: str
        next: object = None

    node = Node('dataclass-cycle-1')
    node.next = node
    ring: deque[object] = deque(['deque-cycle-1'])
    ring.append(ring)

    assert SecretsMasker({'A': node, 'C': ring}).mask('dataclass-cycle-1 deque-cycle-1') == ' '.join([MASKED_VALUE] * 2)


def test_containers_inside_dataclass_fields_wrapped_values_and_iterables_are_searched():
    from collections import deque

    @dataclasses.dataclass(slots=True)
    class Keys:
        items: list[str]

    class Wrapped:
        def get_secret_value(self) -> list[str]:
            return ['wrapped-list-1']

    masker = SecretsMasker({'A': Keys(['field-list-1']), 'B': Wrapped(), 'C': deque([('deque-tuple-1',)])})

    assert masker.mask('field-list-1 wrapped-list-1 deque-tuple-1') == ' '.join([MASKED_VALUE] * 3)


def test_a_four_character_value_gets_its_encoded_forms():
    masker = SecretsMasker({'A': 'ab+c'})

    assert masker.mask(f'{base64.b64encode(b"ab+c").decode()} ab%2Bc') == f'{MASKED_VALUE} {MASKED_VALUE}'


def test_url_with_a_password_and_no_user_name():
    masker = SecretsMasker({'U': 'https://:only-pass-word-1@host.example/'})

    assert masker.mask('auth :only-pass-word-1 pw only-pass-word-1') == f'auth {MASKED_VALUE} pw {MASKED_VALUE}'


def test_masking_after_a_character_whose_lower_case_changes_the_length():
    # 'İ'.lower() is two characters: the ASCII fast path must not be used for such text.
    masker = SecretsMasker({'K': 'KEY-0123456789'})

    assert masker.mask('İstanbul key-0123456789 İzmir KEY-0123456789') == f'İstanbul {MASKED_VALUE} İzmir {MASKED_VALUE}'


def test_repeated_add_does_not_keep_the_old_patterns_alive():
    import gc
    import re
    import tracemalloc

    re.purge()
    gc.collect()
    tracemalloc.start()
    try:
        base = tracemalloc.get_traced_memory()[0]
        masker = SecretsMasker({'A': 'https://rpc.example/v3/token-start-00000'})
        for index in range(60):
            masker.add({f'T{index}': f'https://rpc.example/v3/token-rotated-{index:05d}'})
        gc.collect()
        retained = tracemalloc.get_traced_memory()[0] - base
    finally:
        tracemalloc.stop()

    # Without the fix the re cache holds every earlier pattern: tens of MiB after 60 rotations.
    assert retained < 8 * 2**20, f'{retained / 2**20:.1f} MiB retained'
    assert masker.mask('token-rotated-00059 token-start-00000') == f'{MASKED_VALUE} {MASKED_VALUE}'
