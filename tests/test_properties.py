"""Property-style checks on fixed random inputs: the masked line is valid JSON and carries no secret."""

import json
import logging
import random
import string

import pytest

from logmask.formatter import JsonFormatter
from logmask.secrets import MASKED_VALUE, SecretsMasker
from tests.conftest import make_record

ALPHABET = string.ascii_letters + string.digits + '"\'\\\n\t\x00\x7f /:@?&=+%#é€🔑'


def random_secret(rng: random.Random) -> str:
    # 6-20 characters from an alphabet with the JSON and repr special characters and non-ASCII text.
    length = rng.randint(6, 20)
    return ''.join(rng.choice(ALPHABET) for _ in range(length))


def messages(secret: str) -> list[tuple[object, tuple[object, ...]]]:
    """Every shape in which a service logs a value: %s, %r, a dict, a nested dict, JSON and repr of a dict."""
    return [
        ('got %s', (secret,)),
        ('got %r', (secret,)),
        ({'msg': 'got', 'value': secret}, ()),
        ({'msg': 'got', 'value': {'inner': [secret, {'deep': secret}]}}, ()),
        ('body %s', (json.dumps({'p': secret}),)),
        ('config %s', (str({'p': secret}),)),
        ('error %s', (str(ValueError(secret)),)),
    ]


@pytest.mark.parametrize('seed', range(40))
def test_random_secrets_never_leak_and_the_line_stays_json(seed):
    rng = random.Random(seed)
    secret = random_secret(rng)
    formatter = JsonFormatter(SecretsMasker({'S': secret}))
    # The shortest piece of the secret that must not appear: a run of 6 characters without the special ones.
    plain = ''.join(char for char in secret if char.isalnum())

    for msg, args in messages(secret):
        record = make_record(msg, logging.INFO)
        record.args = args
        line = formatter.format(record)

        parsed = json.loads(line)
        assert MASKED_VALUE in line, (secret, msg)
        if len(plain) >= 6:
            assert plain not in line, (secret, msg)
        assert parsed['name'] == 'test'


@pytest.mark.parametrize('seed', range(20))
def test_two_layers_in_mixed_quote_contexts(seed):
    rng = random.Random(1000 + seed)
    secret = random_secret(rng)
    masker = SecretsMasker({'S': secret})
    plain = ''.join(char for char in secret if char.isalnum())

    contexts = [
        repr(repr(secret)),
        repr(str({'k': secret, 'quote': '"'})),
        json.dumps(repr(secret)),
        repr(json.dumps(secret)),
        repr(["it's", secret]),
        str(KeyError(secret)),
        json.dumps({'msg': str(ValueError(secret))}),
    ]
    for text in contexts:
        masked = masker.mask(text)

        assert MASKED_VALUE in masked, (secret, text)
        if len(plain) >= 6:
            assert plain not in masked, (secret, text)


def test_a_large_line_with_many_occurrences_is_masked_completely():
    key = '0x' + 'ab' * 32
    masker = SecretsMasker({'K': key})
    line = json.dumps({'value': [{'key': key, 'index': i} for i in range(20000)]})

    masked = masker.mask(line)

    assert 'abab' not in masked
    assert masked.count(MASKED_VALUE) == 20000
    json.loads(masked)
