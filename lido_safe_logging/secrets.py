import json
import os
import re
from collections.abc import Iterable, Iterator, Mapping
from urllib.parse import urlsplit

MASKED_VALUE = '***'
# Shorter values are not masked: they would hide ordinary text (ports, flags) in every log line.
MIN_SECRET_LENGTH = 8
# The usual words in the name of an environment variable that holds a secret.
DEFAULT_SECRET_NAME_MARKERS = ('SECRET', 'TOKEN', 'PASSWORD', 'PASS', 'PRIVATE', 'CREDENTIALS', 'KEY')


def _variants(secret: str) -> Iterator[str]:
    # A secret read from a file usually keeps the trailing newline, the log shows the stripped value.
    for text in (secret, secret.strip()):
        yield text
        yield text.rstrip('/')

        try:
            url = urlsplit(text)
        except ValueError:
            continue
        if not (url.scheme and url.netloc):
            continue

        if url.username:
            yield url.username
        if url.password:
            # Basic auth: the credential is in the userinfo; the path is an ordinary route and stays readable.
            yield url.password
            yield f'{url.username or ""}:{url.password}'
        else:
            # HTTP libraries often log only the path or the query of a URL, and that is where the provider key usually is.
            yield url.path
            yield url.path.rstrip('/')
            yield url.query


def _strings(value: object) -> Iterator[str]:
    """Every string inside the value: plain strings, items of lists, tuples and sets, values of nested mappings."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list | tuple | set | frozenset):
        for item in value:
            yield from _strings(item)


def secret_values(secrets: Mapping[str, object], *, min_length: int = MIN_SECRET_LENGTH) -> list[str]:
    """Strings to hide in logs: every secret value and list item, its URL parts and the JSON-escaped forms."""
    values: set[str] = set()

    for value in secrets.values():
        for item in _strings(value):
            for variant in _variants(item):
                if len(variant) < min_length:
                    continue
                values.add(variant)
                values.add(json.dumps(variant)[1:-1])

    # Longest first, so that a value which contains another one is replaced as a whole.
    return sorted(values, key=lambda value: (-len(value), value))


class SecretsMasker:
    """Replaces the secret values with the masked value in any text, for example in a formatted log line."""

    def __init__(self, secrets: Mapping[str, object], *, masked_value: str = MASKED_VALUE, min_length: int = MIN_SECRET_LENGTH):
        self._masked_value = masked_value
        self._values = tuple(secret_values(secrets, min_length=min_length))
        # One pass per line. The alternation tries the values in order, so the longest match wins.
        self._pattern = re.compile('|'.join(map(re.escape, self._values))) if self._values else None

    @property
    def values(self) -> tuple[str, ...]:
        """The strings this masker replaces, longest first."""
        return self._values

    def mask(self, text: str) -> str:
        if self._pattern is None:
            return text
        return self._pattern.sub(lambda _: self._masked_value, text)


def secrets_from_env(
    environ: Mapping[str, str] | None = None,
    *,
    markers: Iterable[str] = DEFAULT_SECRET_NAME_MARKERS,
) -> dict[str, str]:
    """Values of the environment variables whose name contains one of the markers (case does not matter).

    Empty values are dropped. This adds to an explicit list of secrets, it does not replace it: a secret under a name
    without a marker stays unmasked.
    """
    if environ is None:
        environ = os.environ
    upper_markers = tuple(marker.upper() for marker in markers)
    return {name: value for name, value in environ.items() if value and any(marker in name.upper() for marker in upper_markers)}
