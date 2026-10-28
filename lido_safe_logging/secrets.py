import contextlib
import json
import re
import threading
from collections.abc import Iterator, Mapping
from urllib.parse import unquote, urlsplit

MASKED_VALUE = '***'
# Shorter values are not masked: they would hide ordinary text (ports, flags) in every log line.
MIN_SECRET_LENGTH = 8

_HEX = re.compile(r'(0x)?([0-9a-fA-F]+)', re.ASCII)


def _key_like(text: str, min_length: int) -> bool:
    """A part of a URL that looks like a provider key, not like a route: long enough and not a plain word."""
    return len(text) >= min_length and (any(char.isdigit() for char in text) or len(text) >= 2 * min_length)


def _hex_forms(text: str) -> Iterator[str]:
    # A hex secret (a private key, a hash) is logged with or without the 0x prefix, in lower or upper case:
    # bytes come out of json_default as lower-case 0x-hex, a configured value may be upper-case.
    match = _HEX.fullmatch(text)
    if match is None:
        return
    for digits in (match[2].lower(), match[2].upper()):
        yield digits
        yield '0x' + digits


def _url_parts(text: str, min_length: int) -> Iterator[str]:
    try:
        url = urlsplit(text)
    except ValueError:
        return
    if not (url.scheme and url.netloc):
        return

    for part in (url.username, url.password):
        if part:
            yield part
            yield unquote(part)
    if url.password:
        yield f'{url.username or ""}:{url.password}'

    # HTTP libraries often log only the path or the query of a URL, and that is where a provider key usually is.
    # A route without a key-like segment (/eth/v1/beacon) stays readable, otherwise it would be masked in every line.
    segments = url.path.split('/')
    if any(_key_like(segment, min_length) for segment in segments):
        yield url.path
        yield url.path.rstrip('/')
        yield unquote(url.path)
        for segment in segments:
            if _key_like(segment, min_length):
                yield segment
                yield unquote(segment)

    query_is_secret = False
    for pair in url.query.split('&'):
        _, _, value = pair.partition('=')
        if _key_like(value, min_length):
            query_is_secret = True
            yield pair
            yield value
            yield unquote(value)
    if query_is_secret:
        yield url.query


def _variants(secret: str, min_length: int) -> Iterator[str]:
    # A secret read from a file usually keeps the trailing newline, the log shows the stripped value.
    for text in dict.fromkeys((secret, secret.strip())):
        yield text
        yield text.rstrip('/')
        yield from _hex_forms(text)
        yield from _url_parts(text, min_length)


def _escaped_forms(text: str) -> Iterator[str]:
    # The forms a value takes after one layer of encoding: repr() (a %r in a message, str() of a dict or an exception)
    # and json.dumps() (a JSON document inside a message). The JSON encoding of the log line is added on top later.
    yield repr(text)[1:-1]
    yield json.dumps(text)[1:-1]


def _strings(value: object, seen: set[int]) -> Iterator[str]:
    """Every string inside the value: plain strings, bytes as text and as hex, items of containers, the rest as str()."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, bytes | bytearray):
        raw = bytes(value)
        with contextlib.suppress(UnicodeDecodeError):
            yield raw.decode()
        yield '0x' + raw.hex()
    elif isinstance(value, Mapping | list | tuple | set | frozenset):
        if id(value) in seen:
            return
        seen.add(id(value))
        items = value.values() if isinstance(value, Mapping) else value
        for item in items:
            yield from _strings(item, seen)
    else:
        # A number, a Path, a Decimal, a SecretStr: whatever text it shows in a log is a secret too.
        yield str(value)


def secret_values(secrets: Mapping[str, object], *, min_length: int = MIN_SECRET_LENGTH) -> list[str]:
    """Strings to hide in logs: every secret value and list item, its URL parts, hex, stripped, repr and JSON-escaped forms."""
    base: set[str] = set()
    for value in secrets.values():
        for item in _strings(value, set()):
            for variant in _variants(item, min_length):
                if variant and len(variant) >= min_length:
                    base.add(variant)
                    base.update(_escaped_forms(variant))

    # Every form once more JSON-escaped: the replacement runs on the formatted JSON line.
    values = base | {json.dumps(variant)[1:-1] for variant in base}
    # Longest first, so that a value which contains another one is replaced as a whole.
    return sorted(values, key=lambda value: (-len(value), value))


class SecretsMasker:
    """Replaces the secret values with the masked value in any text, for example in a formatted log line.

    New secrets can be added later with `add()`, for a service that configures logging before it reads its config.
    """

    def __init__(self, secrets: Mapping[str, object], *, masked_value: str = MASKED_VALUE, min_length: int = MIN_SECRET_LENGTH):
        self._masked_value = masked_value
        self._min_length = min_length
        self._lock = threading.Lock()
        self._secrets: list[Mapping[str, object]] = []
        self._values: tuple[str, ...] = ()
        self._pattern: re.Pattern[str] | None = None
        self.add(secrets)

    def add(self, secrets: Mapping[str, object]) -> None:
        """Mask the values of these secrets too, in every line from now on."""
        with self._lock:
            self._secrets.append(dict(secrets))
            merged = {f'{index}:{name}': value for index, mapping in enumerate(self._secrets) for name, value in mapping.items()}
            values = secret_values(merged, min_length=self._min_length)
            # The alternation tries the values in order, so the longest match at a position wins. The lookahead makes
            # the search report a match at every position, also inside an earlier match: overlapping secrets are
            # merged into one span, a plain substitution would leave the tail of the second one visible.
            pattern = re.compile('(?=(' + '|'.join(map(re.escape, values)) + '))') if values else None
            self._values, self._pattern = tuple(values), pattern

    @property
    def values(self) -> tuple[str, ...]:
        """The strings this masker replaces, longest first."""
        return self._values

    def mask(self, text: str) -> str:
        pattern = self._pattern
        if pattern is None:
            return text

        spans: list[list[int]] = []
        for match in pattern.finditer(text):
            start, end = match.start(), match.start() + len(match[1])
            if spans and start <= spans[-1][1]:
                spans[-1][1] = max(spans[-1][1], end)
            else:
                spans.append([start, end])
        if not spans:
            return text

        parts: list[str] = []
        last = 0
        for start, end in spans:
            parts.append(text[last:start])
            parts.append(self._masked_value)
            last = end
        parts.append(text[last:])
        return ''.join(parts)
