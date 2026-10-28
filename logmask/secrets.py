import base64
import dataclasses
import json
import numbers
import os
import re
import threading
from collections.abc import Iterable, Iterator, Mapping
from urllib.parse import quote, quote_plus, unquote, unquote_plus, urlsplit

MASKED_VALUE = '***'
# Every line the library writes on its own behalf, instead of the record, starts with this tag.
LIBRARY_TAG = '[logmask]'
# Every private value is masked whole, whatever its length. A standalone fragment of a private URL (the host, one
# path segment, one query value) is masked on its own only when it can be a key: 16 characters or more, or 8 or more
# with a digit. The whole URL, the whole path, the whole query and the user:password are masked without any
# condition. Masking a word like `eth`, a segment like `v3` or a host like `el` on its own would erase it from every
# log line.
_KEY_FRAGMENT_LENGTH = 16
_KEY_FRAGMENT_LENGTH_WITH_DIGIT = 8
# The encodings of a value (percent, base64, hex of its bytes) are derived for values of 4 characters or more: the
# encodings of a shorter value are short random-looking strings that hit ordinary words. The value itself is always
# masked.
_ENCODED_FORMS_MIN_LENGTH = 4
# How many layers of repr() or json.dumps() around a secret are recognised, on top of the JSON encoding of the line.
_ESCAPE_DEPTH = 2

_HEX = re.compile(r'(0x)?([0-9a-f]+)', re.ASCII | re.IGNORECASE)


def _key_fragment(text: str) -> bool:
    return len(text) >= _KEY_FRAGMENT_LENGTH or (len(text) >= _KEY_FRAGMENT_LENGTH_WITH_DIGIT and any(char.isdigit() for char in text))


def _utf8(text: str) -> bytes:
    # A value read from the environment may carry bytes that are not UTF-8, as lone surrogates (surrogateescape).
    return text.encode('utf-8', errors='surrogateescape')


def _hex_forms(text: str) -> Iterator[str]:
    # A hex secret is logged with or without the 0x prefix, and as the bytes it encodes (a private key is held as
    # bytes by eth_account); the pattern ignores the case.
    match = _HEX.fullmatch(text)
    if match is None:
        return
    digits = match[2]
    yield digits
    yield '0x' + digits
    if len(digits) % 2 == 0:
        yield repr(bytes.fromhex(digits))[2:-1]


def _encoded_forms(text: str) -> Iterator[str]:
    """The forms an application gives a raw secret when it builds a URL, a header or a bytes value from it."""
    if len(text) < _ENCODED_FORMS_MIN_LENGTH:
        return
    raw = _utf8(text)
    yield quote(text, safe='', errors='surrogateescape')
    yield quote(text, errors='surrogateescape')
    yield quote_plus(text, errors='surrogateescape')
    for encoded in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
        yield encoded.decode()
        yield encoded.decode().rstrip('=')
    # json_default writes a bytes value as 0x-hex; a text secret inside such a value must be found in that form too.
    yield raw.hex()
    yield repr(raw)[2:-1]


def _with_decoded(text: str) -> Iterator[str]:
    yield text
    yield unquote(text)


def _url_parts(text: str) -> Iterator[str]:
    try:
        url = urlsplit(text)
    except ValueError:
        return
    if not (url.scheme and url.netloc):
        return

    # The netloc with the credentials always, and the host alone when a provider may have put the key into it.
    if '@' in url.netloc:
        yield url.netloc
    for host in (url.netloc.rpartition('@')[2], url.hostname or ''):
        if _key_fragment(host):
            yield host
    for part in (url.username, url.password):
        if part:
            yield from _with_decoded(part)
    if url.password:
        userinfo = f'{url.username or ""}:{url.password}'
        yield from _with_decoded(userinfo)
        # The same credentials as an HTTP Basic header.
        yield base64.b64encode(_utf8(unquote(userinfo))).decode()

    # HTTP libraries log the path, or the path with the query, without the host.
    if url.path.strip('/'):
        yield from _with_decoded(url.path)
        yield url.path.rstrip('/')
        for segment in url.path.split('/'):
            if _key_fragment(segment):
                yield from _with_decoded(segment)
    if url.query:
        yield url.query
        yield f'{url.path}?{url.query}'
        for pair in url.query.split('&'):
            yield pair
            value = pair.partition('=')[2]
            if _key_fragment(value):
                yield from _with_decoded(value)


def _variants(text: str) -> Iterator[str]:
    # A secret read from a file usually keeps the trailing newline, the log shows the stripped value.
    for form in dict.fromkeys((text, text.strip())):
        yield form
        yield form.rstrip('/')
        # A value stored percent-encoded (a password inside a URL) is used decoded by the application.
        yield unquote(form)
        yield unquote_plus(form)
        yield from _hex_forms(form)
        yield from _url_parts(form)
        yield from _encoded_forms(form)


def _encodings(text: str) -> Iterator[str]:
    """The body of a string after one layer of repr() or json.dumps()."""
    # repr() picks the quote style from the whole string: a secret with a ' inside a string that also has a " is
    # escaped as \'. Both bodies are needed.
    yield repr(text)[1:-1]
    yield repr(text + '"')[1:-2]
    yield json.dumps(text)[1:-1]


def _escaped_forms(text: str) -> set[str]:
    forms = {text}
    layer = {text}
    for _ in range(_ESCAPE_DEPTH):
        layer = {encoded for form in layer for encoded in _encodings(form)}
        forms |= layer
    return forms


def _strings(value: object, seen: dict[int, object]) -> Iterator[str]:
    """Every string inside the value: strings, bytes in their text, hex and repr forms, the items of containers and
    other iterables (the keys of a mapping are names, like the variable names), the fields of a dataclass or of any
    object, the wrapped value of a SecretStr-like object, numbers and paths as text. None and bool are not secrets.

    `seen` keeps a reference to every container visited, so that a cycle stops and a freed temporary cannot hand its
    id to a later container that would then be skipped.
    """
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        yield raw.decode('utf-8', errors='surrogateescape')
        yield raw.hex()
        yield repr(raw)[2:-1]
    elif isinstance(value, numbers.Number | os.PathLike):
        # Whatever text the value shows in a log is a secret too.
        yield str(value)
    elif id(value) in seen:
        return
    elif isinstance(value, Mapping):
        seen[id(value)] = value
        for item in value.values():
            yield from _strings(item, seen)
    elif isinstance(value, Iterable):
        seen[id(value)] = value
        for item in value:
            yield from _strings(item, seen)
    elif callable(getter := getattr(value, 'get_secret_value', None)):
        # pydantic SecretStr and the like: str() shows a placeholder, the secret is behind the method.
        seen[id(value)] = value
        yield from _strings(getter(), seen)
    elif dataclasses.is_dataclass(value):
        seen[id(value)] = value
        for field in dataclasses.fields(value):
            yield from _strings(getattr(value, field.name), seen)
    elif hasattr(value, '__dict__'):
        seen[id(value)] = value
        for item in vars(value).values():
            yield from _strings(item, seen)
    else:
        raise TypeError(f'A private value of type {type(value).__name__} cannot be searched for secrets')


def _secret_values(secrets: Mapping[str, object]) -> frozenset[str]:
    """Every string to hide in the formatted log line, derived from the secret values."""
    forms: set[str] = set()
    for value in secrets.values():
        for item in _strings(value, {}):
            for variant in _variants(item):
                if variant:
                    forms |= _escaped_forms(variant)
    # Every form once more JSON-escaped: the replacement runs on the formatted JSON line.
    return frozenset(forms | {json.dumps(form)[1:-1] for form in forms})


def _compile(forms: Iterable[str], flags: int) -> re.Pattern[str]:
    # Longest first, so that a value which contains another one is replaced as a whole. The alternation tries the
    # values in order, and the lookahead makes the search report a match at every position, also inside an earlier
    # match: overlapping secrets are merged into one span, a plain substitution would leave the tail of the second
    # one visible.
    ordered = sorted(set(forms), key=lambda form: (-len(form), form))
    return re.compile('(?=(' + '|'.join(map(re.escape, ordered)) + '))', flags)


class SecretsMasker:
    """Replaces every form of the secret values with the masked value in any text, for example in a formatted log line.

    The case of the text does not matter: a key is logged upper-case as often as lower-case. New secrets can be added
    later with `add()`, for a service that configures logging before it reads its config.
    """

    def __init__(self, secrets: Mapping[str, object]):
        self._lock = threading.Lock()
        self._forms: frozenset[str] = frozenset()
        # One pattern for ASCII text, matched on the lower-cased text (same offsets, half the cost), and one
        # case-insensitive pattern for text whose lower case may change the offsets.
        self._pattern_ascii: re.Pattern[str] | None = None
        self._pattern: re.Pattern[str] | None = None
        self.add(secrets)

    def add(self, secrets: Mapping[str, object]) -> None:
        """Mask the values of these secrets too, in every line from now on."""
        new_forms = _secret_values(secrets)
        with self._lock:
            forms = self._forms | new_forms
            if forms == self._forms:
                return
            pattern_ascii = _compile((form.lower() for form in forms), 0)
            pattern = _compile(forms, re.IGNORECASE)
            self._forms, self._pattern_ascii, self._pattern = forms, pattern_ascii, pattern

    def __repr__(self) -> str:
        return f'{type(self).__name__}({len(self._forms)} forms)'

    def mask(self, text: str) -> str:
        pattern_ascii, pattern = self._pattern_ascii, self._pattern
        if pattern is None or pattern_ascii is None:
            return text
        matches = pattern_ascii.finditer(text.lower()) if text.isascii() else pattern.finditer(text)

        spans: list[list[int]] = []
        for match in matches:
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
            parts.append(MASKED_VALUE)
            last = end
        parts.append(text[last:])
        return ''.join(parts)
