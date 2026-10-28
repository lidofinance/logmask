# lido-safe-logging

JSON logging with masked secrets for Python services. One JSON object per line goes to the stream, and every line - including the messages of third-party libraries and the traceback of an unhandled exception - passes through a masker that replaces the configured secret values with `***`.

The library gives you:

- `SecretsMasker` - replaces known secret values in any text, in their raw, stripped, hex, URL, repr and JSON-escaped forms; takes more secrets later with `add()`
- `JsonFormatter` - a `logging.Formatter` that writes one JSON object per record and masks the result; it never raises
- `SafeStreamHandler` - a `logging.StreamHandler` whose error report (a broken pipe, a closed stream) does not print the record
- `install_excepthook` - sends unhandled exceptions of the main thread and of other threads through the logger
- `masked_config` - builds a config dict for the startup log without reading the private values
- `setup_logging` - one call that wires all of the above into the root logger
- `mask_secrets_processor` - the same masking as a structlog processor (structlog is not a dependency of this package, your service brings its own)

No runtime dependencies, by design: the package installs nothing besides itself, and a test plus a CI check keep it that way. Python 3.12 or newer.

## Install

Pin a tag:

```bash
poetry add git+https://github.com/lidofinance/lido-safe-logging.git@v0.1.0
```

A Docker build stage that installs the package from git needs `git`.

## Usage

### Standard `logging`

```py
import logging

from lido_safe_logging import masked_config, setup_logging

PUBLIC = {'RPC_TIMEOUT': 30, 'DRY_RUN': True}
PRIVATE = {'RPC_URL': 'https://user:password@rpc.example.com/v1', 'API_TOKEN': 'abcdef0123456789'}

setup_logging(PRIVATE)

logger = logging.getLogger(__name__)
logger.info({'msg': 'Config', 'value': masked_config(PUBLIC, PRIVATE)})
```

`setup_logging` configures the root logger (JSON lines to stderr, level INFO), replaces the handlers that were there, and installs `sys.excepthook` and `threading.excepthook`, so that an unhandled exception is logged as one CRITICAL line with the masked traceback. It returns the `SecretsMasker` it built.

A service that reads its config after it has configured logging (a module that logs at import time, a secret fetched from a vault) adds the values when it has them. Every line from that moment on is masked with them too:

```py
masker = setup_logging()
...
masker.add({'VAULT_TOKEN': token})
```

Options:

```py
setup_logging(
    PRIVATE,
    level='DEBUG',  # int or name, default INFO
    stream=sys.stdout,  # default stderr
    env_heuristic=True,  # also mask the values of env variables with SECRET, TOKEN, PASSWORD, PASS, PRIVATE, CREDENTIALS or KEY as a word in the name
    excepthook=False,  # keep the default exception hooks
)
```

`masked_config(public, private)` builds the dict for the startup log: public values as they are, private values replaced by `***`, a private list keeps its length, a private dict keeps its keys, an unset private value (`None` or empty) becomes `''`. `0` and `False` are set values and show `***`. A key listed in both mappings raises `ValueError`.

### The pieces, when you need them one by one

```py
from lido_safe_logging import JsonFormatter, SafeStreamHandler, SecretsMasker, install_excepthook

masker = SecretsMasker(PRIVATE)
handler = SafeStreamHandler(masker=masker)
handler.setFormatter(JsonFormatter(masker))
logging.basicConfig(level=logging.INFO, handlers=[handler])
install_excepthook(masker=masker)
```

`masker.mask(text)` masks any text by hand. `JsonFormatter()` without a masker only formats. `install_excepthook` uses its masker for the output that cannot go through the logger: a KeyboardInterrupt traceback, or any exception when no handler is configured.

### structlog

```py
import structlog

from lido_safe_logging import SecretsMasker, mask_secrets_processor

masker = SecretsMasker(PRIVATE)
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt='iso'),
        structlog.processors.JSONRenderer(),
        mask_secrets_processor(masker),  # last: masks the rendered line
    ],
)
```

After the renderer the processor masks the rendered line, keys and JSON-escaped forms included. Before the renderer it masks the string values of the event dict, nested lists, tuples, sets and dicts too. The module does not import structlog: the processor is a plain function with the `(logger, method_name, event_dict)` contract.

## What is masked

The examples below use this masker:

```py
masker = SecretsMasker(
    {
        'RPC_URL': 'https://rpc.example.com/v3/a1b2c3d4e5f6/',
        'CL_URL': 'https://user:s3cretPassw0rd@beacon.example.com/eth/v1',
        'API_TOKEN': 'tok_9f8e7d6c5b4a\n',  # read from a file, with the trailing newline
        'RPC_LIST': ['https://one.example.com/key/abcdef123456', 'https://two.example.com/key/ghijkl789012'],
        'NESTED': {'inner': {'token': 'nested-secret-value'}},
        'PRIVATE_KEY': '0xABCDEF0123456789',
        'RAW_KEY': b'\xde\xad\xbe\xef\x01\x02\x03\x04',
    }
)
```

The value itself, and every item of a list, tuple, set or nested dict:

```py
masker.mask('connect https://rpc.example.com/v3/a1b2c3d4e5f6/')
# 'connect ***'
masker.mask('rpc https://two.example.com/key/ghijkl789012 failed')
# 'rpc *** failed'
masker.mask('got nested-secret-value')
# 'got ***'
```

The value without surrounding whitespace and without a trailing `/`, so a secret read from a file with a trailing newline, or a URL configured with a slash at the end, is still caught when the log shows it the other way:

```py
masker.mask('token tok_9f8e7d6c5b4a expired')
# 'token *** expired'
masker.mask('connect https://rpc.example.com/v3/a1b2c3d4e5f6')
# 'connect ***'
```

The path and the query of a URL on their own, and every segment or query value that looks like a key: 8 characters or more and not a plain word (it has a digit, or it is 16 characters or longer). HTTP libraries often log only the path, and that is where a provider key lives. The host stays readable:

```py
masker.mask("HTTPSConnectionPool(host='rpc.example.com', port=443): Max retries exceeded with url: /v3/a1b2c3d4e5f6")
# "HTTPSConnectionPool(host='rpc.example.com', port=443): Max retries exceeded with url: ***"
masker.mask('project a1b2c3d4e5f6 rate limited')
# 'project *** rate limited'
```

For a URL with basic auth: the whole URL, the password, `user:password`, and the username when it is 8 characters or longer. A route-like path (`/eth/v1`, no key-like segment) is not a secret, so a request path after the configured URL stays readable:

```py
masker.mask('GET https://user:s3cretPassw0rd@beacon.example.com/eth/v1/beacon/genesis')
# 'GET ***/beacon/genesis'
masker.mask('auth user:s3cretPassw0rd rejected')
# 'auth *** rejected'
```

A hex value with or without the `0x` prefix, in lower or upper case, and bytes as text and as hex. Bytes logged through `JsonFormatter` come out as lower-case `0x`-hex, a configured key may be upper-case:

```py
masker.mask('key 0xabcdef0123456789 or ABCDEF0123456789')
# 'key *** or ***'
masker.mask('raw 0xdeadbeef01020304 DEADBEEF01020304')
# 'raw *** ***'
```

The `repr()` and the JSON form of each value, and the JSON-escaped form of all of them, because the replacement runs on the formatted JSON line. A password with a quote, a backslash or a newline in it is masked when a message shows it with `%r`, as part of `str(dict)` or an exception text, or inside a JSON document:

```py
formatter = JsonFormatter(SecretsMasker({'PASSWORD': 'pa"ss\\word\n123'}))
logger.info('login %r failed with %s', 'pa"ss\\word\n123', json.dumps({'password': 'pa"ss\\word\n123'}))
# {"name": "app", ..., "msg": "login '***' failed with {\"password\": \"***\"}"}
```

Overlapping values are masked as one span, nothing of the second one stays visible:

```py
SecretsMasker({'A': 'abcdefgh', 'B': 'efghijklmnop'}).mask('abcdefghijklmnop')
# '***'
```

Numbers and other non-string values in the mapping, by their text:

```py
SecretsMasker({'PIN': 12345678}).mask('pin 12345678')
# 'pin ***'
```

Longer values are replaced first, so a value that contains another one is replaced as a whole. The limit for a value is `min_length` of `SecretsMasker`, 8 characters by default.

## What is not masked

A value that is not in the mapping. Masking is a list of known values, not a search for secret-looking text:

```py
masker.mask('other secret zzz-not-configured')
# 'other secret zzz-not-configured'
```

Keep the mapping complete, or add `env_heuristic=True` to `setup_logging` so that the values of env variables with SECRET, TOKEN, PASSWORD, PASS, PRIVATE, CREDENTIALS or KEY as a word in the name are added. A marker inside a longer word does not count, `KEYS_API_URL` is a public URL:

```py
secrets_from_env({'API_TOKEN': 'abc', 'KEYS_API_URL': 'http://x', 'DB_PASS': 'p', 'COMPASS_URL': 'http://c'})
# {'API_TOKEN': 'abc', 'DB_PASS': 'p'}
```

A value shorter than 8 characters, the username `user` of the basic auth URL above included. It would hide ordinary text such as ports and flags in every line:

```py
SecretsMasker({'PORT': '9000'}).mask('listen on 9000')
# 'listen on 9000'
masker.mask('login as user')
# 'login as user'
```

A transformed form the masker does not know: base64, or a part of a value shorter than 8 characters:

```py
masker.mask('dG9rXzlmOGU3ZDZjNWI0YQ==')  # base64 of the token
# 'dG9rXzlmOGU3ZDZjNWI0YQ=='
masker.mask('prefix a1b2c3')
# 'prefix a1b2c3'
```

The host of a URL, and a route-like path of a URL. They are not secrets, and alerts need them:

```py
masker.mask('host rpc.example.com down')
# 'host rpc.example.com down'
masker.mask('GET /eth/v1/beacon/genesis')
# 'GET /eth/v1/beacon/genesis'
```

Output written to stdout or stderr without the logger: `print`, or a library that writes to the stream directly.

A record that cannot be formatted (wrong `%` arguments, a value `json` cannot serialize) is still written as one masked JSON line with an `error` field, instead of the unmasked `--- Logging error ---` block the standard library prints to stderr:

```py
logger.info('rpc %d %s', 'https://rpc.example.com/v3/a1b2c3d4e5f6', 'x')
# {"name": "app", ..., "msg": "rpc %d %s", "error": "Log record could not be formatted: TypeError('%d format: a real number is required, not str')", "args": "('***', 'x')"}
```

A record that cannot be written (the stream is closed, the pipe is broken) is reported by `SafeStreamHandler` with the error and the record location only; the standard handler would print the raw message and arguments.

## Log format

```json
{"name": "app", "levelname": "INFO", "funcName": "main", "lineno": 29, "module": "main", "pathname": "/app/src/main.py", "timestamp": 1761600000, "msg": "Config", "value": {"RPC_URL": "***", "API_TOKEN": "***"}}
```

- every line has `name`, `levelname`, `funcName`, `lineno`, `module`, `pathname` and `timestamp` (the record time in whole seconds)
- a dict message is merged into the line, a string message becomes `msg`; a message key with the name of a record field is written as `msg_<key>`, the record field wins
- `exc_info` with the traceback is added for `logger.exception()` and `exc_info=True`
- bytes are written as `0x`-hex, dataclasses as dicts, sets as lists, other unknown values as text

## Development

```bash
poetry install
poetry run ruff format --check . && poetry run ruff check . && poetry run pyright lido_safe_logging tests
poetry run pytest
```

## Release

1. Set the version in `pyproject.toml` and add a section to `CHANGELOG.md`.
2. Merge to `main` and create the tag `vX.Y.Z`.
3. Consumers update the tag in their `pyproject.toml`.
