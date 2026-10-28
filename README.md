# lido-safe-logging

JSON logging for Python services, with secrets masked. Every log line is one JSON object. Every line goes through a masker that replaces your secret values with `***`. This includes the messages of third-party libraries and the traceback of an unhandled exception.

No runtime dependencies. Python 3.12 or newer.

## Install

```bash
poetry add git+https://github.com/lidofinance/lido-safe-logging.git@v0.1.0
```

Pin a tag. A Docker build stage that installs the package from git needs `git`.

## Quick start

```py
import logging

from lido_safe_logging import masked_config, setup_logging

PUBLIC = {'RPC_TIMEOUT': 30, 'DRY_RUN': True}
PRIVATE = {'RPC_URL': 'https://rpc.example.com/v3/a1b2c3d4e5f6', 'API_TOKEN': 'tok_9f8e7d6c5b4a'}

setup_logging(PRIVATE)

logger = logging.getLogger(__name__)
logger.info({'msg': 'Config', 'value': masked_config(PUBLIC, PRIVATE)})
logger.info('Connecting to %s', PRIVATE['RPC_URL'])
```

Output (one line per record, stderr):

```json
{"name": "app", "levelname": "INFO", "funcName": "main", "lineno": 12, "module": "main", "pathname": "/app/main.py", "timestamp": 1761600000, "msg": "Config", "value": {"RPC_TIMEOUT": 30, "DRY_RUN": true, "RPC_URL": "***", "API_TOKEN": "***"}}
{"name": "app", "levelname": "INFO", "funcName": "main", "lineno": 13, "module": "main", "pathname": "/app/main.py", "timestamp": 1761600000, "msg": "Connecting to ***"}
```

`setup_logging(PRIVATE)` does three things:

- configures the root logger: JSON lines to stderr, level INFO, old handlers removed
- masks every line with the values of `PRIVATE`
- installs `sys.excepthook` and `threading.excepthook`, so an unhandled exception becomes one CRITICAL line with a masked traceback

`masked_config(PUBLIC, PRIVATE)` builds a dict for the startup log. Public values stay as they are. Private values become `***`. A private list keeps its length, a private dict keeps its keys. An unset private value (`None` or `''`) becomes `''`, so you can see which variables are set. A key present in both dicts raises `ValueError`.

```py
masked_config({'PORT': 9000}, {'TOKEN': 'abc', 'RPC_URLS': ['a', 'b'], 'OPTIONAL_KEY': None})
# {'PORT': 9000, 'TOKEN': '***', 'RPC_URLS': ['***', '***'], 'OPTIONAL_KEY': ''}
```

## How to

### Log a message

A string message goes to the `msg` field. A dict message is merged into the line, so its keys become fields:

```py
logger.info('Report sent for slot %d', 1234567)
# {..., "msg": "Report sent for slot 1234567"}

logger.info({'msg': 'Report sent', 'slot': 1234567, 'root': b'\x0a\x0b'})
# {..., "msg": "Report sent", "slot": 1234567, "root": "0x0a0b"}
```

### Log an exception

```py
try:
    client.get(url)
except ConnectionError:
    logger.exception('Request failed')
# {..., "levelname": "ERROR", "msg": "Request failed", "exc_info": "Traceback (most recent call last):\n  ...\nConnectionError: Max retries exceeded with url: ***"}
```

### Set the level and the stream

```py
setup_logging(PRIVATE, level=os.getenv('LOG_LEVEL', 'INFO'), stream=sys.stdout)
```

`level` takes a name or an int. `stream` is stderr by default.

### Add secrets later

`setup_logging` returns the masker. Call `add()` when a secret becomes known after logging is configured, for example a token fetched from a vault or a config module that logs at import time:

```py
masker = setup_logging()

from app import config  # logs at import time, before the config is known

masker.add(config.PRIVATE)
```

Every line from that point on is masked with the new values too.

### Keep the default exception hooks

```py
setup_logging(PRIVATE, excepthook=False)
```

### Mask text by hand

```py
masker = setup_logging(PRIVATE)
masker.mask('connect https://rpc.example.com/v3/a1b2c3d4e5f6')
# 'connect ***'
```

### Use structlog

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

Put the processor last, after the renderer. It then masks the whole rendered line. Before the renderer it masks the values of the event dict, including nested lists, tuples, sets and dicts. The package does not depend on structlog: your service installs its own version.

### Use the pieces one by one

```py
import logging

from lido_safe_logging import JsonFormatter, SafeStreamHandler, SecretsMasker, install_excepthook

masker = SecretsMasker(PRIVATE)
handler = SafeStreamHandler(masker=masker)
handler.setFormatter(JsonFormatter(masker))
logging.basicConfig(level=logging.INFO, handlers=[handler])
install_excepthook(masker=masker)
```

- `SecretsMasker(secrets, min_length=8, masked_value='***')` - the masker; `mask(text)` and `add(secrets)`
- `JsonFormatter(masker)` - one JSON object per record, masked; without a masker it only formats
- `SafeStreamHandler(stream, masker=masker)` - a `StreamHandler` that does not print the record when the write fails
- `install_excepthook(masker=masker)` - the exception hooks; the masker covers the output that cannot go through the logger, see below

## What is masked

The examples use this masker:

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

Each value, and each item of a list, tuple, set or nested dict:

```py
masker.mask('connect https://rpc.example.com/v3/a1b2c3d4e5f6/')
# 'connect ***'
masker.mask('rpc https://two.example.com/key/ghijkl789012 failed')
# 'rpc *** failed'
masker.mask('got nested-secret-value')
# 'got ***'
```

The value without spaces and newlines around it, and without a trailing `/`:

```py
masker.mask('token tok_9f8e7d6c5b4a expired')
# 'token *** expired'
masker.mask('connect https://rpc.example.com/v3/a1b2c3d4e5f6')
# 'connect ***'
```

The path and the query of a URL on their own, when they contain something that looks like a key (8 characters or more, with a digit, or 16 characters or more). HTTP libraries often log only the path:

```py
masker.mask("HTTPSConnectionPool(host='rpc.example.com', port=443): Max retries exceeded with url: /v3/a1b2c3d4e5f6")
# "HTTPSConnectionPool(host='rpc.example.com', port=443): Max retries exceeded with url: ***"
masker.mask('project a1b2c3d4e5f6 rate limited')
# 'project *** rate limited'
```

The password and `user:password` of a URL with basic auth. The username too, when it is 8 characters or longer:

```py
masker.mask('GET https://user:s3cretPassw0rd@beacon.example.com/eth/v1/beacon/genesis')
# 'GET ***/beacon/genesis'
masker.mask('auth user:s3cretPassw0rd rejected')
# 'auth *** rejected'
```

Hex values in both cases, with and without `0x`. Bytes as text and as hex:

```py
masker.mask('key 0xabcdef0123456789 or ABCDEF0123456789')
# 'key *** or ***'
masker.mask('raw 0xdeadbeef01020304 DEADBEEF01020304')
# 'raw *** ***'
```

A value shown with `repr()`, inside `str(dict)`, in an exception text or inside a JSON document. Quotes, backslashes and newlines in the secret are not a problem:

```py
password = 'pa"ss\\word\n123'
logger.info('login %r failed with %s', password, json.dumps({'password': password}))
# {..., "msg": "login '***' failed with {\"password\": \"***\"}"}
```

Numbers and other non-string values, by their text:

```py
SecretsMasker({'PIN': 12345678}).mask('pin 12345678')
# 'pin ***'
```

Two secrets that overlap in the text are masked as one:

```py
SecretsMasker({'A': 'abcdefgh', 'B': 'efghijklmnop'}).mask('abcdefghijklmnop')
# '***'
```

## What is not masked

A value that is not in your secrets. The masker replaces known values, it does not search for text that looks like a secret:

```py
masker.mask('other secret zzz-not-configured')
# 'other secret zzz-not-configured'
```

A value shorter than 8 characters (`min_length`). Otherwise ports, flags and short words would disappear from every line:

```py
SecretsMasker({'PORT': '9000'}).mask('listen on 9000')
# 'listen on 9000'
masker.mask('login as user')
# 'login as user'
```

A form of the value the masker does not know, such as base64, or a part of the value:

```py
masker.mask('dG9rXzlmOGU3ZDZjNWI0YQ==')  # base64 of the token
# 'dG9rXzlmOGU3ZDZjNWI0YQ=='
masker.mask('prefix a1b2c3')
# 'prefix a1b2c3'
```

The host of a URL, and a URL path without a key in it. Alerts need them:

```py
masker.mask('host rpc.example.com down')
# 'host rpc.example.com down'
masker.mask('GET /eth/v1/beacon/genesis')
# 'GET /eth/v1/beacon/genesis'
```

Text written to stdout or stderr without the logger: `print`, or a library that writes to the stream directly.

## When logging itself fails

A record that cannot be formatted (wrong `%` arguments, a value `json` cannot serialize) is still written as one masked JSON line, with the problem in the `error` field:

```py
logger.info('rpc %d %s', 'https://rpc.example.com/v3/a1b2c3d4e5f6', 'x')
# {..., "msg": "rpc %d %s", "error": "Log record could not be formatted: TypeError('%d format: a real number is required, not str')", "args": "('***', 'x')"}
```

The standard library would print this instead, to stderr and without masking:

```text
--- Logging error ---
Traceback (most recent call last):
  ...
TypeError: %d format: a real number is required, not str
Message: 'rpc %d %s'
Arguments: ('https://rpc.example.com/v3/a1b2c3d4e5f6', 'x')
```

A record that cannot be written (the stream is closed, the pipe is broken) is reported by `SafeStreamHandler` without the record. The standard handler prints the same `Message:` and `Arguments:` lines as above:

```text
--- Logging error: BrokenPipeError(32, 'Broken pipe') (record from app, /app/main.py:31) ---
```

An unhandled exception goes through the logger as a CRITICAL line:

```py
raise ConnectionError(f'Max retries exceeded with url: {RPC_URL}')
# {"name": "unhandled", "levelname": "CRITICAL", ..., "msg": "Unhandled exception. Shut down.", "error": "Traceback (most recent call last):\n  ...\nConnectionError: Max retries exceeded with url: ***\n"}
```

Two cases cannot go through the logger and are written to stderr as plain text, masked: a `KeyboardInterrupt` (Ctrl-C is not an error, so there is no CRITICAL line) and an exception when no handler is configured.

## Log format

Every line has these fields, in this order:

```json
{"name": "app", "levelname": "INFO", "funcName": "main", "lineno": 29, "module": "main", "pathname": "/app/main.py", "timestamp": 1761600000, "msg": "Config", "value": {"RPC_URL": "***"}}
```

- `name`, `levelname`, `funcName`, `lineno`, `module`, `pathname` - from the log record
- `timestamp` - the record time in whole seconds
- `msg` - the string message; a dict message adds its keys after `timestamp` instead. A dict key with the name of a record field (for example `name`) is written as `msg_name`
- `exc_info` - the traceback, for `logger.exception()` and `exc_info=True`
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
