# logmask

JSON logging for Python services, with secrets masked. Every log line is one JSON object. Every line goes through a masker that replaces every form of your secret values with `***`. This includes the messages of third-party libraries, warnings, and the traceback of an unhandled exception.

No runtime dependencies. Python 3.12 or newer.

## Install

The package is on PyPI as [`logmask`](https://pypi.org/project/logmask/):

```bash
poetry add logmask
pip install logmask
```

The versions and their changes are in `CHANGELOG.md`.

A commit that is not released yet can be installed from the repository; a build stage that installs this way needs `git`:

```bash
poetry add "git+https://github.com/lidofinance/logmask.git@<commit or tag>"
```

## Quick start

```py
import logging

from logmask import masked_config, setup_logging

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

`setup_logging(PRIVATE)` does four things:

- configures the root logger: JSON lines to stderr, level INFO, old handlers removed
- masks every line with every form of the values of `PRIVATE`
- routes `warnings.warn()` through the logger, so a warning text is masked too
- installs `sys.excepthook`, `threading.excepthook` and `sys.unraisablehook`, so an unhandled exception becomes one CRITICAL line with a masked traceback

`masked_config(PUBLIC, PRIVATE)` builds a dict for the startup log. Public values stay as they are. Private values become `***`. A private list keeps its length. An unset private value (`None`, `''` or `b''`) becomes `''`, so you can see which variables are set; any other value, `0` and `False` included, is set and shows `***`. A key present in both dicts raises `ValueError`, and a private value of a type the masker cannot search raises `TypeError` (see "What is masked").

```py
masked_config({'PORT': 9000}, {'TOKEN': 'abc', 'RPC_URLS': ['a', 'b'], 'OPTIONAL_KEY': None})
# {'PORT': 9000, 'TOKEN': '***', 'RPC_URLS': ['***', '***'], 'OPTIONAL_KEY': ''}
```

Every value of `PRIVATE` is treated as a secret, whatever it looks like (`None` and booleans are not values). Put a variable there only when its value must never appear in a log: a value such as `true` or `9000` in `PRIVATE` would be masked inside every line, field names included. A realistic set of secrets (about 20 variables, about 100 forms) costs about 50 microseconds per line; hundreds of secrets make every line noticeably slower.

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

`level` takes a name in any case or an int. `stream` is stderr by default. Three outputs always go to stderr: the traceback of a KeyboardInterrupt, the report of a handler that cannot write, and the line written when the exception hook itself fails.

### Add secrets later

`setup_logging` returns the masker. Pass `{}` and call `add()` when a secret becomes known after logging is configured, for example a token fetched from a vault or a config module that logs at import time:

```py
masker = setup_logging({})

from app import config  # logs at import time, before the config is known

masker.add(config.PRIVATE)
```

Every line from that point on is masked with the new values too. The lines written before `add()` are not. A second `setup_logging` call in the same process adds its secrets to the same masker, so the secrets of the first call stay masked.

### Mask text by hand

```py
masker = setup_logging(PRIVATE)
masker.mask('connect https://rpc.example.com/v3/a1b2c3d4e5f6')
# 'connect ***'
```

### Use structlog

Call `setup_logging` as well: structlog does not route the standard-library loggers of `web3`, `urllib3` or `requests` anywhere, and without a configured root logger their warnings go to stderr unmasked.

```py
import structlog

from logmask import mask_secrets_processor, setup_logging

masker = setup_logging(PRIVATE)
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt='iso'),
        structlog.processors.JSONRenderer(),
        mask_secrets_processor(masker),  # last: masks the rendered line
    ],
)
```

The processor must be the last one, after the renderer: it masks the rendered line, keys and JSON-escaped forms included. Placed earlier it receives the event dict and raises `TypeError` at the first event that reaches the processors, which with a filtering logger is the first event at or above the configured level, not the first call. Do not render tracebacks with `structlog.processors.dict_tracebacks` in its default form: it prints the local variables of every frame cut to 80 characters, and a cut secret is a part that no form matches. Use `format_exc_info`, or `ExceptionRenderer(ExceptionDictTransformer(show_locals=False))`. The package does not depend on structlog: your service installs its own version.

### Use the pieces one by one

`setup_logging` wires these classes; they can be used directly, and each of them requires the masker:

- `SecretsMasker(secrets)` - the masker; `mask(text)` and `add(secrets)`
- `JsonFormatter(masker)` - one JSON object per record, masked
- `SafeStreamHandler(stream, masker=masker)` - a `StreamHandler` that does not print the record when the write fails
- `install_excepthook(masker=masker)` - the three exception hooks; the masker covers the output that cannot go through the logger

## What is masked

The examples use this masker:

```py
masker = SecretsMasker(
    {
        'RPC_URL': 'https://rpc.example.com/v3/a1b2c3d4e5f6/',
        'CL_URL': 'https://user:s3cretPassw0rd@beacon.example.com/',
        'API_TOKEN': 'tok_9f8e7d6c5b4a\n',  # read from a file, with the trailing newline
        'RPC_LIST': ['https://one.example.com/key/abcdef123456', 'https://two.example.com/key/ghijkl789012'],
        'KEYS': {'nested-secret-key': 'nested-secret-value'},
        'PRIVATE_KEY': '0xABCDEF0123456789',
        'RAW_KEY': b'\xde\xad\xbe\xef\x01\x02\x03\x04',
    }
)
```

Each value, each item of a list, tuple, set or any other iterable, the keys and the values of a nested dict (only the top-level keys are the variable names, they stay), the fields of a dataclass, the value behind a `SecretStr`-like object (`get_secret_value()`), numbers and paths by their text:

```py
masker.mask('connect https://rpc.example.com/v3/a1b2c3d4e5f6/')
# 'connect ***'
masker.mask('rpc https://two.example.com/key/ghijkl789012 failed')
# 'rpc *** failed'
masker.mask('KEYS nested-secret-key nested-secret-value')
# 'KEYS *** ***'
```

A value of any other type (a plain object, a function, a module, a class) raises `TypeError` in `setup_logging`, `SecretsMasker`, `add()` and `masked_config`: the masker cannot promise to find every secret inside it, so it refuses the value instead of masking a part. Pass the data of such an object as a dict.

The values held by one string: a JSON document is searched as the container it encodes (a list of URLs, the JSON of a service account with its `private_key`), several URLs separated by commas, semicolons or white space are searched one by one, and every line of a multi-line value (a PEM key) is a secret on its own:

```py
masker = SecretsMasker({'RPC_LIST': 'https://one.example.com/key/abcdef123456,https://two.example.com/key/ghijkl789012'})
masker.mask('rpc https://one.example.com/key/abcdef123456 failed, path /key/abcdef123456')
# 'rpc *** failed, path ***'
masker = SecretsMasker(
    {'ACCOUNT': '{"type": "service_account", "private_key": "-----BEGIN KEY-----\\nMIIEvQIBADANBg\\n-----END KEY-----"}'}
)
masker.mask('key MIIEvQIBADANBg of type service_account')
# 'key *** of *** ***'
```

The value without spaces and newlines around it, and without a trailing `/`:

```py
masker.mask('token tok_9f8e7d6c5b4a expired')
# 'token *** expired'
masker.mask('connect https://rpc.example.com/v3/a1b2c3d4e5f6')
# 'connect ***'
```

The parts of a URL on their own: the host with its credentials, the path, the path with the query, the query, each `name=value` pair, the user name, the password and `user:password`, percent-decoded as well, and the credentials as an HTTP Basic header. HTTP libraries often log only the path:

```py
masker.mask("HTTPSConnectionPool(host='rpc.example.com', port=443): Max retries exceeded with url: /v3/a1b2c3d4e5f6")
# "HTTPSConnectionPool(host='rpc.example.com', port=443): Max retries exceeded with url: ***"
masker.mask('GET https://user:s3cretPassw0rd@beacon.example.com/eth/v1/beacon/genesis')
# 'GET ***eth/v1/beacon/genesis'
masker.mask('auth user:s3cretPassw0rd rejected, header Basic dXNlcjpzM2NyZXRQYXNzdzByZA==')
# 'auth *** rejected, header Basic ***'
```

A single segment of the path, a single query value and the host without its credentials, when they can be a key: 16 characters or more, or 8 or more with a digit. A short word of a URL (`eth`, `v1`, a host like `el`) is masked only as part of the whole path or URL, otherwise it would vanish from every line:

```py
masker.mask('project a1b2c3d4e5f6 rate limited, host beacon.example.com')
# 'project *** rate limited, host ***'
masker.mask('GET /eth/v1/beacon/genesis from rpc.example.com')
# 'GET /eth/v1/beacon/genesis from rpc.example.com'
```

Hex values in any case, with and without `0x`, and as the bytes they encode. Bytes as text, as hex and as their `repr()`:

```py
masker.mask('key 0xabcdef0123456789 or ABCDEF0123456789 or 0XABCDEF0123456789')
# 'key *** or *** or ***'
masker.mask("raw 0xdeadbeef01020304 DEADBEEF01020304 b'\\xde\\xad\\xbe\\xef\\x01\\x02\\x03\\x04'")
# "raw *** *** b'***'"
masker.mask(repr(bytes.fromhex('ABCDEF0123456789')))
# "b'***'"
```

The value percent-encoded (with `quote` and with `quote_plus`), percent-decoded, base64-encoded, and as the hex or the `repr()` of its bytes, as an application writes it into a URL, a header or a bytes body:

```py
SecretsMasker({'T': 'tok/en+value=1'}).mask('k=tok%2Fen%2Bvalue%3D1 auth dG9rL2VuK3ZhbHVlPTE= body 0x746f6b2f656e2b76616c75653d31')
# 'k=*** auth *** body 0x***'
```

A value shown with `repr()`, inside `str(dict)`, in an exception text or inside a JSON document, up to two layers deep (for example the `repr()` of a JSON document). Quotes, backslashes and newlines in the secret are not a problem, and a secret made of JSON syntax (a quote, a brace, `true`) is masked inside the strings of the line, so the line stays valid JSON:

```py
password = 'pa"ss\\word\n123'
masker.add({'PASSWORD': password})
logger.info('login %r failed with %s', password, json.dumps({'password': password}))
# {..., "msg": "login '***' failed with {\"password\": \"***\"}"}
```

The case of the text does not matter:

```py
masker.mask('TOK_9F8E7D6C5B4A')
# '***'
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

A form of the value the masker does not know: a part of the value, a hash of it, more than two layers of escaping:

```py
masker.mask('prefix a1b2c3')
# 'prefix a1b2c3'
```

A short word of a URL on its own (see above).

A password re-encoded by an HTTP library with its own set of safe characters. The masker knows the password raw, percent-decoded and in the three encodings of `urllib.parse` (`quote` with and without the default safe characters, `quote_plus`). yarl, used by aiohttp, keeps `+ ! & =` raw and encodes the rest, so `p%40ss+x!y` is a form the masker does not know, and only the user name and the host of such a URL are masked. A per-character pattern for the credentials (each character raw or percent-encoded) is planned; until then, prefer a password without characters that need encoding.

Text that does not pass through the handler installed by `setup_logging`:

- `print`, a library that writes to the stream directly, and the message of `sys.exit('...')`, which the interpreter prints without calling the exception hook
- a logger with its own handler that does not propagate to the root logger (a logger without any handler that does not propagate goes to `logging.lastResort`, which `setup_logging` replaces by a masked handler)
- a handler added to the root logger after `setup_logging` (a `FileHandler`, the handler of an error tracker), and a `logging.config.dictConfig` call after it: they format the record themselves
- a child process of `multiprocessing`: with the `fork` start method, an exception in the child is printed by `multiprocessing` itself, without the hooks; with `spawn`, the child starts without `setup_logging` unless its module calls it

## When logging itself fails

A record that cannot be formatted (wrong `%` arguments, a value `json` cannot serialize, a dict message nested deeper than the recursion limit) is still written as one masked JSON line, with the problem in the `error` field. Every line the library writes on its own behalf, instead of the record, starts with `[logmask]`:

```py
logger.info('rpc %d %s', 'https://rpc.example.com/v3/a1b2c3d4e5f6', 'x')
# {..., "msg": "rpc %d %s", "error": "[logmask] Log record could not be formatted: TypeError('%d format: a real number is required, not str')", "args": "('***', 'x')"}
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

A record that cannot be written (the stream is closed, the pipe is broken) is reported by `SafeStreamHandler` without the record, where the standard handler would print the same `Message:` and `Arguments:` lines as above:

```text
--- [logmask] Logging error: BrokenPipeError(32, 'Broken pipe') (record from app, /app/main.py:31) ---
```

An unhandled exception goes through the logger as a CRITICAL line:

```py
raise ConnectionError(f'Max retries exceeded with url: {RPC_URL}')
# {"name": "unhandled", "levelname": "CRITICAL", ..., "msg": "Unhandled exception. Shut down.", "error": "Traceback (most recent call last):\n  ...\nConnectionError: Max retries exceeded with url: ***\n"}
```

An exception in another thread gives the same line with `"msg": "Unhandled exception in a thread."` and a `thread` field; the process goes on, as with the default hook. An exception in `__del__` or in a callback (`sys.unraisablehook`) gives `"msg": "Unraisable exception."`.

Three cases cannot go through the logger and are written to stderr masked: a `KeyboardInterrupt` (Ctrl-C is not an error, so there is no CRITICAL line, the traceback is printed as plain text), an exception when no handler is configured (one JSON line written by the hook itself), and a failure of the hook (one line with the exception name).

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
poetry run ruff format --check . && poetry run ruff check . && poetry run pyright logmask tests
poetry run pytest
```

Mutation tests check that the suite notices a weaker masker. They run in CI on every push and pull request; locally:

```bash
poetry run pip install "mutmut==3.8.1"
poetry run mutmut run
poetry run mutmut results           # the survivors
poetry run mutmut show <mutant>     # the diff of one survivor
```

About 50 mutants survive by design (the spelling of `utf-8`, the wording of messages, the references kept by the cycle guard); CI fails above that number.

## Release

1. Set the version in `pyproject.toml` and move the `Unreleased` section of `CHANGELOG.md` under the version and the date.
2. Merge to `main` and publish a GitHub release with the tag `vX.Y.Z` on that commit. The `Publish` workflow builds the package and uploads it to PyPI through trusted publishing (no API token in the repository); it refuses a tag that does not match the version in `pyproject.toml`.
3. Consumers update the version in their `pyproject.toml` and run `poetry lock`.
