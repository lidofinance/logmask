# lido-safe-logging

JSON logging with masked secrets for Python services. One JSON object per line goes to the stream, and every line - including the messages of third-party libraries and the traceback of an unhandled exception - passes through a masker that replaces the configured secret values with `***`.

The library gives you:

- `SecretsMasker` - replaces known secret values in any text, in their raw, stripped, URL and JSON-escaped forms
- `JsonFormatter` - a `logging.Formatter` that writes one JSON object per record and masks the result
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

Options:

```py
setup_logging(
    PRIVATE,
    level='DEBUG',        # int or name, default INFO
    stream=sys.stdout,    # default stderr
    env_heuristic=True,   # also mask the values of env variables with SECRET, TOKEN, PASSWORD, PASS, PRIVATE, CREDENTIALS or KEY in the name
    excepthook=False,     # keep the default exception hooks
)
```

`masked_config(public, private)` builds the dict for the startup log: public values as they are, private values replaced by `***`, a private list keeps its length, an unset private value becomes `''`. A key listed in both mappings raises `ValueError`.

### The pieces, when you need them one by one

```py
from lido_safe_logging import JsonFormatter, SecretsMasker, install_excepthook

masker = SecretsMasker(PRIVATE)
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter(masker))
logging.basicConfig(level=logging.INFO, handlers=[handler])
install_excepthook()
```

`masker.mask(text)` masks any text by hand. `JsonFormatter()` without a masker only formats.

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

After the renderer the processor masks the rendered line, keys and JSON-escaped forms included. Before the renderer it masks the string values of the event dict, nested lists and dicts too. The module does not import structlog: the processor is a plain function with the `(logger, method_name, event_dict)` contract.

## What is masked

For every value of the secrets mapping, and every item of a list value, the masker replaces:

- the value itself and the value without surrounding whitespace (a secret read from a file keeps its trailing newline, the log shows the stripped value)
- the value without a trailing `/`
- for a URL with basic auth (`https://user:password@host/`): the username, the password and `user:password`; the path stays readable, it is an ordinary route
- for a URL without a password: the username (a token in front of `@`), the path, the path without a trailing `/` and the query - HTTP libraries often log only the path or the query, and that is where a provider key lives
- the JSON-escaped form of each of these, because the replacement runs on the JSON line

Strings are taken from plain values, from items of lists, tuples and sets, and from the values of nested dicts.

Values shorter than 8 characters are not masked: they would hide ordinary text such as ports and flags in every line. The limit is the `min_length` argument of `SecretsMasker`. Longer values are replaced first, so a value that contains another one is replaced as a whole.

## What is not masked

- a secret that is not in the mapping: masking is a list of known values, not a search for secret-looking text; keep the mapping complete, or add `env_heuristic=True`
- a value that appears in a transformed form the masker does not know (base64, hex of the bytes, a part of a value shorter than 8 characters)
- numbers and other non-string values in the secrets mapping (a numeric PIN has to be given as a string)
- output written to stdout or stderr without the logger (`print`, a library that writes to the stream)

A record that cannot be formatted (wrong `%` arguments, a value `json` cannot serialize) is still written as one masked JSON line with an `error` field, instead of the unmasked `--- Logging error ---` block the standard library prints to stderr.

## Log format

```json
{"name": "app", "levelname": "INFO", "funcName": "main", "lineno": 29, "module": "main", "pathname": "/app/src/main.py", "timestamp": 1761600000, "msg": "Config", "value": {"RPC_URL": "***", "API_TOKEN": "***"}}
```

- every line has `name`, `levelname`, `funcName`, `lineno`, `module`, `pathname` and `timestamp` (the record time in whole seconds)
- a dict message is merged into the line, a string message becomes `msg`
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
