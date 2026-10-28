import logging
import sys
import threading
from collections.abc import Iterator

import pytest

KEY = '0x' + 'ab' * 32
RPC = 'https://rpc.example/v3/secret-key-1/'
RPC_2 = 'https://rpc.example/v3/secret-key-2'
CL_URL = 'https://user:secret-pass-3@cl.example/'
TOKEN = 'eyJhbGciOiJIUzI1NiJ9.token-value-4'

# One value of every shape the bots keep in PRIVATE_ENV_VARS: a list of RPC URLs, a hex key,
# a URL with basic auth, a bare token, and the unset ones.
SECRETS: dict[str, object] = {
    'WEB3_RPC_ENDPOINTS': [RPC, RPC_2],
    'WALLET_PRIVATE_KEY': KEY,
    'CONSENSUS_CLIENT_URI': CL_URL,
    'PINATA_JWT': TOKEN,
    'UNSET_TOKEN': None,
    'EMPTY_TOKEN': '',
}

SECRET_FRAGMENTS = ('secret-key', 'secret-pass', 'token-value', KEY)


def make_record(msg: object, level: int = logging.INFO, exc_info: object = None) -> logging.LogRecord:
    return logging.LogRecord('test', level, __file__, 1, msg, None, exc_info)  # type: ignore[arg-type]


def assert_no_secret(text: str) -> None:
    for fragment in SECRET_FRAGMENTS:
        assert fragment not in text, f'{fragment!r} leaked into {text!r}'


@pytest.fixture
def secrets() -> dict[str, object]:
    return dict(SECRETS)


@pytest.fixture
def restore_logging() -> Iterator[None]:
    """Keep the root logger and the exception hooks as they were before the test."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    sys_hook, thread_hook = sys.excepthook, threading.excepthook
    try:
        yield
    finally:
        root.handlers[:] = handlers
        root.setLevel(level)
        sys.excepthook = sys_hook
        threading.excepthook = thread_hook
