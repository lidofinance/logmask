# CHANGELOG

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-28

### Added

- `SecretsMasker`: masking of every form of the secret values - raw, stripped, without the trailing slash, hex in any case with and without `0x`, the parts of a URL (host with credentials, path, query, pairs, user name, password, `user:password`, the Basic header), percent-encoded and decoded, base64-encoded, the hex and the `repr()` of its bytes, `repr()` and JSON-escaped up to two layers deep, bytes as text, hex and `repr()`; the items of nested containers and other iterables, the fields of dataclasses and objects and the value behind a `SecretStr`-like object are secrets too; the pattern ignores the case; overlapping values are masked as one span; `add()` takes secrets that are read after logging is configured and keeps working after a failed call.
- `JsonFormatter` with a fixed set of record fields that a message cannot overwrite, `exc_info` for exceptions and bytes, dataclasses and sets serialized. `format()` never raises, and the masked line is always valid JSON.
- `SafeStreamHandler`: a `StreamHandler` whose error report (a broken pipe, a closed stream) does not print the record. Every line the library writes instead of a record starts with `[logmask]`.
- `install_excepthook`: unhandled exceptions of the main thread, of other threads and the unraisable ones go through the logger; a KeyboardInterrupt traceback, the output without a configured logger and a failure of the hook itself are masked too.
- `masked_config`: the startup config dump with masked private values; a list keeps its length and its unset items.
- `setup_logging`: one call that configures the root logger, captures the warnings and installs the hooks; a second call adds to the same masker. The masker is required everywhere; the secrets mapping is required (`{}` for secrets added later).
- `mask_secrets_processor` for structlog, to be placed after the renderer; it raises `TypeError` when it receives an event dict. The package has no runtime dependencies; structlog is used only in the tests.
