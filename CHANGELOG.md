# CHANGELOG

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-28

### Added

- `SecretsMasker` and `secret_values`: masking of the secret values in their raw, stripped, hex, URL, repr and JSON-escaped forms; bytes and numbers are secrets too; overlapping values are masked as one span; `add()` takes secrets that are read after logging is configured.
- `secrets_from_env`: values of the env variables with SECRET, TOKEN, PASSWORD, PASS, PRIVATE, CREDENTIALS or KEY as a word in the name.
- `JsonFormatter` with a fixed set of record fields that a message cannot overwrite, `exc_info` for exceptions and `json_default` for bytes, dataclasses and sets. `format()` never raises.
- `SafeStreamHandler`: a `StreamHandler` whose error report (a broken pipe, a closed stream) does not print the record.
- `install_excepthook` and `log_unhandled_exception`: unhandled exceptions of the main thread and of other threads go through the logger; a KeyboardInterrupt traceback and the output without a configured logger are masked too.
- `masked_config`: the startup config dump with masked private values.
- `setup_logging`: one call that configures the root logger and the hooks.
- `mask_secrets_processor` for structlog. The package has no runtime dependencies; structlog is used only in the tests.
