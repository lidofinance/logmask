# CHANGELOG

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2026-10-29

### Changed

- The wheel and the sdist on PyPI carry PEP 740 attestations: they are signed through Sigstore by the `Publish` workflow of this repository, so PyPI shows the provenance of every file and `pypi-attestations verify pypi` checks that it was built by that workflow from a tagged commit. The library code is the same as in 0.1.4.

## [0.1.4] - 2026-10-29

### Fixed

- A password used in an HTTP Basic header was masked only when `user:` happened to be a multiple of 3 bytes: base64 encodes 3-byte groups, so the same password has three encodings depending on its offset. The base64 forms of a secret are now derived at every offset, for the standard and the URL-safe alphabets.
- A multi-line value stored with the two characters `\n` between the lines (a PEM key in an environment variable) was split into lines only on real newlines, so one line of the key logged on its own was written in clear. The literal `\n` and `\r\n` sequences split the value too.

### Changed

- A one-shot iterator as a private value (a generator, `map()`, an open file) raises `TypeError`. Before, the first pass consumed it: `masked_config` followed by `setup_logging` with the same mapping masked nothing from it, without an error.
- A private value with non-ASCII characters raises `TypeError`: the JSON line writes such text as `\uXXXX` escapes, which have one case only, so the value was masked only in the case it was set in. Non-ASCII secrets are not supported.

## [0.1.3] - 2026-10-29

### Fixed

- A string holding several URLs (`url1,url2`, `url1 url2`, a JSON list) was parsed as one URL, so every URL but the last one was masked only as a whole, not by its parts: `connect url1` and the path of `url1` were written in clear. A JSON document in a string (a list, the JSON of a service account) is now searched as the container it encodes, several URLs in one string are searched one by one, and every line of a multi-line value (a PEM key) is a secret on its own.
- A dict message nested deeper than the recursion limit, in a process with a secret that breaks the JSON syntax of the line (a number, a quote), raised `RecursionError` out of `logger.info()`. Such a record becomes a flat masked line with the error.
- A logger that does not propagate and has no handler went to `logging.lastResort`, which wrote the raw message to stderr. `setup_logging` replaces it by a masked JSON handler on the same stream.

### Changed

- The keys of a nested mapping are secrets too, like its values: a private mapping may be keyed by the secret itself. The top-level keys stay the variable names.
- A private value of a type the masker cannot search (a plain object, a function, a module, a class) raises `TypeError` in `SecretsMasker`, `add()`, `setup_logging` and `masked_config`, with the list of the supported types. Before, an object was searched through its `__dict__`, which does not see slots, properties or closures, and a function or a module was accepted with no secret found.
- README: the list of outputs that do not pass through the handler (handlers added later, `dictConfig`, `multiprocessing` children, `print`, `sys.exit`), and the known gap for a password re-encoded by yarl.

## [0.1.2] - 2026-10-28

### Fixed

- Every `add()` left the previous compiled pattern, with the text of the secrets, in the cache of the `re` module for the life of the process: about 1 MiB per call, so a service that rotates a token many times kept hundreds of MiB, and the secrets outlived the masker. The cache is now dropped after each compilation.

## [0.1.1] - 2026-10-28

### Fixed

- A number equal to a secret in a dict message (a PIN logged as an int) was written in clear: the line-level mask broke the JSON syntax and the fallback masked only the strings. The fallback now masks numbers by their text too.

### Added

- Property tests on random secrets, tests of the rule boundaries, of the hooks and of a real structlog chain; mutation tests in CI (mutmut, at most 50 known equivalent survivors).

## [0.1.0] - 2026-10-28

### Added

- `SecretsMasker`: masking of every form of the secret values - raw, stripped, without the trailing slash, hex in any case with and without `0x`, the parts of a URL (host with credentials, path, query, pairs, user name, password, `user:password`, the Basic header), percent-encoded and decoded, base64-encoded, the hex and the `repr()` of its bytes, `repr()` and JSON-escaped up to two layers deep, bytes as text, hex and `repr()`; the items of nested containers and other iterables, the fields of dataclasses and objects and the value behind a `SecretStr`-like object are secrets too; the pattern ignores the case; overlapping values are masked as one span; `add()` takes secrets that are read after logging is configured and keeps working after a failed call.
- `JsonFormatter` with a fixed set of record fields that a message cannot overwrite, `exc_info` for exceptions and bytes, dataclasses and sets serialized. `format()` never raises, and the masked line is always valid JSON.
- `SafeStreamHandler`: a `StreamHandler` whose error report (a broken pipe, a closed stream) does not print the record. Every line the library writes instead of a record starts with `[logmask]`.
- `install_excepthook`: unhandled exceptions of the main thread, of other threads and the unraisable ones go through the logger; a KeyboardInterrupt traceback, the output without a configured logger and a failure of the hook itself are masked too.
- `masked_config`: the startup config dump with masked private values; a list keeps its length and its unset items.
- `setup_logging`: one call that configures the root logger, captures the warnings and installs the hooks; a second call adds to the same masker. The masker is required everywhere; the secrets mapping is required (`{}` for secrets added later).
- `mask_secrets_processor` for structlog, to be placed after the renderer; it raises `TypeError` when it receives an event dict. The package has no runtime dependencies; structlog is used only in the tests.
