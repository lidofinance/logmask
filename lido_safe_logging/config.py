from collections.abc import Mapping
from typing import Any

from .secrets import MASKED_VALUE


def masked_config(public: Mapping[str, Any], private: Mapping[str, Any]) -> dict[str, Any]:
    """The config for the startup log: public values as they are, private values replaced by the placeholder.

    A private list keeps its length, and an unset private value (None or an empty string) becomes an empty string, so
    the log shows which variables are set without reading their values. Any other value, `0` and `False` included, is
    set and shows the placeholder. A variable in both mappings is an error.
    """
    overlap = sorted(set(public) & set(private))
    if overlap:
        raise ValueError(f'Variables listed as both public and private: {overlap}')

    return {**public, **{key: _mask(value) for key, value in private.items()}}


def _mask(value: Any) -> Any:
    if value is None or (isinstance(value, str | bytes) and not value):
        return ''
    if isinstance(value, list | tuple):
        return [_mask(item) for item in value]
    return MASKED_VALUE
