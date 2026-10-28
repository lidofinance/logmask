import pytest

from lido_safe_logging.config import masked_config
from lido_safe_logging.secrets import MASKED_VALUE
from tests.conftest import SECRETS, assert_no_secret

PUBLIC = {'LIDO_LOCATOR': '0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb', 'PROMETHEUS_PORT': 9000, 'DRY_RUN': False}


def test_masked_config_has_no_private_value_and_keeps_list_length():
    config = masked_config(PUBLIC, SECRETS)

    assert_no_secret(repr(config))
    assert config['WEB3_RPC_ENDPOINTS'] == [MASKED_VALUE, MASKED_VALUE]
    assert config['WALLET_PRIVATE_KEY'] == MASKED_VALUE
    assert config['CONSENSUS_CLIENT_URI'] == MASKED_VALUE
    assert config['PINATA_JWT'] == MASKED_VALUE


def test_masked_config_keeps_public_values_and_marks_unset_private_ones_empty():
    config = masked_config(PUBLIC, SECRETS)

    assert config['LIDO_LOCATOR'] == PUBLIC['LIDO_LOCATOR']
    assert config['PROMETHEUS_PORT'] == 9000
    assert config['DRY_RUN'] is False
    assert config['UNSET_TOKEN'] == ''
    assert config['EMPTY_TOKEN'] == ''
    assert list(config) == list(PUBLIC) + list(SECRETS)


def test_masked_config_rejects_overlapping_keys():
    with pytest.raises(ValueError, match='WALLET_PRIVATE_KEY'):
        masked_config({'WALLET_PRIVATE_KEY': 'x'}, SECRETS)


def test_masked_config_masked_value_is_configurable():
    config = masked_config({}, {'A': 'secret-value', 'B': ['x', 'y']}, masked_value='[hidden]')

    assert config == {'A': '[hidden]', 'B': ['[hidden]', '[hidden]']}
