import io
import logging

import pytest

from lido_safe_logging.formatter import JsonFormatter
from lido_safe_logging.handler import SafeStreamHandler
from lido_safe_logging.secrets import SecretsMasker
from tests.conftest import KEY, SECRETS, assert_no_secret, make_record


class BrokenStream(io.StringIO):
    def write(self, text: str) -> int:
        raise OSError(32, 'Broken pipe')


MASKER = SecretsMasker(SECRETS)


def make_handler(masker: SecretsMasker | None = MASKER) -> SafeStreamHandler:
    handler = SafeStreamHandler(BrokenStream(), masker=masker)
    handler.setFormatter(JsonFormatter(masker))
    return handler


def test_write_failure_does_not_print_the_record(capsys):
    record = make_record('key %s', logging.INFO)
    record.args = (KEY,)

    make_handler().handle(record)

    report = capsys.readouterr().err
    assert 'Logging error' in report
    assert 'Broken pipe' in report
    assert 'conftest.py:1' in report
    assert 'key %s' not in report
    assert_no_secret(report)


def test_write_failure_report_is_masked(capsys):
    record = make_record('x')
    record.name = f'logger-{KEY}'

    make_handler().handle(record)

    assert_no_secret(capsys.readouterr().err)


def test_write_failure_report_respects_raise_exceptions(capsys, monkeypatch):
    monkeypatch.setattr(logging, 'raiseExceptions', False)

    make_handler().handle(make_record('x'))

    assert capsys.readouterr().err == ''


def test_broken_stderr_does_not_raise(monkeypatch):
    monkeypatch.setattr('sys.stderr', BrokenStream())

    make_handler().handle(make_record('x'))


@pytest.mark.parametrize('masker', [None, SecretsMasker({})])
def test_handler_without_secrets_still_reports(capsys, masker):
    make_handler(masker).handle(make_record('x'))

    assert 'Logging error' in capsys.readouterr().err
