import subprocess
import sys

import pytest
import dns.resolver

sys.path.insert(0, ".")
from smimea_lookup import (
    query_smimea,
    extract_cert_from_smimea,
    verify_certificate,
)


def test_extract_cert_from_smimea(mock_smimea_answers_300, tmp_path, monkeypatch):
    """Extracts a valid DER file from a mocked 3 0 0 SMIMEA answer."""
    monkeypatch.chdir(tmp_path)
    cert_file = extract_cert_from_smimea(mock_smimea_answers_300)

    assert cert_file == "smimea_cert.der"
    assert (tmp_path / "smimea_cert.der").exists()
    assert (tmp_path / "smimea_cert.der").stat().st_size > 0


def test_query_smimea_success(monkeypatch, mock_smimea_answers_300):
    """Returns answers and correct SMIMEA name for a successful query."""
    def mock_resolve(name, rdtype):
        return mock_smimea_answers_300

    monkeypatch.setattr(dns.resolver, "resolve", mock_resolve)

    answers, smimea_name = query_smimea("user@example.com")

    assert answers is not None
    assert "_smimecert.example.com" in smimea_name


def test_query_smimea_nxdomain(monkeypatch):
    """Returns (None, name) when domain doesn't exist."""
    def mock_resolve(name, rdtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", mock_resolve)

    answers, smimea_name = query_smimea("user@nonexistent.example")

    assert answers is None
    assert "_smimecert.nonexistent.example" in smimea_name


def test_query_smimea_no_answer(monkeypatch):
    """Returns (None, name) when no SMIMEA record exists."""
    def mock_resolve(name, rdtype):
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver, "resolve", mock_resolve)

    answers, _ = query_smimea("user@example.com")
    assert answers is None


def test_verify_certificate(sample_cert_and_email, capsys):
    """Displays certificate details for a valid DER cert."""
    cert_file, _ = sample_cert_and_email
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_file, "-outform", "DER"],
        capture_output=True,
        check=True,
    )
    der_path = "/tmp/test_verify.der"
    with open(der_path, "wb") as f:
        f.write(result.stdout)

    verify_certificate(der_path)

    captured = capsys.readouterr()
    assert "Certificate successfully retrieved" in captured.out


@pytest.mark.xfail(
    reason="Issue #2: non-3-0-0 SMIMEA records not rejected",
    strict=True,
)
def test_reject_non_300_record(mock_smimea_answers_301, tmp_path, monkeypatch):
    """Should reject or warn about records with matching-type != 0."""
    monkeypatch.chdir(tmp_path)
    cert_file = extract_cert_from_smimea(mock_smimea_answers_301)
    # If the function doesn't reject unsupported records, it returns a file path.
    # The correct behavior is to return None or raise an error.
    assert cert_file is None


@pytest.mark.xfail(
    reason="Issue #4: exit code always 0 on error",
    strict=True,
)
def test_cli_lookup_exit_code_on_nxdomain(monkeypatch):
    """Script should exit non-zero when no SMIMEA record is found."""
    def mock_resolve(name, rdtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", mock_resolve)

    result = subprocess.run(
        [sys.executable, "smimea_lookup.py", "user@nonexistent.example"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
