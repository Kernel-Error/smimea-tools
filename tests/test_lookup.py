import subprocess
import sys
from unittest.mock import MagicMock

import pytest
import dns.flags
import dns.resolver

sys.path.insert(0, ".")
from smimea_lookup import (
    query_smimea,
    extract_cert_from_smimea,
    display_certificate,
)


def _mock_resolver(monkeypatch, mock_answers, ad_flag=False):
    """Patches dns.resolver.Resolver to return mock_answers with optional AD flag."""
    mock_response = MagicMock()
    mock_response.flags = dns.flags.AD if ad_flag else 0

    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter(mock_answers)
    mock_answer.response = mock_response

    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = mock_answer

    monkeypatch.setattr(dns.resolver, "Resolver", lambda: mock_resolver_instance)
    return mock_resolver_instance


def test_extract_cert_from_smimea(mock_smimea_answers_300, tmp_path, monkeypatch):
    """Extracts a valid DER file from a mocked 3 0 0 SMIMEA answer."""
    monkeypatch.chdir(tmp_path)
    cert_file = extract_cert_from_smimea(mock_smimea_answers_300)

    assert cert_file == "smimea_cert.der"
    assert (tmp_path / "smimea_cert.der").exists()
    assert (tmp_path / "smimea_cert.der").stat().st_size > 0


def test_query_smimea_success(monkeypatch, mock_smimea_answers_300):
    """Returns answers, correct SMIMEA name, and dnssec status."""
    _mock_resolver(monkeypatch, mock_smimea_answers_300, ad_flag=False)

    answers, smimea_name, dnssec = query_smimea("user@example.com")

    assert answers is not None
    assert "_smimecert.example.com" in smimea_name
    assert dnssec is False


def test_query_smimea_dnssec_authenticated(monkeypatch, mock_smimea_answers_300):
    """Reports DNSSEC authenticated when AD flag is set."""
    _mock_resolver(monkeypatch, mock_smimea_answers_300, ad_flag=True)

    answers, _, dnssec = query_smimea("user@example.com")

    assert answers is not None
    assert dnssec is True


def test_query_smimea_nxdomain(monkeypatch):
    """Returns (None, name, False) when domain doesn't exist."""
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.side_effect = dns.resolver.NXDOMAIN()
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: mock_resolver_instance)

    answers, smimea_name, dnssec = query_smimea("user@nonexistent.example")

    assert answers is None
    assert "_smimecert.nonexistent.example" in smimea_name
    assert dnssec is False


def test_query_smimea_no_answer(monkeypatch):
    """Returns (None, name, False) when no SMIMEA record exists."""
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.side_effect = dns.resolver.NoAnswer()
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: mock_resolver_instance)

    answers, _, dnssec = query_smimea("user@example.com")
    assert answers is None
    assert dnssec is False


def test_query_smimea_no_nameservers(monkeypatch):
    """Returns (None, name, False) when no nameservers are available."""
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.side_effect = dns.resolver.NoNameservers()
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: mock_resolver_instance)

    answers, _, dnssec = query_smimea("user@example.com")
    assert answers is None
    assert dnssec is False


def test_display_certificate_no_dnssec(sample_cert_and_email, capsys):
    """Shows DNSSEC warning when not authenticated."""
    cert_file, _ = sample_cert_and_email
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_file, "-outform", "DER"],
        capture_output=True,
        check=True,
    )
    der_path = "/tmp/test_verify.der"
    with open(der_path, "wb") as f:
        f.write(result.stdout)

    display_certificate(der_path, dnssec_authenticated=False)

    captured = capsys.readouterr()
    assert "NOT authenticated" in captured.out
    assert "DNSSEC-validating resolver" in captured.out
    assert "Certificate details" in captured.out


def test_display_certificate_with_dnssec(sample_cert_and_email, capsys):
    """Shows DNSSEC success message when authenticated."""
    cert_file, _ = sample_cert_and_email
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_file, "-outform", "DER"],
        capture_output=True,
        check=True,
    )
    der_path = "/tmp/test_verify_dnssec.der"
    with open(der_path, "wb") as f:
        f.write(result.stdout)

    display_certificate(der_path, dnssec_authenticated=True)

    captured = capsys.readouterr()
    assert "authenticated by your resolver" in captured.out
    assert "can be trusted" in captured.out
    assert "Certificate details" in captured.out


def test_reject_non_300_record(mock_smimea_answers_301, tmp_path, monkeypatch):
    """Should reject or warn about records with matching-type != 0."""
    monkeypatch.chdir(tmp_path)
    cert_file = extract_cert_from_smimea(mock_smimea_answers_301)
    assert cert_file is None


def test_cli_lookup_exit_code_on_nxdomain():
    """Script should exit non-zero when no SMIMEA record is found."""
    result = subprocess.run(
        [
            sys.executable, "-c",
            "import dns.resolver; dns.resolver.resolve = lambda *a, **k: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()); "
            "import smimea_lookup; smimea_lookup.main()",
        ],
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": "."},
        input="user@nonexistent.example\n",
    )
    assert result.returncode != 0
