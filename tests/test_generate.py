import subprocess
import sys

import pytest

sys.path.insert(0, ".")
from smimea_generate_record import (
    extract_emails_from_cert,
    convert_cert_to_hex,
    format_bind9_record,
)


def test_extract_emails_from_cert(sample_cert_and_email):
    """Extracts the correct email from a valid certificate."""
    cert_file, email = sample_cert_and_email
    emails = extract_emails_from_cert(cert_file)
    assert email in emails


def test_extract_emails_from_cert_nonexistent_file():
    """Returns empty list for a nonexistent file."""
    result = extract_emails_from_cert("/nonexistent/cert.pem")
    assert result == []


def test_convert_cert_to_hex(sample_cert_and_email):
    """Converts a valid PEM cert to a non-empty uppercase hex string."""
    cert_file, _ = sample_cert_and_email
    hex_str = convert_cert_to_hex(cert_file)
    assert hex_str is not None
    assert len(hex_str) > 0
    assert all(c in "0123456789ABCDEF" for c in hex_str)


def test_convert_cert_to_hex_nonexistent_file():
    """Returns None for a nonexistent file."""
    result = convert_cert_to_hex("/nonexistent/cert.pem")
    assert result is None


def test_format_bind9_record_structure():
    """Output contains required BIND9 SMIMEA record elements."""
    name = "abc123._smimecert.example.com"
    cert_hex = "AA" * 100

    record = format_bind9_record(name, cert_hex)

    assert name in record
    assert "3600 IN SMIMEA 3 0 0" in record
    assert record.strip().endswith(")")


def test_format_bind9_record_custom_ttl():
    """TTL parameter is used in the record output."""
    record = format_bind9_record("test._smimecert.example.com", "AA" * 10, ttl=7200)
    assert "7200 IN SMIMEA 3 0 0" in record


def test_format_bind9_record_line_length():
    """Hex chunks in the record are max 64 characters wide."""
    cert_hex = "AB" * 200
    record = format_bind9_record("test._smimecert.example.com", cert_hex)

    for line in record.split("\n"):
        stripped = line.strip()
        if stripped and stripped not in ("(", ")") and "SMIMEA" not in stripped:
            assert len(stripped) <= 64


def test_cli_generate_success(sample_cert_and_email):
    """CLI produces a BIND9 record for matching email + cert."""
    cert_file, email = sample_cert_and_email
    result = subprocess.run(
        [sys.executable, "smimea_generate_record.py", email, cert_file],
        capture_output=True,
        text=True,
    )
    assert "_smimecert.example.com" in result.stdout
    assert "SMIMEA 3 0 0" in result.stdout


def test_cli_generate_email_mismatch(sample_cert_and_email):
    """CLI shows error when email doesn't match the certificate."""
    cert_file, _ = sample_cert_and_email
    result = subprocess.run(
        [sys.executable, "smimea_generate_record.py", "wrong@example.com", cert_file],
        capture_output=True,
        text=True,
    )
    assert "does not match" in result.stdout


def test_cli_generate_exit_code_on_error(sample_cert_and_email):
    """Script should exit non-zero when email doesn't match cert."""
    cert_file, _ = sample_cert_and_email
    result = subprocess.run(
        [sys.executable, "smimea_generate_record.py", "wrong@example.com", cert_file],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_extract_emails_empty_result(sample_cert_no_email):
    """Cert without email SAN should return an empty list, not ['']."""
    result = extract_emails_from_cert(sample_cert_no_email)
    assert result == []
