import subprocess
import pytest


@pytest.fixture(scope="session")
def sample_cert_and_email(tmp_path_factory):
    """Creates a self-signed cert with email SAN 'Test.User@example.com'."""
    email = "Test.User@example.com"
    tmp_dir = tmp_path_factory.mktemp("certs")
    key_file = tmp_dir / "key.pem"
    cert_file = tmp_dir / "cert.pem"

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_file), "-out", str(cert_file),
            "-days", "1", "-nodes",
            "-subj", "/CN=Test User",
            "-addext", f"subjectAltName=email:{email}",
        ],
        check=True,
        capture_output=True,
    )

    return str(cert_file), email


@pytest.fixture(scope="session")
def sample_cert_no_email(tmp_path_factory):
    """Creates a self-signed cert without any email SAN."""
    tmp_dir = tmp_path_factory.mktemp("certs_no_email")
    key_file = tmp_dir / "key.pem"
    cert_file = tmp_dir / "cert.pem"

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_file), "-out", str(cert_file),
            "-days", "1", "-nodes",
            "-subj", "/CN=No Email Cert",
        ],
        check=True,
        capture_output=True,
    )

    return str(cert_file)


@pytest.fixture(scope="session")
def sample_cert_der_hex(sample_cert_and_email):
    """Returns uppercase hex of the DER-encoded sample certificate."""
    cert_file, _ = sample_cert_and_email
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_file, "-outform", "DER"],
        capture_output=True,
        check=True,
    )
    return result.stdout.hex().upper()


class MockRdata:
    """Mimics a dnspython SMIMEA rdata object."""

    def __init__(self, usage, selector, mtype, cert_hex):
        self.usage = usage
        self.selector = selector
        self.mtype = mtype
        self._cert_hex = cert_hex

    def to_text(self):
        return f"{self.usage} {self.selector} {self.mtype} {self._cert_hex}"


@pytest.fixture
def mock_smimea_answers_300(sample_cert_der_hex):
    """Returns mock DNS answers for a valid 3 0 0 SMIMEA record."""
    return [MockRdata(3, 0, 0, sample_cert_der_hex)]


@pytest.fixture
def mock_smimea_answers_301():
    """Returns mock DNS answers for a 3 0 1 record (SHA-256 hash, not full cert)."""
    fake_hash = "AB" * 32
    return [MockRdata(3, 0, 1, fake_hash)]
