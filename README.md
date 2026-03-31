# SMIMEA Tools

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A collection of Python tools for generating and querying SMIMEA (RFC 8162) DNS records for S/MIME certificates.

## Features

- **`smimea_generate_record.py`**: Generates a BIND9-compatible SMIMEA DNS record from an email and its corresponding certificate.
- **`smimea_lookup.py`**: Queries and extracts an SMIMEA record from DNS, retrieves the certificate, and displays its details using OpenSSL.

> **Note:** The lookup tool checks the DNSSEC AD (Authenticated Data) flag from your resolver and reports whether the response was authenticated. For this to work, you need a DNSSEC-validating resolver (e.g. Unbound, systemd-resolved with `DNSSEC=yes`).

## Installation

### Prerequisites
- Python 3.9+
- `openssl` command-line tool

### Setup

```sh
pip install -e .
```

For development (includes pytest):

```sh
pip install -e ".[dev]"
```

## Usage

### Generating an SMIMEA Record

```sh
python smimea_generate_record.py <email> <certificate.pem>
```

Example:

```sh
python smimea_generate_record.py user@example.com user_cert.pem
```

The email address must match one of the addresses in the certificate. The generated record uses SMIMEA parameters `3 0 0` (DANE-EE, full certificate, exact match).

### Querying an SMIMEA Record

```sh
python smimea_lookup.py <email>
```

Example:

```sh
python smimea_lookup.py user@example.com
```

Only records with `selector=0` (full certificate) and `matching-type=0` (exact match) are supported. Records with other parameter combinations are skipped with a warning.

## Project Structure

```
smimea-tools/
├── smimea_common.py              # Shared utilities (email hashing)
├── smimea_generate_record.py     # SMIMEA record generator
├── smimea_lookup.py              # SMIMEA DNS lookup
├── tests/                        # pytest test suite
├── pyproject.toml                # Project metadata and dependencies
└── LICENSE
```

## Running Tests

```sh
python -m pytest -v
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

Developed by [Sebastian van de Meer](https://www.kernel-error.de).
