# SMIMEA Tools

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A collection of Python tools for generating and querying SMIMEA DNS records for S/MIME certificates.

## 🚀 Features

- **`smimea_generate_record.py`**: Generates a BIND9-compatible SMIMEA DNS record from an email and its corresponding certificate.
- **`smimea_lookup.py`**: Queries and extracts an SMIMEA record from DNS, retrieves the certificate, and verifies it using OpenSSL.

## 🛠️ Installation

### Prerequisites
- Python 3.x
- `openssl` command-line tool
- `dnspython` package (for `smimea_lookup.py`)

To install `dnspython`, run:

```sh
pip install dnspython
```

## 📌 Usage

### Generating an SMIMEA Record

```sh
python smimea_generate_record.py <email> <certificate.pem>
```

Example:

```sh
python smimea_generate_record.py user@example.com user_cert.pem
```

### Querying an SMIMEA Record

```sh
python smimea_lookup.py <email>
```

Example:

```sh
python smimea_lookup.py user@example.com
```

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ✨ Author

Developed by [Sebastian van de Meer](https://www.kernel-error.de).
