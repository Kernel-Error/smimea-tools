#!/usr/bin/env python3
# Author: Sebastian van de Meer
# Website: https://www.kernel-error.de
# License: MIT License
# Feel free to use, modify, and distribute this script as long as you retain attribution.

import argparse
import subprocess
import sys
import textwrap

from smimea_common import hash_local_part, green, red

def extract_emails_from_cert(cert_file):
    """Extracts email addresses from a given PEM certificate using OpenSSL."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_file, "-noout", "-email"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            emails = [e for e in result.stdout.strip().split("\n") if e]
            return emails
        else:
            print(red("Error extracting email from certificate:"), result.stderr)
    except FileNotFoundError:
        print(red("OpenSSL is not installed or not found in the system path."))

    return []

def convert_cert_to_hex(cert_file):
    """Converts a PEM certificate to DER and returns the hexadecimal representation."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_file, "-outform", "DER"],
            capture_output=True
        )
        if result.returncode != 0:
            print(red("Error converting certificate to DER format:"), result.stderr.decode(errors="replace"))
            return None

        return result.stdout.hex().upper()
    except FileNotFoundError:
        print(red("OpenSSL is not installed or not found in the system path."))
        return None

def format_bind9_record(name, cert_hex, ttl=3600):
    """Formats the SMIMEA record into the correct BIND9 format with proper line breaks and indentation."""
    # Split the certificate hex into 64-character chunks
    hex_chunks = textwrap.wrap(cert_hex, 64)

    formatted_record = f"{name}. {ttl} IN SMIMEA 3 0 0 (\n"
    for chunk in hex_chunks:
        formatted_record += f"   {chunk}\n"
    formatted_record += "   )\n"

    return formatted_record

def main():
    parser = argparse.ArgumentParser(
        description="Generate a BIND9-compatible SMIMEA DNS record from an email and certificate."
    )
    parser.add_argument("email", help="Email address for the SMIMEA record")
    parser.add_argument("certificate", help="Path to the PEM certificate file")
    parser.add_argument("--ttl", type=int, default=3600, help="TTL for the DNS record (default: 3600)")
    args = parser.parse_args()

    email = args.email
    cert_file = args.certificate

    # Validate email against certificate
    cert_emails = extract_emails_from_cert(cert_file)
    
    if not cert_emails:
        print(red("No email address found in the certificate. Aborting."))
        sys.exit(1)

    if email not in cert_emails:
        print(red(f"Error: The email address '{email}' does not match any in the certificate!"))
        sys.exit(1)

    print(green(f"Email '{email}' matches the certificate."))

    # Compute the DNS record name
    local_hash, domain = hash_local_part(email)
    smimea_name = f"{local_hash}._smimecert.{domain}"

    # Convert certificate to hex
    cert_hex = convert_cert_to_hex(cert_file)
    
    if not cert_hex:
        print(red("Error converting certificate to hex format. Aborting."))
        sys.exit(1)

    # Generate the BIND9 DNS entry
    bind9_record = format_bind9_record(smimea_name, cert_hex, args.ttl)

    print(green("\nGenerated BIND9 DNS Record:\n"))
    print(bind9_record)

if __name__ == "__main__":
    main()
