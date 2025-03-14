#!/usr/bin/env python3
# Author: Sebastian van de Meer
# Website: https://www.kernel-error.de
# License: MIT License
# Feel free to use, modify, and distribute this script as long as you retain attribution.

import hashlib
import base64
import subprocess
import sys
import textwrap

def hash_local_part(email):
    """Computes the SHA-256 hash of the local part of an email address, truncated to 28 bytes."""
    local_part, domain = email.split('@')
    hashed = hashlib.sha256(local_part.encode()).digest()
    return base64.b16encode(hashed[:28]).decode().lower(), domain

def extract_emails_from_cert(cert_file):
    """Extracts email addresses from a given PEM certificate using OpenSSL."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_file, "-noout", "-email"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            emails = result.stdout.strip().split("\n")
            return emails
        else:
            print("Error extracting email from certificate:", result.stderr)
    except FileNotFoundError:
        print("OpenSSL is not installed or not found in the system path.")
    
    return []

def convert_cert_to_hex(cert_file):
    """Converts a PEM certificate to DER and returns the hexadecimal representation."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_file, "-outform", "DER"],
            capture_output=True
        )
        if result.returncode != 0:
            print("Error converting certificate to DER format:", result.stderr)
            return None

        return result.stdout.hex().upper()
    except FileNotFoundError:
        print("OpenSSL is not installed or not found in the system path.")
        return None

def format_bind9_record(name, cert_hex):
    """Formats the SMIMEA record into the correct BIND9 format with proper line breaks and indentation."""
    # Split the certificate hex into 64-character chunks
    hex_chunks = textwrap.wrap(cert_hex, 64)

    formatted_record = f"{name}. 3600 IN SMIMEA 3 0 0 (\n"
    for chunk in hex_chunks:
        formatted_record += f"   {chunk}\n"
    formatted_record += "   )\n"

    return formatted_record

def main():
    # Read the email address and certificate path from arguments or prompt
    if len(sys.argv) > 2:
        email = sys.argv[1]
        cert_file = sys.argv[2]
    else:
        email = input("Enter the email address: ").strip()
        cert_file = input("Enter the path to the PEM certificate: ").strip()

    # Validate email against certificate
    cert_emails = extract_emails_from_cert(cert_file)
    
    if not cert_emails:
        print("No email address found in the certificate. Aborting.")
        return

    if email not in cert_emails:
        print(f"Error: The email address '{email}' does not match any in the certificate!")
        return
    
    print(f"✅ Email '{email}' matches the certificate!")

    # Compute the DNS record name
    local_hash, domain = hash_local_part(email)
    smimea_name = f"{local_hash}._smimecert.{domain}"

    # Convert certificate to hex
    cert_hex = convert_cert_to_hex(cert_file)
    
    if not cert_hex:
        print("Error converting certificate to hex format. Aborting.")
        return

    # Generate the BIND9 DNS entry
    bind9_record = format_bind9_record(smimea_name, cert_hex)

    print("\n🔹 **Generated BIND9 DNS Record:**\n")
    print(bind9_record)

if __name__ == "__main__":
    main()
