#!/usr/bin/env python3
# Author: Sebastian van de Meer
# Website: https://www.kernel-error.de
# License: MIT License
# Feel free to use, modify, and distribute this script as long as you retain attribution.

import hashlib
import dns.resolver
import base64
import subprocess
import sys

def hash_local_part(email):
    """Computes the SHA-256 hash of the local part of an email address, truncated to 28 bytes."""
    local_part, domain = email.split('@')
    hashed = hashlib.sha256(local_part.encode()).digest()
    return base64.b16encode(hashed[:28]).decode().lower(), domain

def query_smimea(email):
    """Queries the SMIMEA record for the hashed email address."""
    local_hash, domain = hash_local_part(email)
    smimea_name = f"{local_hash}._smimecert.{domain}"

    print(f"\nQuerying DNS for SMIMEA record:\n  {smimea_name}\n")
    
    try:
        answers = dns.resolver.resolve(smimea_name, 'SMIMEA')
        return answers, smimea_name
    except dns.resolver.NoAnswer:
        print("No SMIMEA record found.")
    except dns.resolver.NXDOMAIN:
        print("The domain does not exist.")
    except dns.exception.Timeout:
        print("DNS query timed out.")
    
    return None, smimea_name

def extract_cert_from_smimea(answers):
    """Extracts the certificate from the DNS record and saves it as a DER file."""
    for rdata in answers:
        cert_hex = ''.join(rdata.to_text().split()[3:])  # Remove the first three fields (Usage, Selector, Matching Type)
        cert_bin = bytes.fromhex(cert_hex)
        cert_file = "smimea_cert.der"

        with open(cert_file, "wb") as f:
            f.write(cert_bin)

        print(f"Certificate saved as {cert_file}")
        return cert_file

    return None

def verify_certificate(cert_file):
    """Verifies the certificate using OpenSSL."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", cert_file, "-text", "-noout"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("Certificate successfully retrieved and verified:\n")
            print(result.stdout)
        else:
            print("Error during certificate verification:", result.stderr)
    except FileNotFoundError:
        print("OpenSSL is not installed or not found in the system path.")

def main():
    if len(sys.argv) > 1:
        email = sys.argv[1]
    else:
        email = input("Enter the email address: ").strip()
    
    answers, smimea_name = query_smimea(email)
    
    if answers:
        cert_file = extract_cert_from_smimea(answers)
        if cert_file:
            verify_certificate(cert_file)
    else:
        print(f"\nNo valid SMIMEA record found for: {smimea_name}")

if __name__ == "__main__":
    main()
