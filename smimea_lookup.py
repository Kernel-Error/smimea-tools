#!/usr/bin/env python3
# Author: Sebastian van de Meer
# Website: https://www.kernel-error.de
# License: MIT License
# Feel free to use, modify, and distribute this script as long as you retain attribution.

import dns.flags
import dns.resolver
import subprocess
import sys

from smimea_common import hash_local_part

def query_smimea(email):
    """Queries the SMIMEA record for the hashed email address.

    Requests DNSSEC data (DO flag) and checks the AD flag in the response
    to determine whether the resolver validated the DNSSEC chain.

    Returns (answers, smimea_name, dnssec_authenticated).
    """
    local_hash, domain = hash_local_part(email)
    smimea_name = f"{local_hash}._smimecert.{domain}"

    print(f"\nQuerying DNS for SMIMEA record:\n  {smimea_name}\n")

    try:
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        answers = resolver.resolve(smimea_name, 'SMIMEA')
        dnssec_authenticated = bool(answers.response.flags & dns.flags.AD)
        return answers, smimea_name, dnssec_authenticated
    except dns.resolver.NoAnswer:
        print("No SMIMEA record found.")
    except dns.resolver.NXDOMAIN:
        print("The domain does not exist.")
    except dns.exception.Timeout:
        print("DNS query timed out.")
    except dns.resolver.NoNameservers:
        print("No nameservers available for this domain.")
    except dns.exception.DNSException as e:
        print(f"DNS error: {e}")

    return None, smimea_name, False

def extract_cert_from_smimea(answers):
    """Extracts the certificate from the DNS record and saves it as a DER file.

    Only supports selector=0 (full certificate) with matching-type=0 (exact match).
    """
    for rdata in answers:
        fields = rdata.to_text().split()
        usage, selector, mtype = int(fields[0]), int(fields[1]), int(fields[2])

        if selector != 0 or mtype != 0:
            print(f"Unsupported SMIMEA record: usage={usage} selector={selector} matching-type={mtype}")
            print("Only selector=0 (full certificate) with matching-type=0 (exact match) is supported.")
            continue

        cert_hex = ''.join(fields[3:])
        try:
            cert_bin = bytes.fromhex(cert_hex)
        except ValueError:
            print("Error: invalid hex data in SMIMEA record.")
            continue

        cert_file = "smimea_cert.der"
        with open(cert_file, "wb") as f:
            f.write(cert_bin)

        print(f"Certificate saved as {cert_file} (usage={usage} selector={selector} matching-type={mtype})")
        return cert_file

    return None

def display_certificate(cert_file, dnssec_authenticated):
    """Decodes and displays the certificate details using OpenSSL.

    Shows DNSSEC authentication status so the user can make an informed
    trust decision.
    """
    if dnssec_authenticated:
        print("DNSSEC: The DNS response was authenticated by your resolver.")
        print("The SMIMEA record can be trusted.\n")
    else:
        print("DNSSEC: The DNS response was NOT authenticated.")
        print("This means either the domain does not support DNSSEC, or your")
        print("resolver does not perform DNSSEC validation. The certificate")
        print("data may have been tampered with in transit.")
        print("Consider using a DNSSEC-validating resolver (e.g. Unbound,")
        print("systemd-resolved with DNSSEC=yes).\n")

    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", cert_file, "-text", "-noout"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("Certificate details:\n")
            print(result.stdout)
        else:
            print("Error decoding certificate:", result.stderr)
    except FileNotFoundError:
        print("OpenSSL is not installed or not found in the system path.")

def main():
    if len(sys.argv) > 1:
        email = sys.argv[1]
    else:
        email = input("Enter the email address: ").strip()
    
    answers, smimea_name, dnssec_authenticated = query_smimea(email)

    if answers:
        cert_file = extract_cert_from_smimea(answers)
        if cert_file:
            display_certificate(cert_file, dnssec_authenticated)
    else:
        print(f"\nNo valid SMIMEA record found for: {smimea_name}")
        sys.exit(1)

if __name__ == "__main__":
    main()
