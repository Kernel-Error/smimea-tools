#!/usr/bin/env python3
# Author: Sebastian van de Meer
# Website: https://www.kernel-error.de
# License: MIT License
# Feel free to use, modify, and distribute this script as long as you retain attribution.

import argparse

import dns.flags
import dns.resolver
import subprocess
import sys

from smimea_common import hash_local_part, green, yellow, red

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
        print(red("No SMIMEA record found."))
    except dns.resolver.NXDOMAIN:
        print(red("The domain does not exist."))
    except dns.exception.Timeout:
        print(red("DNS query timed out."))
    except dns.resolver.NoNameservers:
        print(red("No nameservers available for this domain."))
    except dns.exception.DNSException as e:
        print(red(f"DNS error: {e}"))

    return None, smimea_name, False

def extract_cert_from_smimea(answers, email=None):
    """Extracts the certificate from the DNS record and saves it as a DER file.

    Only supports selector=0 (full certificate) with matching-type=0 (exact match).
    Filename is derived from the email address if provided.
    """
    for rdata in answers:
        fields = rdata.to_text().split()
        usage, selector, mtype = int(fields[0]), int(fields[1]), int(fields[2])

        if selector != 0 or mtype != 0:
            print(yellow(f"Unsupported SMIMEA record: usage={usage} selector={selector} matching-type={mtype}"))
            print(yellow("Only selector=0 (full certificate) with matching-type=0 (exact match) is supported."))
            continue

        cert_hex = ''.join(fields[3:])
        try:
            cert_bin = bytes.fromhex(cert_hex)
        except ValueError:
            print(red("Error: invalid hex data in SMIMEA record."))
            continue

        if email:
            cert_file = email.replace("@", "_at_") + ".der"
        else:
            cert_file = "smimea_cert.der"

        with open(cert_file, "wb") as f:
            f.write(cert_bin)

        print(f"Certificate saved as {cert_file} (usage={usage} selector={selector} matching-type={mtype})")
        return cert_file

    return None

def get_certificate_summary(cert_file):
    """Extracts a compact summary from a DER certificate using OpenSSL."""
    fields = {
        "subject": ["-subject", "-nameopt", "utf8,sep_comma_plus_space"],
        "issuer": ["-issuer", "-nameopt", "utf8,sep_comma_plus_space"],
        "dates": ["-dates"],
        "email": ["-email"],
    }
    summary = {}
    for key, flags in fields.items():
        try:
            result = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-in", cert_file, "-noout"] + flags,
                capture_output=True, text=True
            )
            if result.returncode == 0:
                summary[key] = result.stdout.strip()
        except FileNotFoundError:
            return None
    return summary


def display_certificate(cert_file, dnssec_authenticated, full=False):
    """Decodes and displays the certificate details using OpenSSL.

    Shows DNSSEC authentication status so the user can make an informed
    trust decision. Displays a compact summary by default, or full
    OpenSSL output with --full.
    """
    if dnssec_authenticated:
        print(green("DNSSEC: The DNS response was authenticated by your resolver."))
        print(green("The SMIMEA record can be trusted.\n"))
    else:
        print(yellow("DNSSEC: The DNS response was NOT authenticated."))
        print(yellow("This means either the domain does not support DNSSEC, or your"))
        print(yellow("resolver does not perform DNSSEC validation. The certificate"))
        print(yellow("data may have been tampered with in transit."))
        print(yellow("Consider using a DNSSEC-validating resolver (e.g. Unbound,"))
        print(yellow("systemd-resolved with DNSSEC=yes).\n"))

    if full:
        try:
            result = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-in", cert_file, "-text", "-noout"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print("Certificate details:\n")
                print(result.stdout)
            else:
                print(red("Error decoding certificate:"), result.stderr)
        except FileNotFoundError:
            print(red("OpenSSL is not installed or not found in the system path."))
    else:
        summary = get_certificate_summary(cert_file)
        if summary is None:
            print(red("OpenSSL is not installed or not found in the system path."))
            return
        print("Certificate summary:")
        if "subject" in summary:
            print(f"  Subject: {summary['subject'].removeprefix('subject=').strip()}")
        if "issuer" in summary:
            print(f"  Issuer:  {summary['issuer'].removeprefix('issuer=').strip()}")
        if "dates" in summary:
            for line in summary["dates"].split("\n"):
                if line.startswith("notBefore="):
                    print(f"  Valid from:  {line.removeprefix('notBefore=')}")
                elif line.startswith("notAfter="):
                    print(f"  Valid until: {line.removeprefix('notAfter=')}")
        if "email" in summary:
            emails = [e for e in summary["email"].split("\n") if e]
            for e in emails:
                print(f"  Email SAN:   {e}")
        print()

def main():
    parser = argparse.ArgumentParser(
        description="Query and display SMIMEA DNS records for S/MIME certificates."
    )
    parser.add_argument("email", help="Email address to look up")
    parser.add_argument("--full", action="store_true", help="Show full certificate details instead of summary")
    args = parser.parse_args()

    answers, smimea_name, dnssec_authenticated = query_smimea(args.email)

    if answers:
        cert_file = extract_cert_from_smimea(answers, email=args.email)
        if cert_file:
            display_certificate(cert_file, dnssec_authenticated, full=args.full)
    else:
        print(red(f"\nNo valid SMIMEA record found for: {smimea_name}"))
        sys.exit(1)

if __name__ == "__main__":
    main()
