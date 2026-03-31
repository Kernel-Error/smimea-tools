#!/usr/bin/env python3
# Author: Sebastian van de Meer
# Website: https://www.kernel-error.de
# License: MIT License
# Feel free to use, modify, and distribute this script as long as you retain attribution.

import hashlib
import base64


def hash_local_part(email):
    """Computes the SHA-256 hash of the local part of an email address, truncated to 28 bytes."""
    parts = email.rsplit('@', 1)
    if len(parts) != 2 or not parts[0] or not parts[1] or '@' in parts[0]:
        raise ValueError(f"Invalid email address: {email!r}")
    local_part, domain = parts
    hashed = hashlib.sha256(local_part.lower().encode()).digest()
    return base64.b16encode(hashed[:28]).decode().lower(), domain
