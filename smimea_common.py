#!/usr/bin/env python3
# Author: Sebastian van de Meer
# Website: https://www.kernel-error.de
# License: MIT License
# Feel free to use, modify, and distribute this script as long as you retain attribution.

import hashlib
import base64


def hash_local_part(email):
    """Computes the SHA-256 hash of the local part of an email address, truncated to 28 bytes."""
    local_part, domain = email.split('@')
    hashed = hashlib.sha256(local_part.encode()).digest()
    return base64.b16encode(hashed[:28]).decode().lower(), domain
