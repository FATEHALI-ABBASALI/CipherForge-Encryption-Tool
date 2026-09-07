"""
CipherForge
-----------
Password-based key derivation using Argon2id.

Passwords are never used directly as encryption keys.
Argon2id derives a strong 256-bit key from the user's password
and a unique random salt.
"""

from __future__ import annotations

import os

from argon2.low_level import (
    Type,
    hash_secret_raw,
)


# ---------------------------------------------------------------------------
# Cryptographic constants
# ---------------------------------------------------------------------------

SALT_SIZE = 16          # 128-bit salt
KEY_SIZE = 32           # 256-bit derived key

# Argon2id parameters.
#
# These are intentionally kept in one place so they can later be exposed
# through CipherForge Settings if required.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024   # 64 MiB
ARGON2_PARALLELISM = 2


# ---------------------------------------------------------------------------
# Salt generation
# ---------------------------------------------------------------------------

def generate_salt() -> bytes:
    """
    Generate a cryptographically secure random salt.

    Returns:
        bytes: A 16-byte random salt.
    """

    return os.urandom(SALT_SIZE)


# ---------------------------------------------------------------------------
# Password key derivation
# ---------------------------------------------------------------------------

def derive_key(
    password: str,
    salt: bytes,
) -> bytes:
    """
    Derive a 256-bit encryption key from a password using Argon2id.

    Args:
        password:
            User's password.

        salt:
            Unique random salt generated for the encryption operation.

    Returns:
        bytes:
            A 32-byte / 256-bit derived key.

    Raises:
        TypeError:
            If password or salt has an invalid type.

        ValueError:
            If password is empty or salt has an invalid length.
    """

    if not isinstance(password, str):
        raise TypeError(
            "Password must be a string."
        )

    if not isinstance(salt, bytes):
        raise TypeError(
            "Salt must be bytes."
        )

    if not password:
        raise ValueError(
            "Password cannot be empty."
        )

    if len(salt) != SALT_SIZE:
        raise ValueError(
            f"Salt must be exactly {SALT_SIZE} bytes."
        )

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )