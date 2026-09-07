"""
CipherForge
-----------
Recovery-key cryptographic operations.

This module handles:

    1. Recovery secret generation
    2. Human-readable recovery-key formatting
    3. Recovery-key parsing
    4. HKDF-based recovery-key derivation
    5. File-key wrapping
    6. File-key unwrapping

This module does NOT handle:

    - GUI
    - file dialogs
    - USB detection
    - recovery-key files
    - encrypted file containers

Those responsibilities will be implemented separately.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import (
    InvalidRecoveryKeyError,
)


# ============================================================================
# Constants
# ============================================================================

# 256-bit recovery secret.
RECOVERY_SECRET_SIZE = 32

# AES-256-GCM key size.
RECOVERY_KEY_SIZE = 32

# AES-GCM uses a 96-bit nonce.
WRAP_NONCE_SIZE = 12

# Version/context identifier.
RECOVERY_INFO = (
    b"CipherForge-Recovery-Key-Wrap-v1"
)

# Associated data authenticates the purpose of the wrapped key.
RECOVERY_AAD = (
    b"CipherForge-Recovery-Key-v1"
)


# ============================================================================
# Recovery secret generation
# ============================================================================

def generate_recovery_secret() -> bytes:
    """
    Generate a cryptographically secure 256-bit recovery secret.

    Returns:
        bytes:
            32 random bytes.

    Notes:
        os.urandom() uses the operating system's secure random
        source and is suitable for cryptographic key material.
    """

    return os.urandom(
        RECOVERY_SECRET_SIZE
    )


# ============================================================================
# Recovery secret -> human-readable text
# ============================================================================

def recovery_secret_to_text(
    secret: bytes,
) -> str:
    """
    Convert a binary recovery secret into a readable Base32 key.

    Example format:

        A1BCD-EFGHI-JKLMN-OPQRS-...

    Base32 is used because it avoids many characters that are
    inconvenient or ambiguous when users manually read/copy keys.

    Args:
        secret:
            Exactly 32 bytes.

    Returns:
        str:
            Human-readable recovery key.
    """

    if not isinstance(secret, bytes):
        raise TypeError(
            "Recovery secret must be bytes."
        )

    if len(secret) != RECOVERY_SECRET_SIZE:
        raise ValueError(
            f"Recovery secret must be exactly "
            f"{RECOVERY_SECRET_SIZE} bytes."
        )

    encoded = base64.b32encode(
        secret
    ).decode(
        "ascii"
    )

    # Remove Base32 padding because it is unnecessary
    # for the displayed recovery key.
    encoded = encoded.rstrip(
        "="
    )

    # Group into 5-character blocks.
    groups = [
        encoded[index:index + 5]
        for index in range(
            0,
            len(encoded),
            5,
        )
    ]

    return "-".join(
        groups
    )


# ============================================================================
# Human-readable text -> recovery secret
# ============================================================================

def recovery_text_to_secret(
    text: str,
) -> bytes:
    """
    Convert a human-readable recovery key back into bytes.

    The parser accepts keys containing:

        - hyphens
        - spaces
        - upper/lowercase characters

    Example:

        ABCDE-FGHIJ-KLMNO...

    Args:
        text:
            Recovery key text.

    Returns:
        bytes:
            Original 32-byte recovery secret.

    Raises:
        InvalidRecoveryKeyError:
            If the key format is invalid.
    """

    if not isinstance(text, str):
        raise TypeError(
            "Recovery key must be a string."
        )

    cleaned = (
        text
        .replace("-", "")
        .replace(" ", "")
        .replace("\t", "")
        .replace("\r", "")
        .replace("\n", "")
        .strip()
        .upper()
    )

    if not cleaned:
        raise InvalidRecoveryKeyError(
            "Recovery key cannot be empty."
        )

    # Base32 alphabet consists of A-Z and digits 2-7.
    valid_characters = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    )

    if any(
        character not in valid_characters
        for character in cleaned
    ):
        raise InvalidRecoveryKeyError(
            "Recovery key contains invalid characters."
        )

    # Base32 requires a length divisible by 8.
    padding_length = (
        -len(cleaned)
    ) % 8

    padded = (
        cleaned
        + ("=" * padding_length)
    )

    try:

        secret = base64.b32decode(
            padded,
            casefold=True,
        )

    except Exception as exc:

        raise InvalidRecoveryKeyError(
            "Recovery key has an invalid format."
        ) from exc

    if len(secret) != RECOVERY_SECRET_SIZE:
        raise InvalidRecoveryKeyError(
            "Recovery key has an invalid length."
        )

    return secret


# ============================================================================
# HKDF
# ============================================================================

def derive_recovery_wrap_key(
    recovery_secret: bytes,
) -> bytes:
    """
    Derive a 256-bit key from the recovery secret using HKDF-SHA256.

    HKDF is used here as a key-derivation / key-separation layer.

    Args:
        recovery_secret:
            32-byte recovery secret.

    Returns:
        bytes:
            32-byte AES-256-GCM wrapping key.
    """

    if not isinstance(
        recovery_secret,
        bytes,
    ):
        raise TypeError(
            "Recovery secret must be bytes."
        )

    if len(recovery_secret) != RECOVERY_SECRET_SIZE:
        raise ValueError(
            f"Recovery secret must be exactly "
            f"{RECOVERY_SECRET_SIZE} bytes."
        )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=RECOVERY_KEY_SIZE,
        salt=None,
        info=RECOVERY_INFO,
    )

    return hkdf.derive(
        recovery_secret
    )


# ============================================================================
# File-key wrapping
# ============================================================================

def wrap_file_key(
    file_key: bytes,
    recovery_secret: bytes,
) -> tuple[bytes, bytes]:
    """
    Encrypt/wrap the file encryption key using a key derived
    from the recovery secret.

    Args:
        file_key:
            32-byte random file encryption key.

        recovery_secret:
            32-byte recovery secret.

    Returns:
        tuple[bytes, bytes]:
            (
                wrap_nonce,
                wrapped_file_key,
            )

    The returned wrapped key contains the AES-GCM authentication
    tag appended by cryptography's AESGCM implementation.
    """

    if not isinstance(
        file_key,
        bytes,
    ):
        raise TypeError(
            "File key must be bytes."
        )

    if len(file_key) != RECOVERY_KEY_SIZE:
        raise ValueError(
            f"File key must be exactly "
            f"{RECOVERY_KEY_SIZE} bytes."
        )

    wrap_key = derive_recovery_wrap_key(
        recovery_secret
    )

    nonce = os.urandom(
        WRAP_NONCE_SIZE
    )

    wrapped_file_key = AESGCM(
        wrap_key
    ).encrypt(
        nonce,
        file_key,
        RECOVERY_AAD,
    )

    return (
        nonce,
        wrapped_file_key,
    )


# ============================================================================
# File-key unwrapping
# ============================================================================

def unwrap_file_key(
    wrapped_file_key: bytes,
    nonce: bytes,
    recovery_secret: bytes,
) -> bytes:
    """
    Recover the original file encryption key.

    Args:
        wrapped_file_key:
            Encrypted file key including authentication tag.

        nonce:
            12-byte wrapping nonce.

        recovery_secret:
            32-byte recovery secret.

    Returns:
        bytes:
            Original 32-byte file encryption key.

    Raises:
        InvalidRecoveryKeyError:
            If the recovery key is incorrect or the wrapped
            data has been modified.
    """

    if not isinstance(
        wrapped_file_key,
        bytes,
    ):
        raise TypeError(
            "Wrapped file key must be bytes."
        )

    if not isinstance(
        nonce,
        bytes,
    ):
        raise TypeError(
            "Nonce must be bytes."
        )

    if len(nonce) != WRAP_NONCE_SIZE:
        raise ValueError(
            f"Nonce must be exactly "
            f"{WRAP_NONCE_SIZE} bytes."
        )

    if len(wrapped_file_key) < 16:
        raise InvalidRecoveryKeyError(
            "Wrapped recovery data is invalid."
        )

    wrap_key = derive_recovery_wrap_key(
        recovery_secret
    )

    try:

        file_key = AESGCM(
            wrap_key
        ).decrypt(
            nonce,
            wrapped_file_key,
            RECOVERY_AAD,
        )

    except InvalidTag as exc:

        raise InvalidRecoveryKeyError(
            "Invalid recovery key or corrupted "
            "recovery data."
        ) from exc

    if len(file_key) != RECOVERY_KEY_SIZE:
        raise InvalidRecoveryKeyError(
            "Recovered file key has an invalid length."
        )

    return file_key