"""
CipherForge
-----------
Authenticated encryption primitives.

Supported algorithms:

    AES-256-GCM
    ChaCha20-Poly1305

This module is intentionally independent from:

    - GUI
    - file handling
    - folder handling
    - recovery-key storage
    - container format

Those components will be implemented separately.
"""

from __future__ import annotations

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)

from .exceptions import (
    AuthenticationError,
    UnsupportedAlgorithmError,
)


# ============================================================================
# Supported algorithms
# ============================================================================

AES_256_GCM = "AES-256-GCM"
CHACHA20_POLY1305 = "ChaCha20-Poly1305"


ALGORITHM_IDS: dict[str, int] = {
    AES_256_GCM: 1,
    CHACHA20_POLY1305: 2,
}


ID_TO_ALGORITHM: dict[int, str] = {
    value: key
    for key, value in ALGORITHM_IDS.items()
}


# ============================================================================
# Cryptographic sizes
# ============================================================================

# AES-256 / ChaCha20 both use a 256-bit key.
KEY_SIZE = 32

# GCM and ChaCha20-Poly1305 use a 96-bit nonce.
NONCE_SIZE = 12

# We use a 32-bit random prefix plus a 64-bit chunk counter.
NONCE_PREFIX_SIZE = 4

# AEAD authentication tag size.
# cryptography's AESGCM and ChaCha20Poly1305 append this automatically.
AUTH_TAG_SIZE = 16


# ============================================================================
# Algorithm helpers
# ============================================================================

def is_supported_algorithm(
    algorithm: str,
) -> bool:
    """
    Check whether an algorithm is supported by CipherForge.
    """

    return algorithm in ALGORITHM_IDS


def get_algorithm_id(
    algorithm: str,
) -> int:
    """
    Convert algorithm name to its compact numeric identifier.
    """

    try:
        return ALGORITHM_IDS[algorithm]

    except KeyError as exc:
        raise UnsupportedAlgorithmError(
            f"Unsupported encryption algorithm: {algorithm}"
        ) from exc


def get_algorithm_name(
    algorithm_id: int,
) -> str:
    """
    Convert numeric algorithm identifier back to its name.
    """

    try:
        return ID_TO_ALGORITHM[algorithm_id]

    except KeyError as exc:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm ID: {algorithm_id}"
        ) from exc


# ============================================================================
# Key generation
# ============================================================================

def generate_file_key() -> bytes:
    """
    Generate a cryptographically secure random 256-bit key.

    This key will eventually be used to encrypt the actual file data.

    Returns:
        32 random bytes.
    """

    return os.urandom(
        KEY_SIZE
    )


# ============================================================================
# Nonce generation
# ============================================================================

def generate_nonce_prefix() -> bytes:
    """
    Generate a random 32-bit nonce prefix.

    For streaming/chunk encryption, the final nonce is constructed as:

        4-byte random prefix
        +
        8-byte chunk counter

    Result:
        12-byte / 96-bit nonce.
    """

    return os.urandom(
        NONCE_PREFIX_SIZE
    )


def create_chunk_nonce(
    prefix: bytes,
    chunk_index: int,
) -> bytes:
    """
    Create a unique 96-bit nonce for a specific chunk.

    Args:
        prefix:
            4-byte random nonce prefix.

        chunk_index:
            Zero-based chunk number.

    Returns:
        12-byte nonce.

    Example:

        prefix = random 4 bytes
        chunk 0 -> prefix + 0000000000000000
        chunk 1 -> prefix + 0000000000000001
        chunk 2 -> prefix + 0000000000000002
    """

    if not isinstance(prefix, bytes):
        raise TypeError(
            "Nonce prefix must be bytes."
        )

    if len(prefix) != NONCE_PREFIX_SIZE:
        raise ValueError(
            f"Nonce prefix must be exactly "
            f"{NONCE_PREFIX_SIZE} bytes."
        )

    if not isinstance(chunk_index, int):
        raise TypeError(
            "Chunk index must be an integer."
        )

    if chunk_index < 0:
        raise ValueError(
            "Chunk index cannot be negative."
        )

    # Unsigned 64-bit big-endian counter.
    counter = struct.pack(
        ">Q",
        chunk_index,
    )

    return prefix + counter


# ============================================================================
# Cipher factory
# ============================================================================

def _create_cipher(
    algorithm: str,
    key: bytes,
):
    """
    Create the requested AEAD cipher.

    Internal helper.
    """

    if not isinstance(key, bytes):
        raise TypeError(
            "Encryption key must be bytes."
        )

    if len(key) != KEY_SIZE:
        raise ValueError(
            f"Encryption key must be exactly "
            f"{KEY_SIZE} bytes."
        )

    if algorithm == AES_256_GCM:

        return AESGCM(key)

    if algorithm == CHACHA20_POLY1305:

        return ChaCha20Poly1305(key)

    raise UnsupportedAlgorithmError(
        f"Unsupported encryption algorithm: {algorithm}"
    )


# ============================================================================
# Encryption
# ============================================================================

def encrypt_chunk(
    algorithm: str,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """
    Encrypt one chunk using authenticated encryption.

    Args:
        algorithm:
            AES-256-GCM or ChaCha20-Poly1305.

        key:
            32-byte encryption key.

        nonce:
            Unique 12-byte nonce.

        plaintext:
            Data to encrypt.

        associated_data:
            Optional authenticated metadata that is NOT encrypted.

    Returns:
        Ciphertext followed by a 16-byte authentication tag.

    Important:
        The same key + nonce combination must NEVER be reused.
    """

    if not isinstance(plaintext, bytes):
        raise TypeError(
            "Plaintext must be bytes."
        )

    if not isinstance(associated_data, bytes):
        raise TypeError(
            "Associated data must be bytes."
        )

    if not isinstance(nonce, bytes):
        raise TypeError(
            "Nonce must be bytes."
        )

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"Nonce must be exactly "
            f"{NONCE_SIZE} bytes."
        )

    cipher = _create_cipher(
        algorithm,
        key,
    )

    return cipher.encrypt(
        nonce,
        plaintext,
        associated_data,
    )


# ============================================================================
# Decryption
# ============================================================================

def decrypt_chunk(
    algorithm: str,
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """
    Decrypt and authenticate one chunk.

    Args:
        algorithm:
            AES-256-GCM or ChaCha20-Poly1305.

        key:
            32-byte encryption key.

        nonce:
            Unique 12-byte nonce used during encryption.

        ciphertext:
            Ciphertext including authentication tag.

        associated_data:
            The exact same authenticated metadata supplied
            during encryption.

    Returns:
        Original plaintext.

    Raises:
        AuthenticationError:
            If authentication fails.

    Authentication failure normally means:

        - wrong key
        - modified ciphertext
        - modified associated data
        - incorrect nonce
    """

    if not isinstance(ciphertext, bytes):
        raise TypeError(
            "Ciphertext must be bytes."
        )

    if not isinstance(associated_data, bytes):
        raise TypeError(
            "Associated data must be bytes."
        )

    if not isinstance(nonce, bytes):
        raise TypeError(
            "Nonce must be bytes."
        )

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"Nonce must be exactly "
            f"{NONCE_SIZE} bytes."
        )

    if len(ciphertext) < AUTH_TAG_SIZE:
        raise AuthenticationError(
            "Ciphertext is too short."
        )

    cipher = _create_cipher(
        algorithm,
        key,
    )

    try:

        return cipher.decrypt(
            nonce,
            ciphertext,
            associated_data,
        )

    except InvalidTag as exc:

        raise AuthenticationError(
            "Authentication failed. "
            "The encryption key may be incorrect, "
            "or the encrypted data may have been modified."
        ) from exc