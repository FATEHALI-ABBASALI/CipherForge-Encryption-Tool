"""
CipherForge - Key Management
============================

Security responsibilities:

- Generate random 256-bit file keys.
- Generate cryptographically secure recovery keys.
- Derive password wrapping keys using Argon2id.
- Derive recovery wrapping keys using HKDF-SHA256.
- Wrap the random file key using AES-256-GCM.
- Unlock the file key using password OR recovery key.
- Serialize/deserialize the key envelope.

The actual file/folder encryption is handled by other modules.

Security architecture:

    Password
       |
       v
    Argon2id
       |
       v
    256-bit wrapping key
       |
       v
    AES-256-GCM
       |
       v
    Random 256-bit File Key


    Recovery Key
       |
       v
    HKDF-SHA256
       |
       v
    256-bit wrapping key
       |
       v
    AES-256-GCM
       |
       v
    Random 256-bit File Key
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets

from dataclasses import dataclass
from typing import Any

from argon2.low_level import (
    Type,
    hash_secret_raw,
)

from cryptography.exceptions import InvalidTag

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes


# ============================================================================
# CONSTANTS
# ============================================================================

KEY_SIZE = 32

SALT_SIZE = 16

NONCE_SIZE = 12

RECOVERY_KEY_SIZE = 32

RECOVERY_DISPLAY_BYTES = 32

FORMAT = "CipherForge-KeyEnvelope"

VERSION = 1

PASSWORD_METHOD = "argon2id"

RECOVERY_METHOD = "hkdf-sha256"

WRAP_ALGORITHM = "AES-256-GCM"


# ============================================================================
# ARGON2ID PARAMETERS
# ============================================================================

# Practical desktop configuration.
#
# Memory: 64 MiB
# Time:   3 passes
# Lanes:  4
#
# This provides a strong password KDF while remaining practical
# for normal Windows/Linux desktop systems.

ARGON2_MEMORY_KIB = 64 * 1024

ARGON2_TIME_COST = 3

ARGON2_PARALLELISM = 4

ARGON2_HASH_LEN = 32

ARGON2_VERSION = 0x13


# ============================================================================
# DOMAIN SEPARATION
# ============================================================================

PASSWORD_WRAP_CONTEXT = (
    b"CipherForge/password-wrap/v1"
)

RECOVERY_WRAP_CONTEXT = (
    b"CipherForge/recovery-wrap/v1"
)


# ============================================================================
# EXCEPTIONS
# ============================================================================

class KeyManagerError(Exception):
    """Base exception for key management."""


class InvalidPasswordError(KeyManagerError):
    """Password could not unlock the file key."""


class InvalidRecoveryKeyError(KeyManagerError):
    """Recovery key is invalid or could not unlock the file key."""


class InvalidKeyEnvelopeError(KeyManagerError):
    """Key envelope is malformed or invalid."""


# ============================================================================
# KEY ENVELOPE
# ============================================================================

@dataclass(frozen=True)
class KeyEnvelope:
    """
    Serializable key envelope.

    IMPORTANT:
        The plaintext file key is NEVER stored here.
    """

    version: int

    password: dict[str, Any]

    recovery: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "version": self.version,
            "password": self.password,
            "recovery": self.recovery,
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
    ) -> "KeyEnvelope":

        if not isinstance(value, dict):
            raise InvalidKeyEnvelopeError(
                "Key envelope must be an object."
            )

        if value.get("format") != FORMAT:
            raise InvalidKeyEnvelopeError(
                "Unknown key envelope format."
            )

        version = value.get("version")

        if version != VERSION:
            raise InvalidKeyEnvelopeError(
                f"Unsupported key envelope version: {version}"
            )

        password = value.get("password")

        recovery = value.get("recovery")

        if not isinstance(password, dict):
            raise InvalidKeyEnvelopeError(
                "Password envelope is invalid."
            )

        if not isinstance(recovery, dict):
            raise InvalidKeyEnvelopeError(
                "Recovery envelope is invalid."
            )

        return cls(
            version=version,
            password=password,
            recovery=recovery,
        )

    @classmethod
    def from_json_bytes(
        cls,
        data: bytes,
    ) -> "KeyEnvelope":

        if not isinstance(data, bytes):
            raise TypeError(
                "Envelope data must be bytes."
            )

        try:

            value = json.loads(
                data.decode("utf-8")
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:

            raise InvalidKeyEnvelopeError(
                "Invalid key envelope JSON."
            ) from exc

        return cls.from_dict(value)


# ============================================================================
# BASE64 HELPERS
# ============================================================================

def _b64_encode(
    value: bytes,
) -> str:

    return base64.urlsafe_b64encode(
        value
    ).decode("ascii")


def _b64_decode(
    value: str,
) -> bytes:

    if not isinstance(
        value,
        str,
    ):
        raise InvalidKeyEnvelopeError(
            "Encoded value must be a string."
        )

    try:

        return base64.urlsafe_b64decode(
            value.encode("ascii")
        )

    except (
        ValueError,
        binascii.Error,
    ) as exc:

        raise InvalidKeyEnvelopeError(
            "Invalid Base64 data."
        ) from exc


# ============================================================================
# FILE KEY GENERATION
# ============================================================================

def generate_file_key() -> bytes:
    """
    Generate a cryptographically secure 256-bit file key.
    """

    return secrets.token_bytes(
        KEY_SIZE
    )


# ============================================================================
# RECOVERY KEY GENERATION
# ============================================================================

def generate_recovery_key_bytes() -> bytes:
    """
    Generate a cryptographically secure 256-bit recovery secret.
    """

    return secrets.token_bytes(
        RECOVERY_KEY_SIZE
    )


def format_recovery_key(
    recovery_key: bytes,
) -> str:
    """
    Convert raw recovery bytes into a human-friendly key.

    Example:

        CF-AOGNR-3XPG6-UOC52-...

    The actual secret remains 256 bits.
    """

    if not isinstance(
        recovery_key,
        bytes,
    ):
        raise TypeError(
            "Recovery key must be bytes."
        )

    if len(recovery_key) != RECOVERY_DISPLAY_BYTES:
        raise ValueError(
            "Recovery key must be exactly 32 bytes."
        )

    encoded = base64.b32encode(
        recovery_key
    ).decode(
        "ascii"
    ).rstrip("=")

    groups = [
        encoded[index:index + 5]
        for index in range(
            0,
            len(encoded),
            5,
        )
    ]

    return "CF-" + "-".join(groups)


# ============================================================================
# RECOVERY KEY PARSING
# ============================================================================

def parse_recovery_key(
    recovery_key: str,
) -> bytes:
    """
    Convert a displayed recovery key back to its raw 32-byte secret.

    Accepts:

        CF-XXXXX-XXXXX-XXXXX-...

    Also accepts:

        CF XXXXX XXXXX ...

    Hyphens and spaces are ignored.

    The CF prefix is optional internally, but normal user-generated
    CipherForge recovery keys always contain it.
    """

    if not isinstance(
        recovery_key,
        str,
    ):
        raise InvalidRecoveryKeyError(
            "Recovery key must be text."
        )

    normalized = (
        recovery_key
        .strip()
        .upper()
        .replace("-", "")
        .replace(" ", "")
    )

    # ------------------------------------------------------------
    # Remove CipherForge prefix.
    # ------------------------------------------------------------

    if normalized.startswith("CF"):
        normalized = normalized[2:]

    if not normalized:
        raise InvalidRecoveryKeyError(
            "Recovery key is empty."
        )

    # ------------------------------------------------------------
    # Validate Base32 alphabet.
    # ------------------------------------------------------------

    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    )

    for character in normalized:

        if character not in allowed:

            raise InvalidRecoveryKeyError(
                "Recovery key contains invalid characters."
            )

    # ------------------------------------------------------------
    # Expected Base32 length.
    #
    # 32 bytes -> 52 Base32 characters.
    # ------------------------------------------------------------

    expected_length = 52

    if len(normalized) != expected_length:

        raise InvalidRecoveryKeyError(
            "Recovery key has an invalid length."
        )

    # ------------------------------------------------------------
    # IMPORTANT:
    #
    # Base32 requires padding to a multiple of 8 characters.
    #
    # 52 % 8 = 4
    #
    # Therefore:
    #
    # 52 + 4 "=" = 56
    # ------------------------------------------------------------

    remainder = len(normalized) % 8

    if remainder == 0:

        padding = ""

    else:

        padding = "=" * (
            8 - remainder
        )

    encoded = (
        normalized
        + padding
    )

    try:

        decoded = base64.b32decode(
            encoded,
            casefold=True,
        )

    except (
        ValueError,
        binascii.Error,
    ) as exc:

        raise InvalidRecoveryKeyError(
            "Recovery key encoding is invalid."
        ) from exc

    # ------------------------------------------------------------
    # Final length check.
    # ------------------------------------------------------------

    if len(decoded) != RECOVERY_KEY_SIZE:

        raise InvalidRecoveryKeyError(
            "Recovery key has an invalid decoded length."
        )

    return decoded


# ============================================================================
# PASSWORD
# ============================================================================

def _password_bytes(
    password: str,
) -> bytes:
    """
    Convert password into UTF-8 bytes.

    No Unicode normalization is performed.

    The same exact password must be supplied during decryption.
    """

    if not isinstance(
        password,
        str,
    ):
        raise TypeError(
            "Password must be a string."
        )

    if not password:

        raise ValueError(
            "Password cannot be empty."
        )

    return password.encode(
        "utf-8"
    )


# ============================================================================
# ARGON2ID
# ============================================================================

def derive_password_key(
    password: str,
    salt: bytes,
) -> bytes:
    """
    Derive a 256-bit wrapping key using Argon2id.
    """

    password_data = _password_bytes(
        password
    )

    if not isinstance(
        salt,
        bytes,
    ):
        raise TypeError(
            "Salt must be bytes."
        )

    if len(salt) != SALT_SIZE:

        raise ValueError(
            f"Salt must be exactly {SALT_SIZE} bytes."
        )

    return hash_secret_raw(
        secret=password_data,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


# ============================================================================
# RECOVERY KDF
# ============================================================================

def derive_recovery_key(
    recovery_secret: bytes,
) -> bytes:
    """
    Derive a 256-bit AES wrapping key from recovery secret.

    HKDF-SHA256 provides domain separation.
    """

    if not isinstance(
        recovery_secret,
        bytes,
    ):
        raise TypeError(
            "Recovery secret must be bytes."
        )

    if len(recovery_secret) != RECOVERY_KEY_SIZE:

        raise ValueError(
            "Recovery secret must be exactly 32 bytes."
        )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=RECOVERY_WRAP_CONTEXT,
    ).derive(
        recovery_secret
    )


# ============================================================================
# AES-256-GCM WRAPPING
# ============================================================================

def _wrap_file_key(
    wrapping_key: bytes,
    file_key: bytes,
    context: bytes,
) -> tuple[bytes, bytes]:
    """
    Encrypt a file key using AES-256-GCM.
    """

    if len(wrapping_key) != KEY_SIZE:

        raise ValueError(
            "Wrapping key must be exactly 32 bytes."
        )

    if len(file_key) != KEY_SIZE:

        raise ValueError(
            "File key must be exactly 32 bytes."
        )

    nonce = secrets.token_bytes(
        NONCE_SIZE
    )

    cipher = AESGCM(
        wrapping_key
    )

    ciphertext = cipher.encrypt(
        nonce,
        file_key,
        context,
    )

    return (
        nonce,
        ciphertext,
    )


def _unwrap_file_key(
    wrapping_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    context: bytes,
) -> bytes:
    """
    Decrypt a wrapped file key.
    """

    if len(wrapping_key) != KEY_SIZE:

        raise ValueError(
            "Wrapping key must be exactly 32 bytes."
        )

    if len(nonce) != NONCE_SIZE:

        raise InvalidKeyEnvelopeError(
            "Invalid wrapping nonce."
        )

    if len(ciphertext) < 16:

        raise InvalidKeyEnvelopeError(
            "Wrapped key ciphertext is too short."
        )

    cipher = AESGCM(
        wrapping_key
    )

    try:

        file_key = cipher.decrypt(
            nonce,
            ciphertext,
            context,
        )

    except InvalidTag as exc:

        raise InvalidKeyEnvelopeError(
            "Key authentication failed."
        ) from exc

    if len(file_key) != KEY_SIZE:

        raise InvalidKeyEnvelopeError(
            "Recovered file key has invalid length."
        )

    return file_key


# ============================================================================
# PASSWORD ENVELOPE
# ============================================================================

def _create_password_envelope(
    password: str,
    file_key: bytes,
) -> dict[str, Any]:
    """
    Create password-protected file-key record.
    """

    salt = secrets.token_bytes(
        SALT_SIZE
    )

    derived_key = derive_password_key(
        password,
        salt,
    )

    nonce, ciphertext = _wrap_file_key(
        wrapping_key=derived_key,
        file_key=file_key,
        context=PASSWORD_WRAP_CONTEXT,
    )

    return {
        "method": PASSWORD_METHOD,
        "algorithm": WRAP_ALGORITHM,
        "salt": _b64_encode(salt),
        "nonce": _b64_encode(nonce),
        "ciphertext": _b64_encode(ciphertext),
        "argon2": {
            "memory_kib": ARGON2_MEMORY_KIB,
            "time_cost": ARGON2_TIME_COST,
            "parallelism": ARGON2_PARALLELISM,
            "hash_len": ARGON2_HASH_LEN,
            "version": ARGON2_VERSION,
        },
    }


def _unwrap_with_password(
    password: str,
    envelope: dict[str, Any],
) -> bytes:
    """
    Recover file key using password.
    """

    if envelope.get(
        "method"
    ) != PASSWORD_METHOD:

        raise InvalidKeyEnvelopeError(
            "Unsupported password key method."
        )

    try:

        salt = _b64_decode(
            envelope["salt"]
        )

        nonce = _b64_decode(
            envelope["nonce"]
        )

        ciphertext = _b64_decode(
            envelope["ciphertext"]
        )

    except KeyError as exc:

        raise InvalidKeyEnvelopeError(
            "Password envelope is incomplete."
        ) from exc

    if len(salt) != SALT_SIZE:

        raise InvalidKeyEnvelopeError(
            "Password salt has invalid length."
        )

    try:

        derived_key = derive_password_key(
            password,
            salt,
        )

        return _unwrap_file_key(
            wrapping_key=derived_key,
            nonce=nonce,
            ciphertext=ciphertext,
            context=PASSWORD_WRAP_CONTEXT,
        )

    except (
        InvalidKeyEnvelopeError,
        ValueError,
        TypeError,
    ) as exc:

        raise InvalidPasswordError(
            "Password could not unlock the file key."
        ) from exc


# ============================================================================
# RECOVERY ENVELOPE
# ============================================================================

def _create_recovery_envelope(
    recovery_secret: bytes,
    file_key: bytes,
) -> dict[str, Any]:
    """
    Create recovery-protected file-key record.
    """

    recovery_wrapping_key = derive_recovery_key(
        recovery_secret
    )

    nonce, ciphertext = _wrap_file_key(
        wrapping_key=recovery_wrapping_key,
        file_key=file_key,
        context=RECOVERY_WRAP_CONTEXT,
    )

    return {
        "method": RECOVERY_METHOD,
        "algorithm": WRAP_ALGORITHM,
        "nonce": _b64_encode(nonce),
        "ciphertext": _b64_encode(ciphertext),
    }


def _unwrap_with_recovery(
    recovery_secret: bytes,
    envelope: dict[str, Any],
) -> bytes:
    """
    Recover file key using recovery secret.
    """

    if envelope.get(
        "method"
    ) != RECOVERY_METHOD:

        raise InvalidKeyEnvelopeError(
            "Unsupported recovery key method."
        )

    try:

        nonce = _b64_decode(
            envelope["nonce"]
        )

        ciphertext = _b64_decode(
            envelope["ciphertext"]
        )

    except KeyError as exc:

        raise InvalidKeyEnvelopeError(
            "Recovery envelope is incomplete."
        ) from exc

    try:

        recovery_wrapping_key = derive_recovery_key(
            recovery_secret
        )

        return _unwrap_file_key(
            wrapping_key=recovery_wrapping_key,
            nonce=nonce,
            ciphertext=ciphertext,
            context=RECOVERY_WRAP_CONTEXT,
        )

    except (
        InvalidKeyEnvelopeError,
        ValueError,
        TypeError,
    ) as exc:

        raise InvalidRecoveryKeyError(
            "Recovery key could not unlock the file key."
        ) from exc


# ============================================================================
# CREATE COMPLETE ENVELOPE
# ============================================================================

def create_key_envelope(
    password: str,
    file_key: bytes | None = None,
    recovery_secret: bytes | None = None,
) -> tuple[KeyEnvelope, bytes]:
    """
    Create password + recovery protected key envelope.

    Returns:

        (
            KeyEnvelope,
            recovery_secret
        )

    The recovery secret should be immediately converted into
    a user-friendly recovery key using format_recovery_key().
    """

    if file_key is None:

        file_key = generate_file_key()

    if not isinstance(
        file_key,
        bytes,
    ):
        raise TypeError(
            "File key must be bytes."
        )

    if len(file_key) != KEY_SIZE:

        raise ValueError(
            "File key must be exactly 32 bytes."
        )

    if recovery_secret is None:

        recovery_secret = (
            generate_recovery_key_bytes()
        )

    if not isinstance(
        recovery_secret,
        bytes,
    ):
        raise TypeError(
            "Recovery secret must be bytes."
        )

    if len(recovery_secret) != RECOVERY_KEY_SIZE:

        raise ValueError(
            "Recovery secret must be exactly 32 bytes."
        )

    password_envelope = (
        _create_password_envelope(
            password=password,
            file_key=file_key,
        )
    )

    recovery_envelope = (
        _create_recovery_envelope(
            recovery_secret=recovery_secret,
            file_key=file_key,
        )
    )

    envelope = KeyEnvelope(
        version=VERSION,
        password=password_envelope,
        recovery=recovery_envelope,
    )

    return (
        envelope,
        recovery_secret,
    )


# ============================================================================
# PASSWORD UNLOCK
# ============================================================================

def unlock_with_password(
    password: str,
    envelope: KeyEnvelope,
) -> bytes:
    """
    Unlock file key using password.
    """

    if not isinstance(
        envelope,
        KeyEnvelope,
    ):
        raise TypeError(
            "Expected KeyEnvelope."
        )

    return _unwrap_with_password(
        password,
        envelope.password,
    )


# ============================================================================
# RECOVERY UNLOCK
# ============================================================================

def unlock_with_recovery_key(
    recovery_key: str,
    envelope: KeyEnvelope,
) -> bytes:
    """
    Unlock file key using displayed recovery key.
    """

    if not isinstance(
        envelope,
        KeyEnvelope,
    ):
        raise TypeError(
            "Expected KeyEnvelope."
        )

    recovery_secret = parse_recovery_key(
        recovery_key
    )

    return _unwrap_with_recovery(
        recovery_secret,
        envelope.recovery,
    )


# ============================================================================
# GENERIC UNLOCK
# ============================================================================

def unlock_file_key(
    *,
    password: str | None = None,
    recovery_key: str | None = None,
    envelope: KeyEnvelope,
) -> bytes:
    """
    Unlock file key using either password OR recovery key.

    Exactly one credential must be provided.
    """

    if password is None and recovery_key is None:

        raise KeyManagerError(
            "Password or recovery key is required."
        )

    if password is not None and recovery_key is not None:

        raise KeyManagerError(
            "Provide either password or recovery key, not both."
        )

    if password is not None:

        return unlock_with_password(
            password,
            envelope,
        )

    return unlock_with_recovery_key(
        recovery_key,
        envelope,
    )


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

def secure_compare(
    left: bytes,
    right: bytes,
) -> bool:
    """
    Constant-time byte comparison.
    """

    if not isinstance(
        left,
        bytes,
    ):

        return False

    if not isinstance(
        right,
        bytes,
    ):

        return False

    return hmac.compare_digest(
        left,
        right,
    )


def fingerprint_key(
    file_key: bytes,
) -> str:
    """
    Generate a short non-secret fingerprint.

    This fingerprint cannot be used to decrypt data.
    """

    if not isinstance(
        file_key,
        bytes,
    ):
        raise TypeError(
            "File key must be bytes."
        )

    if len(file_key) != KEY_SIZE:

        raise ValueError(
            "File key must be exactly 32 bytes."
        )

    digest = hashlib.sha256(
        b"CipherForge-Key-Fingerprint-v1"
        + file_key
    ).hexdigest()

    return digest[:16]