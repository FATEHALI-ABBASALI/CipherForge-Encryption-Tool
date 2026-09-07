"""
CipherForge - File Encryption Engine
====================================

Step 9
------

Supports:

    AES-256-GCM
    ChaCha20-Poly1305

Architecture:

    Password / Recovery Key
            |
            v
       Key Manager
            |
            v
       Random File Key
            |
            v
      File Encryption
            |
            v
     CipherForge Container

The encrypted container stores:

    - magic
    - version
    - algorithm
    - original filename
    - key envelope
    - file nonce
    - encrypted file data

It NEVER stores:

    - plaintext password
    - plaintext recovery secret
    - plaintext file encryption key
"""

from __future__ import annotations

import base64
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidTag

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)

from .key_manager import (
    KeyEnvelope,
    InvalidKeyEnvelopeError,
    InvalidPasswordError,
    InvalidRecoveryKeyError,
    create_key_envelope,
    unlock_with_password,
    unlock_with_recovery_key,
)


# ============================================================================
# CONSTANTS
# ============================================================================

MAGIC = b"CFENC001"

CONTAINER_VERSION = 2
LEGACY_CONTAINER_VERSION = 1

NONCE_SIZE = 12

KEY_SIZE = 32

HEADER_LENGTH_SIZE = 8

CHUNK_SIZE = 1024 * 1024

MAX_HEADER_SIZE = 16 * 1024 * 1024

ALGORITHM_AES256_GCM = "AES-256-GCM"

ALGORITHM_CHACHA20_POLY1305 = "ChaCha20-Poly1305"

SUPPORTED_ALGORITHMS = {
    ALGORITHM_AES256_GCM,
    ALGORITHM_CHACHA20_POLY1305,
}

# Type alias for callers / GUI.
AlgorithmName = Literal[
    "AES-256-GCM",
    "ChaCha20-Poly1305",
]


# ============================================================================
# EXCEPTIONS
# ============================================================================

class FileCryptoError(Exception):
    """Base exception for file encryption errors."""


class UnsupportedAlgorithmError(FileCryptoError):
    """Unsupported encryption algorithm."""


class InvalidContainerError(FileCryptoError):
    """Encrypted container is malformed."""


class AuthenticationError(FileCryptoError):
    """Encrypted data authentication failed."""


class FileEncryptionError(FileCryptoError):
    """File encryption operation failed."""


class FileDecryptionError(FileCryptoError):
    """File decryption operation failed."""


# ============================================================================
# ALGORITHM HELPERS
# ============================================================================

def validate_algorithm(
    algorithm: str,
) -> str:
    """
    Validate and normalize an encryption algorithm.
    """

    if not isinstance(
        algorithm,
        str,
    ):
        raise UnsupportedAlgorithmError(
            "Algorithm must be a string."
        )

    normalized = algorithm.strip()

    if normalized not in SUPPORTED_ALGORITHMS:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {algorithm}"
        )

    return normalized


def _create_cipher(
    algorithm: str,
    key: bytes,
):
    """
    Create the selected AEAD cipher.
    """

    algorithm = validate_algorithm(
        algorithm
    )

    if len(key) != KEY_SIZE:
        raise ValueError(
            "Encryption key must be exactly 32 bytes."
        )

    if algorithm == ALGORITHM_AES256_GCM:
        return AESGCM(key)

    if algorithm == ALGORITHM_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)

    raise UnsupportedAlgorithmError(
        f"Unsupported algorithm: {algorithm}"
    )


# ============================================================================
# HEADER HELPERS
# ============================================================================

def _encode_header(
    header: dict,
) -> bytes:
    """
    Serialize container header.
    """

    try:

        data = json.dumps(
            header,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    except (
        TypeError,
        ValueError,
    ) as exc:

        raise InvalidContainerError(
            "Could not serialize encrypted-file header."
        ) from exc

    if len(data) > MAX_HEADER_SIZE:
        raise InvalidContainerError(
            "Encrypted-file header is too large."
        )

    return data


def _decode_header(
    data: bytes,
) -> dict:
    """
    Deserialize container header.
    """

    if not isinstance(
        data,
        bytes,
    ):
        raise InvalidContainerError(
            "Header must be bytes."
        )

    if not data:
        raise InvalidContainerError(
            "Encrypted-file header is empty."
        )

    if len(data) > MAX_HEADER_SIZE:
        raise InvalidContainerError(
            "Encrypted-file header is too large."
        )

    try:

        header = json.loads(
            data.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:

        raise InvalidContainerError(
            "Encrypted-file header is invalid."
        ) from exc

    if not isinstance(
        header,
        dict,
    ):
        raise InvalidContainerError(
            "Encrypted-file header must be an object."
        )

    return header


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
        raise InvalidContainerError(
            "Encoded container value must be text."
        )

    try:

        return base64.urlsafe_b64decode(
            value.encode("ascii")
        )

    except Exception as exc:

        raise InvalidContainerError(
            "Invalid Base64 container value."
        ) from exc


# ============================================================================
# ORIGINAL FILENAME
# ============================================================================

def _safe_original_name(
    source: Path,
) -> str:
    """
    Store only the original filename.

    We deliberately do not store the original directory.
    """

    name = source.name

    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise FileEncryptionError(
            "Source file has no valid filename."
        )

    return name


# ============================================================================
# CONTAINER HEADER
# ============================================================================

def _build_header(
    *,
    algorithm: str,
    original_filename: str,
    envelope: KeyEnvelope,
    nonce_prefix: bytes,
    plaintext_size: int,
) -> dict:

    algorithm = validate_algorithm(
        algorithm
    )

    if len(nonce_prefix) != 4:
        raise ValueError(
            "Nonce prefix must be exactly 4 bytes."
        )

    if plaintext_size < 0:
        raise ValueError(
            "Plaintext size cannot be negative."
        )

    return {
        "format": "CipherForge",
        "version": CONTAINER_VERSION,
        "type": "file",
        "algorithm": algorithm,
        "original_filename": original_filename,
        "plaintext_size": plaintext_size,
        "nonce_prefix": _b64_encode(nonce_prefix),
        "chunk_size": CHUNK_SIZE,
        "key_envelope": envelope.to_dict(),
    }


# ============================================================================
# HEADER VALIDATION
# ============================================================================

def _validate_header(
    header: dict,
) -> None:

    if header.get("format") != "CipherForge":
        raise InvalidContainerError(
            "Not a CipherForge encrypted file."
        )

    if header.get("version") not in {LEGACY_CONTAINER_VERSION, CONTAINER_VERSION}:
        raise InvalidContainerError(
            "Unsupported CipherForge container version."
        )

    if header.get("type") != "file":
        raise InvalidContainerError(
            "Container is not a file container."
        )

    algorithm = header.get(
        "algorithm"
    )

    validate_algorithm(
        algorithm
    )

    filename = header.get(
        "original_filename"
    )

    if not isinstance(
        filename,
        str,
    ) or not filename or filename in {".", ".."} or "/" in filename or "\\" in filename:

        raise InvalidContainerError(
            "Original filename is invalid."
        )

    plaintext_size = header.get(
        "plaintext_size"
    )

    if not isinstance(
        plaintext_size,
        int,
    ) or isinstance(plaintext_size, bool) or plaintext_size < 0:

        raise InvalidContainerError(
            "Plaintext size is invalid."
        )

    if header["version"] == LEGACY_CONTAINER_VERSION:
        nonce = _b64_decode(header.get("nonce"))
        if len(nonce) != NONCE_SIZE:
            raise InvalidContainerError("Container nonce has invalid length.")
    else:
        prefix = _b64_decode(header.get("nonce_prefix"))
        if len(prefix) != 4 or header.get("chunk_size") != CHUNK_SIZE:
            raise InvalidContainerError("Container chunk metadata is invalid.")

    envelope_value = header.get(
        "key_envelope"
    )

    if not isinstance(
        envelope_value,
        dict,
    ):
        raise InvalidContainerError(
            "Key envelope is missing."
        )

    try:

        KeyEnvelope.from_dict(
            envelope_value
        )

    except InvalidKeyEnvelopeError as exc:

        raise InvalidContainerError(
            "Key envelope is invalid."
        ) from exc


# ============================================================================
# FILE HEADER WRITING
# ============================================================================

def _write_container_header(
    output,
    header_bytes: bytes,
) -> None:

    output.write(
        MAGIC
    )

    output.write(
        struct.pack(
            ">Q",
            len(header_bytes),
        )
    )

    output.write(
        header_bytes
    )


# ============================================================================
# FILE HEADER READING
# ============================================================================

def _read_exact(
    file_object,
    size: int,
) -> bytes:

    data = file_object.read(
        size
    )

    if len(data) != size:
        raise InvalidContainerError(
            "Unexpected end of encrypted file."
        )

    return data


def _read_container_header(
    input_file,
) -> dict:

    magic = _read_exact(
        input_file,
        len(MAGIC),
    )

    if magic != MAGIC:
        raise InvalidContainerError(
            "Invalid CipherForge file signature."
        )

    raw_header_length = _read_exact(
        input_file,
        HEADER_LENGTH_SIZE,
    )

    header_length = struct.unpack(
        ">Q",
        raw_header_length,
    )[0]

    if header_length <= 0:
        raise InvalidContainerError(
            "Invalid encrypted-file header length."
        )

    if header_length > MAX_HEADER_SIZE:
        raise InvalidContainerError(
            "Encrypted-file header is too large."
        )

    header_bytes = _read_exact(
        input_file,
        header_length,
    )

    header = _decode_header(
        header_bytes
    )

    _validate_header(
        header
    )

    return header


# ============================================================================
# ATOMIC OUTPUT
# ============================================================================

def _atomic_replace(
    temporary_path: Path,
    destination: Path,
) -> None:
    """
    Replace destination atomically where supported by OS.
    """

    os.replace(
        temporary_path,
        destination,
    )


def _temporary_path_for(
    destination: Path,
) -> Path:

    directory = destination.parent

    fd, temp_name = tempfile.mkstemp(
        prefix=".cipherforge-",
        suffix=".tmp",
        dir=directory,
    )

    os.close(fd)

    return Path(
        temp_name
    )


# ============================================================================
# ENCRYPT FILE
# ============================================================================

def encrypt_file(
    source_path: str | Path,
    destination_path: str | Path | None = None,
    *,
    password: str,
    algorithm: str = ALGORITHM_AES256_GCM,
) -> tuple[Path, str]:
    """
    Encrypt a single file.

    Parameters
    ----------
    source_path:
        File to encrypt.

    destination_path:
        Output encrypted file.
        If omitted, '.cfenc' is appended.

    password:
        User password.

    algorithm:
        AES-256-GCM or ChaCha20-Poly1305.

    Returns
    -------
    tuple[Path, str]

        (
            encrypted_file_path,
            recovery_key
        )

    The recovery key is returned as a displayable string.
    """

    source = Path(
        source_path
    )

    if not source.exists():
        raise FileEncryptionError(
            "Source file does not exist."
        )

    if not source.is_file():
        raise FileEncryptionError(
            "Source path is not a file."
        )

    algorithm = validate_algorithm(
        algorithm
    )

    if destination_path is None:

        destination = source.with_name(
            source.name + ".cfenc"
        )

    else:

        destination = Path(
            destination_path
        )

    if source.resolve() == destination.resolve():

        raise FileEncryptionError(
            "Source and destination cannot be the same file."
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    plaintext_size = source.stat().st_size

    # ------------------------------------------------------------------------
    # Create file key + password/recovery envelope.
    # ------------------------------------------------------------------------

    envelope, recovery_secret = (
        create_key_envelope(
            password=password
        )
    )

    # Extract the actual random file key through password unlock.
    #
    # This keeps the ownership of key creation inside key_manager.
    from .key_manager import unlock_with_password

    file_key = unlock_with_password(
        password,
        envelope,
    )

    # ------------------------------------------------------------------------
    # Generate file-data nonce.
    # ------------------------------------------------------------------------

    nonce_prefix = os.urandom(4)

    # ------------------------------------------------------------------------
    # Build metadata header.
    # ------------------------------------------------------------------------

    header = _build_header(
        algorithm=algorithm,
        original_filename=_safe_original_name(
            source
        ),
        envelope=envelope,
        nonce_prefix=nonce_prefix,
        plaintext_size=plaintext_size,
    )

    header_bytes = _encode_header(
        header
    )

    cipher = _create_cipher(
        algorithm,
        file_key,
    )

    temporary_path = _temporary_path_for(
        destination
    )

    try:

        with source.open(
            "rb"
        ) as input_file, temporary_path.open(
            "wb"
        ) as output_file:

            # ------------------------------------------------------------
            # Header
            # ------------------------------------------------------------

            _write_container_header(
                output_file,
                header_bytes,
            )

            # Encrypt bounded chunks.  The chunk counter is part of the
            # nonce and AAD, so every AEAD invocation has a unique nonce.
            chunk_index = 0
            while True:
                plaintext = input_file.read(CHUNK_SIZE)
                if not plaintext and chunk_index:
                    break

                nonce = nonce_prefix + struct.pack(">Q", chunk_index)
                aad = header_bytes + struct.pack(">Q", chunk_index)
                ciphertext = cipher.encrypt(nonce, plaintext, aad)
                output_file.write(struct.pack(">I", len(ciphertext)))
                output_file.write(ciphertext)
                chunk_index += 1

                # An empty file still has an authenticated empty chunk.
                if not plaintext:
                    break

            output_file.flush()

            os.fsync(
                output_file.fileno()
            )

        _atomic_replace(
            temporary_path,
            destination,
        )

    except Exception as exc:

        try:

            temporary_path.unlink(
                missing_ok=True
            )

        except OSError:
            pass

        if isinstance(
            exc,
            FileCryptoError,
        ):
            raise

        raise FileEncryptionError(
            f"File encryption failed: {exc}"
        ) from exc

    # ------------------------------------------------------------------------
    # Return human-readable recovery key.
    # ------------------------------------------------------------------------

    from .key_manager import format_recovery_key

    recovery_key = format_recovery_key(
        recovery_secret
    )

    return (
        destination,
        recovery_key,
    )


# ============================================================================
# READ HEADER PUBLIC API
# ============================================================================

def read_encrypted_header(
    encrypted_path: str | Path,
) -> dict:
    """
    Read and validate the header of an encrypted file.

    Does NOT decrypt the file.
    """

    encrypted = Path(
        encrypted_path
    )

    if not encrypted.exists():
        raise FileCryptoError(
            "Encrypted file does not exist."
        )

    if not encrypted.is_file():
        raise FileCryptoError(
            "Encrypted path is not a file."
        )

    try:

        with encrypted.open(
            "rb"
        ) as input_file:

            return _read_container_header(
                input_file
            )

    except InvalidContainerError:
        raise

    except OSError as exc:

        raise FileCryptoError(
            f"Could not read encrypted file: {exc}"
        ) from exc


# ============================================================================
# DECRYPT FILE
# ============================================================================

def decrypt_file(
    encrypted_path: str | Path,
    destination_path: str | Path | None = None,
    *,
    password: str | None = None,
    recovery_key: str | None = None,
) -> Path:
    """
    Decrypt a CipherForge encrypted file.

    Exactly one of:

        password
        recovery_key

    must be provided.

    Returns:
        Path to decrypted file.
    """

    encrypted = Path(
        encrypted_path
    )

    if not encrypted.exists():
        raise FileDecryptionError(
            "Encrypted file does not exist."
        )

    if not encrypted.is_file():
        raise FileDecryptionError(
            "Encrypted path is not a file."
        )

    if password is None and recovery_key is None:
        raise FileDecryptionError(
            "Password or recovery key is required."
        )

    if password is not None and recovery_key is not None:
        raise FileDecryptionError(
            "Provide password OR recovery key, not both."
        )

    try:

        with encrypted.open(
            "rb"
        ) as input_file:

            header = _read_container_header(
                input_file
            )

            header_bytes = _encode_header(
                header
            )

            algorithm = header[
                "algorithm"
            ]

            legacy_nonce = (
                _b64_decode(header["nonce"])
                if header["version"] == LEGACY_CONTAINER_VERSION
                else None
            )

            envelope = KeyEnvelope.from_dict(
                header["key_envelope"]
            )

            if password is not None:

                file_key = unlock_with_password(
                    password,
                    envelope,
                )

            else:

                file_key = unlock_with_recovery_key(
                    recovery_key,
                    envelope,
                )

            cipher = _create_cipher(
                algorithm,
                file_key,
            )

            legacy_ciphertext = (
                input_file.read()
                if header["version"] == LEGACY_CONTAINER_VERSION
                else None
            )

    except (
        InvalidPasswordError,
        InvalidRecoveryKeyError,
    ):

        raise

    except (
        InvalidContainerError,
        InvalidKeyEnvelopeError,
    ) as exc:

        raise FileDecryptionError(
            str(exc)
        ) from exc

    except OSError as exc:

        raise FileDecryptionError(
            f"Could not read encrypted file: {exc}"
        ) from exc

    # ------------------------------------------------------------------------
    # Decrypt/authenticate
    # ------------------------------------------------------------------------

    # ------------------------------------------------------------------------
    # Destination
    # ------------------------------------------------------------------------

    if destination_path is None:

        original_filename = header[
            "original_filename"
        ]

        destination = encrypted.with_name(
            original_filename
        )

        # Avoid overwriting the encrypted file itself.
        if destination.resolve() == encrypted.resolve():

            destination = encrypted.with_name(
                encrypted.stem + ".decrypted"
            )

    else:

        destination = Path(
            destination_path
        )

    if destination.resolve() == encrypted.resolve():

        raise FileDecryptionError(
            "Encrypted source and decrypted destination cannot be the same."
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = _temporary_path_for(
        destination
    )

    try:

        with temporary_path.open("wb") as output_file:
            expected_size = header["plaintext_size"]
            if header["version"] == LEGACY_CONTAINER_VERSION:
                try:
                    plaintext = cipher.decrypt(legacy_nonce, legacy_ciphertext, header_bytes)
                except InvalidTag as exc:
                    raise AuthenticationError(
                        "Encrypted data authentication failed."
                    ) from exc
                output_file.write(plaintext)
                bytes_written = len(plaintext)
            else:
                bytes_written = 0
                chunk_index = 0
                with encrypted.open("rb") as input_file:
                    _read_container_header(input_file)
                    while True:
                        length_bytes = input_file.read(4)
                        if not length_bytes:
                            break
                        if len(length_bytes) != 4:
                            raise InvalidContainerError("Corrupted encrypted chunk length.")
                        chunk_length = struct.unpack(">I", length_bytes)[0]
                        if chunk_length < 16 or chunk_length > CHUNK_SIZE + 16:
                            raise InvalidContainerError("Encrypted chunk length is invalid.")
                        ciphertext = _read_exact(input_file, chunk_length)
                        nonce_prefix = _b64_decode(header["nonce_prefix"])
                        nonce = nonce_prefix + struct.pack(">Q", chunk_index)
                        aad = header_bytes + struct.pack(">Q", chunk_index)
                        try:
                            plaintext = cipher.decrypt(nonce, ciphertext, aad)
                        except InvalidTag as exc:
                            raise AuthenticationError("Encrypted data authentication failed.") from exc
                        if bytes_written + len(plaintext) > expected_size:
                            raise AuthenticationError("Decrypted file size exceeds authenticated metadata.")
                        output_file.write(plaintext)
                        bytes_written += len(plaintext)
                        chunk_index += 1
                if chunk_index == 0:
                    raise InvalidContainerError("Encrypted file has no authenticated chunks.")

            if bytes_written != expected_size:
                raise AuthenticationError("Decrypted file size does not match authenticated metadata.")

            output_file.flush()

            os.fsync(
                output_file.fileno()
            )

        _atomic_replace(
            temporary_path,
            destination,
        )

    except Exception as exc:

        try:

            temporary_path.unlink(
                missing_ok=True
            )

        except OSError:
            pass

        if isinstance(
            exc,
            FileCryptoError,
        ):
            raise

        raise FileDecryptionError(
            f"Could not write decrypted file: {exc}"
        ) from exc

    return destination
