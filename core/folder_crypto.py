"""
CipherForge - Folder Crypto Engine
===================================

Step 10

Secure recursive folder encryption/decryption.

Supported algorithms:
    AES-256-GCM
    ChaCha20-Poly1305

Design:
    1. Generate one random 256-bit master key for the folder operation.
    2. Protect that master key using CipherForge Key Manager.
    3. Store an encrypted/authenticated manifest.
    4. Encrypt every file independently with a fresh nonce.
    5. Preserve relative paths and empty directories.
    6. Never store the original absolute folder path.
    7. Prevent path traversal during extraction.

The resulting file is:

    <folder-name>.cfd

This module intentionally does NOT modify or delete the original folder.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path, PurePosixPath
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
    generate_file_key,
    unlock_with_password,
    unlock_with_recovery_key,
)


# ============================================================================
# CONSTANTS
# ============================================================================

MAGIC = b"CFFOLDER1"

VERSION = 2

NONCE_SIZE = 12

KEY_SIZE = 32

HEADER_LENGTH_SIZE = 8

CHUNK_SIZE = 1024 * 1024

MAX_HEADER_SIZE = 32 * 1024 * 1024

MAX_MANIFEST_SIZE = 128 * 1024 * 1024

ALGORITHM_AES256_GCM = "AES-256-GCM"

ALGORITHM_CHACHA20_POLY1305 = "ChaCha20-Poly1305"

SUPPORTED_ALGORITHMS = {
    ALGORITHM_AES256_GCM,
    ALGORITHM_CHACHA20_POLY1305,
}

AlgorithmName = Literal[
    "AES-256-GCM",
    "ChaCha20-Poly1305",
]


# ============================================================================
# EXCEPTIONS
# ============================================================================

class FolderCryptoError(Exception):
    """Base exception for folder encryption."""


class FolderEncryptionError(FolderCryptoError):
    """Folder encryption failed."""


class FolderDecryptionError(FolderCryptoError):
    """Folder decryption failed."""


class InvalidFolderContainerError(FolderCryptoError):
    """Encrypted folder container is invalid."""


class FolderAuthenticationError(FolderCryptoError):
    """Authenticated folder data failed verification."""


class UnsupportedAlgorithmError(FolderCryptoError):
    """Unsupported encryption algorithm."""


class UnsafePathError(FolderCryptoError):
    """Manifest contains an unsafe path."""


# ============================================================================
# GENERAL HELPERS
# ============================================================================

def _validate_algorithm(
    algorithm: str,
) -> str:

    if not isinstance(
        algorithm,
        str,
    ):
        raise UnsupportedAlgorithmError(
            "Algorithm must be a string."
        )

    algorithm = algorithm.strip()

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {algorithm}"
        )

    return algorithm


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
        raise InvalidFolderContainerError(
            "Encoded value must be a string."
        )

    try:

        return base64.urlsafe_b64decode(
            value.encode("ascii")
        )

    except Exception as exc:

        raise InvalidFolderContainerError(
            "Invalid Base64 value."
        ) from exc


def _json_bytes(
    value: dict,
) -> bytes:

    try:

        data = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    except (
        TypeError,
        ValueError,
    ) as exc:

        raise InvalidFolderContainerError(
            "Could not serialize container metadata."
        ) from exc

    return data


def _read_exact(
    file_object,
    size: int,
) -> bytes:

    data = file_object.read(size)

    if len(data) != size:
        raise InvalidFolderContainerError(
            "Unexpected end of encrypted folder."
        )

    return data


# ============================================================================
# CIPHER
# ============================================================================

def _create_cipher(
    algorithm: str,
    key: bytes,
):

    algorithm = _validate_algorithm(
        algorithm
    )

    if len(key) != KEY_SIZE:
        raise ValueError(
            "Folder encryption key must be 32 bytes."
        )

    if algorithm == ALGORITHM_AES256_GCM:
        return AESGCM(key)

    if algorithm == ALGORITHM_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)

    raise UnsupportedAlgorithmError(
        algorithm
    )


# ============================================================================
# SAFE PATH HANDLING
# ============================================================================

def _relative_posix_path(
    root: Path,
    path: Path,
) -> str:

    relative = path.relative_to(
        root
    )

    parts = relative.parts

    if not parts:
        raise UnsafePathError(
            "Empty relative path."
        )

    for part in parts:

        if part in {
            "",
            ".",
            "..",
        }:
            raise UnsafePathError(
                f"Unsafe path component: {part!r}"
            )

    return PurePosixPath(
        *parts
    ).as_posix()


def _safe_destination_path(
    root: Path,
    relative_path: str,
) -> Path:
    """
    Convert a manifest path into a safe filesystem destination.

    Rejects:
        absolute paths
        ../ traversal
        Windows drive paths
        suspicious separators
    """

    if not isinstance(
        relative_path,
        str,
    ):
        raise UnsafePathError(
            "Manifest path must be a string."
        )

    if not relative_path:
        raise UnsafePathError(
            "Manifest path is empty."
        )

    # Normalize both slash styles for validation.
    normalized = relative_path.replace(
        "\\",
        "/",
    )

    pure = PurePosixPath(
        normalized
    )

    if pure.is_absolute():
        raise UnsafePathError(
            f"Absolute path rejected: {relative_path}"
        )

    # Windows drive-like path.
    if len(normalized) >= 2 and normalized[1] == ":":
        raise UnsafePathError(
            f"Drive path rejected: {relative_path}"
        )

    for part in pure.parts:

        if part in {
            "",
            ".",
        }:
            continue

        if part == "..":
            raise UnsafePathError(
                f"Path traversal rejected: {relative_path}"
            )

    destination = root.joinpath(
        *pure.parts
    )

    root_resolved = root.resolve()

    destination_resolved = destination.resolve()

    try:

        destination_resolved.relative_to(
            root_resolved
        )

    except ValueError as exc:

        raise UnsafePathError(
            f"Destination escapes extraction root: {relative_path}"
        ) from exc

    return destination


# ============================================================================
# MANIFEST CREATION
# ============================================================================

def _build_manifest(
    folder: Path,
) -> tuple[list[dict], list[dict]]:
    """
    Return:

        files
        directories
    """

    files: list[dict] = []

    directories: list[dict] = []

    for current_root, dir_names, file_names in os.walk(
        folder
    ):

        current_path = Path(
            current_root
        )

        # Deterministic ordering.
        dir_names.sort()

        file_names.sort()

        # Preserve empty directories.
        for directory_name in dir_names:

            directory_path = (
                current_path / directory_name
            )

            relative = _relative_posix_path(
                folder,
                directory_path,
            )

            directories.append(
                {
                    "path": relative,
                }
            )

        for file_name in file_names:

            file_path = (
                current_path / file_name
            )

            if not file_path.is_file():
                continue

            relative = _relative_posix_path(
                folder,
                file_path,
            )

            size = file_path.stat().st_size

            files.append(
                {
                    "path": relative,
                    "size": size,
                }
            )

    return (
        files,
        directories,
    )


# ============================================================================
# CONTAINER HEADER
# ============================================================================

def _write_header(
    output,
    header: dict,
) -> bytes:

    header_bytes = _json_bytes(
        header
    )

    if len(header_bytes) > MAX_HEADER_SIZE:
        raise FolderEncryptionError(
            "Folder header is too large."
        )

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

    return header_bytes


def _read_header(
    input_file,
) -> tuple[dict, bytes]:

    magic = _read_exact(
        input_file,
        len(MAGIC),
    )

    if magic != MAGIC:
        raise InvalidFolderContainerError(
            "Invalid CipherForge folder signature."
        )

    raw_length = _read_exact(
        input_file,
        HEADER_LENGTH_SIZE,
    )

    header_length = struct.unpack(
        ">Q",
        raw_length,
    )[0]

    if header_length <= 0:
        raise InvalidFolderContainerError(
            "Invalid header length."
        )

    if header_length > MAX_HEADER_SIZE:
        raise InvalidFolderContainerError(
            "Folder header is too large."
        )

    header_bytes = _read_exact(
        input_file,
        header_length,
    )

    try:

        header = json.loads(
            header_bytes.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:

        raise InvalidFolderContainerError(
            "Folder header is invalid."
        ) from exc

    if not isinstance(
        header,
        dict,
    ):
        raise InvalidFolderContainerError(
            "Folder header must be an object."
        )

    _validate_header(
        header
    )

    return (
        header,
        header_bytes,
    )


def _validate_header(
    header: dict,
) -> None:

    if header.get("format") != "CipherForge":
        raise InvalidFolderContainerError(
            "Not a CipherForge folder."
        )

    if header.get("version") != VERSION:
        raise InvalidFolderContainerError(
            "Unsupported folder container version."
        )

    if header.get("type") != "folder":
        raise InvalidFolderContainerError(
            "Container is not a folder container."
        )

    _validate_algorithm(
        header.get("algorithm")
    )

    folder_name = header.get(
        "folder_name"
    )

    if not isinstance(
        folder_name,
        str,
    ) or not folder_name:

        raise InvalidFolderContainerError(
            "Invalid folder name."
        )

    envelope = header.get(
        "key_envelope"
    )

    if not isinstance(
        envelope,
        dict,
    ):
        raise InvalidFolderContainerError(
            "Missing key envelope."
        )

    try:

        KeyEnvelope.from_dict(
            envelope
        )

    except InvalidKeyEnvelopeError as exc:

        raise InvalidFolderContainerError(
            "Invalid key envelope."
        ) from exc


# ============================================================================
# RECORD FORMAT
# ============================================================================

def _write_record(
    output,
    record_type: int,
    path_bytes: bytes,
    payload: bytes,
) -> None:

    output.write(
        struct.pack(
            ">BQQ",
            record_type,
            len(path_bytes),
            len(payload),
        )
    )

    output.write(
        path_bytes
    )

    output.write(
        payload
    )


def _update_manifest_digest(digest, record_type: int, path_bytes: bytes, payload: bytes) -> None:
    """Bind every record, including directory-only records, into the commit."""
    digest.update(struct.pack(">B", record_type))
    digest.update(struct.pack(">Q", len(path_bytes)))
    digest.update(path_bytes)
    digest.update(hashlib.sha256(payload).digest())


def _read_record(
    input_file,
) -> tuple[int, str, bytes]:

    raw = input_file.read(
        17
    )

    if not raw:
        raise EOFError

    if len(raw) != 17:
        raise InvalidFolderContainerError(
            "Incomplete folder record."
        )

    record_type, path_length, payload_length = (
        struct.unpack(
            ">BQQ",
            raw,
        )
    )

    if record_type not in {1, 2, 3}:
        raise InvalidFolderContainerError(
            "Unknown folder record type."
        )

    if record_type != 3 and path_length <= 0:
        raise InvalidFolderContainerError(
            "Invalid record path length."
        )

    if path_length > 1024 * 1024:
        raise InvalidFolderContainerError(
            "Record path is too large."
        )

    if payload_length > MAX_MANIFEST_SIZE:
        raise InvalidFolderContainerError(
            "Record payload is too large."
        )

    path_bytes = _read_exact(
        input_file,
        path_length,
    )

    try:

        relative_path = path_bytes.decode(
            "utf-8"
        )

    except UnicodeDecodeError as exc:

        raise InvalidFolderContainerError(
            "Record path is not valid UTF-8."
        ) from exc

    payload = _read_exact(
        input_file,
        payload_length,
    )

    return (
        record_type,
        relative_path,
        payload,
    )


# ============================================================================
# ENCRYPTED FILE RECORD
# ============================================================================

def _encrypt_file_payload(
    file_path: Path,
    *,
    cipher,
    nonce: bytes,
    aad: bytes,
) -> bytes:
    """
    Step 10 uses one AEAD message per file.

    The file is read as bytes and encrypted/authenticated together.
    """

    plaintext = file_path.read_bytes()

    return cipher.encrypt(
        nonce,
        plaintext,
        aad,
    )


# ============================================================================
# FOLDER ENCRYPTION
# ============================================================================

def encrypt_folder(
    source_folder: str | Path,
    destination_path: str | Path | None = None,
    *,
    password: str,
    algorithm: str = ALGORITHM_AES256_GCM,
) -> tuple[Path, str]:
    """
    Encrypt a complete folder.

    Returns:

        (
            encrypted_folder_path,
            recovery_key
        )
    """

    source = Path(
        source_folder
    )

    if not source.exists():
        raise FolderEncryptionError(
            "Source folder does not exist."
        )

    if not source.is_dir():
        raise FolderEncryptionError(
            "Source path is not a folder."
        )

    algorithm = _validate_algorithm(
        algorithm
    )

    if destination_path is None:

        destination = source.with_name(
            source.name + ".cfd"
        )

    else:

        destination = Path(
            destination_path
        )

    if destination.exists() and destination.is_dir():
        raise FolderEncryptionError(
            "Destination must be a file."
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if destination.resolve() == source.resolve():
        raise FolderEncryptionError(
            "Destination cannot be the source folder."
        )

    # ------------------------------------------------------------------------
    # Build manifest first.
    # ------------------------------------------------------------------------

    files, directories = _build_manifest(
        source
    )

    # ------------------------------------------------------------------------
    # One random master key for this folder.
    # ------------------------------------------------------------------------

    folder_key = generate_file_key()

    # ------------------------------------------------------------------------
    # Create password + recovery envelope.
    #
    # Key Manager creates its own random file key. To use the folder master
    # key we construct the envelope using the Key Manager's wrapping logic.
    #
    # This implementation uses a temporary envelope creation path and verifies
    # that the generated key can be unlocked before proceeding.
    # ------------------------------------------------------------------------

    envelope, recovery_secret = (
        create_key_envelope(
            password=password,
            file_key=folder_key,
        )
    )

    # Verify key-manager result before writing container.
    unlocked_key = unlock_with_password(
        password,
        envelope,
    )

    if unlocked_key != folder_key:
        raise FolderEncryptionError(
            "Folder key verification failed."
        )

    # ------------------------------------------------------------------------
    # Header.
    # ------------------------------------------------------------------------

    header = {
        "format": "CipherForge",
        "version": VERSION,
        "type": "folder",
        "algorithm": algorithm,
        "folder_name": source.name,
        "file_count": len(files),
        "directory_count": len(directories),
        "key_envelope": envelope.to_dict(),
    }

    # ------------------------------------------------------------------------
    # Atomic output.
    # ------------------------------------------------------------------------

    fd, temp_name = tempfile.mkstemp(
        prefix=".cipherforge-folder-",
        suffix=".tmp",
        dir=destination.parent,
    )

    os.close(fd)

    temporary_path = Path(
        temp_name
    )

    try:

        with temporary_path.open(
            "wb"
        ) as output:

            header_bytes = _write_header(
                output,
                header,
            )

            cipher = _create_cipher(
                algorithm,
                folder_key,
            )
            manifest_digest = hashlib.sha256()

            # ------------------------------------------------------------
            # Directory records
            # ------------------------------------------------------------

            for directory in directories:

                relative = directory[
                    "path"
                ]

                path_bytes = relative.encode(
                    "utf-8"
                )

                _write_record(
                    output,
                    1,
                    path_bytes,
                    b"",
                )
                _update_manifest_digest(manifest_digest, 1, path_bytes, b"")

            # ------------------------------------------------------------
            # File records
            # ------------------------------------------------------------

            for file_index, file_entry in enumerate(
                files
            ):

                relative = file_entry[
                    "path"
                ]

                file_path = (
                    source
                    / Path(
                        *PurePosixPath(
                            relative
                        ).parts
                    )
                )

                if not file_path.is_file():
                    raise FolderEncryptionError(
                        f"File disappeared during encryption: {relative}"
                    )

                plaintext = file_path.read_bytes()

                nonce = os.urandom(
                    NONCE_SIZE
                )

                # Authenticated record metadata.
                aad_object = {
                    "format": "CipherForge",
                    "version": VERSION,
                    "type": "folder-file",
                    "algorithm": algorithm,
                    "index": file_index,
                    "path": relative,
                    "size": len(plaintext),
                }

                aad = _json_bytes(
                    aad_object
                )

                ciphertext = cipher.encrypt(
                    nonce,
                    plaintext,
                    aad,
                )

                payload = (
                    struct.pack(
                        ">I",
                        len(aad),
                    )
                    + aad
                    + nonce
                    + ciphertext
                )

                _write_record(
                    output,
                    2,
                    relative.encode("utf-8"),
                    payload,
                )
                _update_manifest_digest(
                    manifest_digest, 2, relative.encode("utf-8"), payload
                )

            # A final AEAD commit binds the entire header and every record.
            # It prevents header edits, record deletion, and unauthenticated
            # directory injection from being accepted during restoration.
            commit_nonce = os.urandom(NONCE_SIZE)
            commit_aad = header_bytes + manifest_digest.digest()
            commit_payload = commit_nonce + cipher.encrypt(commit_nonce, b"", commit_aad)
            _write_record(output, 3, b"", commit_payload)

            output.flush()

            os.fsync(
                output.fileno()
            )

        os.replace(
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
            FolderCryptoError,
        ):
            raise

        raise FolderEncryptionError(
            f"Folder encryption failed: {exc}"
        ) from exc

    from .key_manager import format_recovery_key

    recovery_key = format_recovery_key(
        recovery_secret
    )

    return (
        destination,
        recovery_key,
    )


# ============================================================================
# READ FOLDER HEADER
# ============================================================================

def read_folder_header(
    encrypted_folder: str | Path,
) -> dict:

    encrypted = Path(
        encrypted_folder
    )

    if not encrypted.exists():
        raise InvalidFolderContainerError(
            "Encrypted folder does not exist."
        )

    if not encrypted.is_file():
        raise InvalidFolderContainerError(
            "Encrypted folder path is not a file."
        )

    with encrypted.open(
        "rb"
    ) as input_file:

        header, _ = _read_header(
            input_file
        )

    return header


# ============================================================================
# FOLDER DECRYPTION
# ============================================================================

def decrypt_folder(
    encrypted_folder: str | Path,
    destination_folder: str | Path | None = None,
    *,
    password: str | None = None,
    recovery_key: str | None = None,
) -> Path:
    """
    Decrypt a CipherForge folder container.

    Exactly one credential must be supplied.
    """

    encrypted = Path(
        encrypted_folder
    )

    if not encrypted.exists():
        raise FolderDecryptionError(
            "Encrypted folder does not exist."
        )

    if not encrypted.is_file():
        raise FolderDecryptionError(
            "Encrypted folder container must be a file."
        )

    if password is None and recovery_key is None:
        raise FolderDecryptionError(
            "Password or recovery key is required."
        )

    if password is not None and recovery_key is not None:
        raise FolderDecryptionError(
            "Provide password OR recovery key."
        )

    try:

        with encrypted.open(
            "rb"
        ) as input_file:

            header, header_bytes = _read_header(
                input_file
            )

            algorithm = header[
                "algorithm"
            ]

            envelope = KeyEnvelope.from_dict(
                header[
                    "key_envelope"
                ]
            )

            if password is not None:

                folder_key = unlock_with_password(
                    password,
                    envelope,
                )

            else:

                folder_key = unlock_with_recovery_key(
                    recovery_key,
                    envelope,
                )

            cipher = _create_cipher(
                algorithm,
                folder_key,
            )

            if destination_folder is None:

                folder_name = header[
                    "folder_name"
                ]

                destination = encrypted.with_name(
                    folder_name
                )

                if destination.exists():
                    destination = encrypted.with_name(folder_name + ".decrypted")

            else:

                destination = Path(
                    destination_folder
                )

            if destination.exists():
                raise FolderDecryptionError(
                    "Decryption destination already exists. Choose an empty new location."
                )

            destination.mkdir(
                parents=True,
                exist_ok=False,
            )

            expected_files = header[
                "file_count"
            ]

            expected_directories = header[
                "directory_count"
            ]

            file_count = 0

            directory_count = 0
            manifest_digest = hashlib.sha256()
            commit_payload: bytes | None = None

            # ------------------------------------------------------------
            # Read records.
            # ------------------------------------------------------------

            while True:

                try:

                    record_type, relative_path, payload = (
                        _read_record(
                            input_file
                        )
                    )

                except EOFError:

                    break

                if record_type == 3:
                    if commit_payload is not None:
                        raise InvalidFolderContainerError("Multiple folder commit records.")
                    commit_payload = payload
                    continue

                if commit_payload is not None:
                    raise InvalidFolderContainerError("Data appears after folder commit record.")

                path_bytes = relative_path.encode("utf-8")
                _update_manifest_digest(manifest_digest, record_type, path_bytes, payload)

                safe_destination = (
                    _safe_destination_path(
                        destination,
                        relative_path,
                    )
                )

                if record_type == 1:

                    safe_destination.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    directory_count += 1

                    continue

                # --------------------------------------------------------
                # File record.
                # --------------------------------------------------------

                if len(payload) < 4 + NONCE_SIZE:
                    raise InvalidFolderContainerError(
                        "File record is too small."
                    )

                aad_length = struct.unpack(
                    ">I",
                    payload[:4],
                )[0]

                if aad_length <= 0:
                    raise InvalidFolderContainerError(
                        "Invalid AAD length."
                    )

                aad_start = 4

                aad_end = (
                    aad_start
                    + aad_length
                )

                if aad_end + NONCE_SIZE > len(payload):
                    raise InvalidFolderContainerError(
                        "Invalid file record structure."
                    )

                aad = payload[
                    aad_start:aad_end
                ]

                nonce = payload[
                    aad_end:
                    aad_end + NONCE_SIZE
                ]

                ciphertext = payload[
                    aad_end + NONCE_SIZE:
                ]

                try:

                    aad_object = json.loads(
                        aad.decode("utf-8")
                    )

                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                ) as exc:

                    raise InvalidFolderContainerError(
                        "Invalid file authentication metadata."
                    ) from exc

                if not isinstance(
                    aad_object,
                    dict,
                ):
                    raise InvalidFolderContainerError(
                        "Invalid file authentication metadata."
                    )

                if aad_object.get(
                    "type"
                ) != "folder-file":

                    raise InvalidFolderContainerError(
                        "Invalid file record type."
                    )

                if aad_object.get(
                    "path"
                ) != relative_path:

                    raise FolderAuthenticationError(
                        "Authenticated path does not match record path."
                    )

                expected_size = aad_object.get(
                    "size"
                )

                if not isinstance(
                    expected_size,
                    int,
                ) or expected_size < 0:

                    raise InvalidFolderContainerError(
                        "Invalid authenticated file size."
                    )

                try:

                    plaintext = cipher.decrypt(
                        nonce,
                        ciphertext,
                        aad,
                    )

                except InvalidTag as exc:

                    raise FolderAuthenticationError(
                        f"Authentication failed for: {relative_path}"
                    ) from exc

                if len(plaintext) != expected_size:

                    raise FolderAuthenticationError(
                        f"Size verification failed for: {relative_path}"
                    )

                safe_destination.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                safe_destination.write_bytes(
                    plaintext
                )

                file_count += 1

            # ------------------------------------------------------------
            # Manifest counts.
            # ------------------------------------------------------------

            if file_count != expected_files:

                raise FolderAuthenticationError(
                    "Folder file count does not match authenticated metadata."
                )

            if directory_count != expected_directories:

                raise FolderAuthenticationError(
                    "Folder directory count does not match authenticated metadata."
                )

            if commit_payload is None or len(commit_payload) < NONCE_SIZE + 16:
                raise FolderAuthenticationError("Folder container is missing its integrity commit.")

            commit_nonce = commit_payload[:NONCE_SIZE]
            try:
                cipher.decrypt(
                    commit_nonce,
                    commit_payload[NONCE_SIZE:],
                    header_bytes + manifest_digest.digest(),
                )
            except InvalidTag as exc:
                raise FolderAuthenticationError(
                    "Folder container integrity verification failed."
                ) from exc

    except (
        InvalidPasswordError,
        InvalidRecoveryKeyError,
    ):
        raise

    except (
        InvalidFolderContainerError,
        UnsafePathError,
        FolderAuthenticationError,
    ):
        raise

    except InvalidKeyEnvelopeError as exc:

        raise FolderDecryptionError(
            "Invalid key envelope."
        ) from exc

    except OSError as exc:

        raise FolderDecryptionError(
            f"Folder decryption failed: {exc}"
        ) from exc

    return destination
