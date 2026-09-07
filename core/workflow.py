"""
CipherForge - Workflow Layer
============================

High-level orchestration layer between the GUI and CipherForge crypto modules.

Supported:
    - File encryption/decryption
    - Folder encryption/decryption
    - AES-256-GCM
    - ChaCha20-Poly1305
    - Password credentials
    - Recovery-key credentials
    - Local recovery-key storage
    - USB recovery-key storage
    - Input/path validation

Workflow algorithm names:
    aes-256-gcm
    chacha20-poly1305

Underlying crypto-module identifiers:
    AES-256-GCM
    ChaCha20-Poly1305
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .file_crypto import (
    encrypt_file,
    decrypt_file,
)

from .folder_crypto import (
    encrypt_folder,
    decrypt_folder,
)

from .storage_manager import (
    StorageResult,
    save_recovery_key_local,
    save_recovery_key_usb,
)

from .key_manager import (
    InvalidRecoveryKeyError,
)


# ============================================================================
# TYPES
# ============================================================================

Algorithm = Literal[
    "aes-256-gcm",
    "chacha20-poly1305",
]

SourceType = Literal[
    "file",
    "folder",
]

StorageType = Literal[
    "local",
    "usb",
]

CredentialType = Literal[
    "password",
    "recovery_key",
]


# ============================================================================
# CONSTANTS
# ============================================================================

SUPPORTED_ALGORITHMS = frozenset(
    {
        "aes-256-gcm",
        "chacha20-poly1305",
    }
)


# ============================================================================
# EXCEPTIONS
# ============================================================================

class WorkflowError(Exception):
    """Base exception for workflow errors."""


class InvalidWorkflowInputError(WorkflowError):
    """Raised when workflow input is invalid."""


class SourceNotFoundError(WorkflowError):
    """Raised when the source does not exist."""


class SourceTypeMismatchError(WorkflowError):
    """Raised when source type does not match the operation."""


class DestinationError(WorkflowError):
    """Raised when destination is invalid."""


class SourceDestinationCollisionError(WorkflowError):
    """Raised when source and destination are identical."""


class UnsupportedAlgorithmError(WorkflowError):
    """Raised when an unsupported algorithm is requested."""


# ============================================================================
# RESULT DATACLASSES
# ============================================================================

@dataclass(frozen=True)
class EncryptionWorkflowResult:
    source: Path
    encrypted_output: Path
    algorithm: Algorithm
    source_type: SourceType
    recovery_key: str
    recovery_storage: StorageResult | None = None

    @property
    def output_path(self) -> Path:
        return self.encrypted_output


@dataclass(frozen=True)
class DecryptionWorkflowResult:
    encrypted_source: Path
    decrypted_output: Path
    source_type: SourceType
    credential_type: CredentialType

    @property
    def output_path(self) -> Path:
        return self.decrypted_output


# ============================================================================
# ALGORITHM NORMALIZATION
# ============================================================================

def _normalize_algorithm(
    algorithm: str,
) -> Algorithm:

    if not isinstance(algorithm, str):
        raise UnsupportedAlgorithmError(
            "Algorithm must be a string."
        )

    value = (
        algorithm
        .strip()
        .lower()
        .replace("_", "-")
        .replace(" ", "")
    )

    aliases: dict[str, Algorithm] = {
        # AES
        "aes": "aes-256-gcm",
        "aes256": "aes-256-gcm",
        "aes-256": "aes-256-gcm",
        "aes256gcm": "aes-256-gcm",
        "aes-256-gcm": "aes-256-gcm",

        # ChaCha
        "chacha": "chacha20-poly1305",
        "chacha20": "chacha20-poly1305",
        "chacha20poly1305": "chacha20-poly1305",
        "chacha20-poly1305": "chacha20-poly1305",
    }

    normalized = aliases.get(value)

    if normalized is None:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {algorithm}"
        )

    return normalized


def _file_crypto_algorithm(
    algorithm: Algorithm,
) -> str:

    mapping = {
        "aes-256-gcm": "AES-256-GCM",
        "chacha20-poly1305": "ChaCha20-Poly1305",
    }

    try:
        return mapping[algorithm]

    except KeyError as exc:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {algorithm}"
        ) from exc


def _folder_crypto_algorithm(
    algorithm: Algorithm,
) -> str:

    mapping = {
        "aes-256-gcm": "AES-256-GCM",
        "chacha20-poly1305": "ChaCha20-Poly1305",
    }

    try:
        return mapping[algorithm]

    except KeyError as exc:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {algorithm}"
        ) from exc


# ============================================================================
# PATH HELPERS
# ============================================================================

def _resolve_path(
    path: str | Path,
) -> Path:

    if not isinstance(path, (str, Path)):
        raise InvalidWorkflowInputError(
            "Path must be a string or pathlib.Path."
        )

    try:
        return Path(path).expanduser().resolve(
            strict=False
        )

    except (OSError, RuntimeError) as exc:
        raise DestinationError(
            f"Unable to resolve path: {path}"
        ) from exc


# ============================================================================
# ENCRYPTION SOURCE VALIDATION
# ============================================================================

def _validate_source_type(
    source: Path,
    source_type: SourceType,
) -> None:

    if source_type not in {
        "file",
        "folder",
    }:
        raise SourceTypeMismatchError(
            "source_type must be 'file' or 'folder'."
        )

    if not source.exists():
        raise SourceNotFoundError(
            f"Source does not exist: {source}"
        )

    if source.is_symlink():
        raise SourceTypeMismatchError(
            "Symbolic-link sources are not supported."
        )

    if source_type == "file":

        if not source.is_file():
            raise SourceTypeMismatchError(
                f"Expected a file: {source}"
            )

    else:

        if not source.is_dir():
            raise SourceTypeMismatchError(
                f"Expected a folder: {source}"
            )


# ============================================================================
# DECRYPTION SOURCE VALIDATION
# ============================================================================

def _validate_encrypted_source(
    source: Path,
) -> None:
    """
    Both encrypted files and encrypted folders are represented by
    encrypted container files.

    Example:

        secret.txt
            ↓
        secret.cforge

        photos/
            ↓
        photos.cforge

    Therefore decryption must validate the encrypted source as a FILE,
    regardless of whether the original source was a file or folder.
    """

    if not source.exists():
        raise SourceNotFoundError(
            f"Encrypted source does not exist: {source}"
        )

    if source.is_symlink():
        raise SourceTypeMismatchError(
            "Symbolic-link encrypted sources are not supported."
        )

    if not source.is_file():
        raise SourceTypeMismatchError(
            f"Encrypted source must be a container file: {source}"
        )


# ============================================================================
# DESTINATION VALIDATION
# ============================================================================

def _validate_destination(
    source: Path,
    destination: str | Path,
    *,
    source_type: SourceType,
    decrypt_operation: bool = False,
) -> Path:

    target = _resolve_path(
        destination
    )

    source_resolved = _resolve_path(
        source
    )

    if target == source_resolved:
        raise SourceDestinationCollisionError(
            "Source and destination cannot be identical."
        )

    # ------------------------------------------------------------------------
    # Decryption destination
    # ------------------------------------------------------------------------

    if decrypt_operation:

        if source_type == "file":

            if target.exists() and target.is_dir():
                raise DestinationError(
                    "File decryption destination cannot be a directory."
                )

        else:

            if target.exists() and target.is_file():
                raise DestinationError(
                    "Folder decryption destination cannot be a file."
                )

        return target

    # ------------------------------------------------------------------------
    # Encryption destination
    # ------------------------------------------------------------------------

    if source_type == "file":

        if target.exists() and target.is_dir():
            raise DestinationError(
                "File destination cannot be an existing directory."
            )

    else:

        if target.exists() and target.is_file():
            raise DestinationError(
                "Folder destination cannot be an existing file."
            )

    return target


# ============================================================================
# PASSWORD VALIDATION
# ============================================================================

def _validate_password(
    password: str | None,
) -> None:

    if password is None:
        raise InvalidWorkflowInputError(
            "Password is required."
        )

    if not isinstance(password, str):
        raise InvalidWorkflowInputError(
            "Password must be a string."
        )

    if not password:
        raise InvalidWorkflowInputError(
            "Password cannot be empty."
        )


# ============================================================================
# DECRYPTION CREDENTIAL VALIDATION
# ============================================================================

def _validate_decryption_credentials(
    *,
    password: str | None,
    recovery_key: str | None,
) -> CredentialType:

    has_password = password is not None
    has_recovery_key = recovery_key is not None

    if has_password and has_recovery_key:
        raise InvalidWorkflowInputError(
            "Provide either password or recovery key, not both."
        )

    if not has_password and not has_recovery_key:
        raise InvalidWorkflowInputError(
            "A password or recovery key is required."
        )

    if has_password:

        _validate_password(
            password
        )

        return "password"

    if not isinstance(
        recovery_key,
        str,
    ):
        raise InvalidRecoveryKeyError(
            "Recovery key must be a string."
        )

    if not recovery_key.strip():
        raise InvalidRecoveryKeyError(
            "Recovery key cannot be empty."
        )

    return "recovery_key"


# ============================================================================
# ENCRYPTION RESULT NORMALIZATION
# ============================================================================

def _normalize_encryption_result(
    result,
) -> tuple[Path, str]:
    """
    Supports the existing crypto modules returning either:

        (output_path, recovery_key)

    or an object containing:

        output_path
        recovery_key

    or:

        encrypted_output
        recovery_key
    """

    # ------------------------------------------------------------------------
    # Tuple / list
    # ------------------------------------------------------------------------

    if isinstance(result, (tuple, list)):

        if len(result) != 2:
            raise WorkflowError(
                "Unexpected encryption result format."
            )

        output_path, recovery_key = result

    # ------------------------------------------------------------------------
    # Object
    # ------------------------------------------------------------------------

    else:

        output_path = None
        recovery_key = None

        for attribute in (
            "output_path",
            "encrypted_output",
        ):

            if hasattr(result, attribute):

                output_path = getattr(
                    result,
                    attribute,
                )

                break

        if hasattr(result, "recovery_key"):

            recovery_key = getattr(
                result,
                "recovery_key",
            )

    # ------------------------------------------------------------------------
    # Validate
    # ------------------------------------------------------------------------

    if output_path is None:
        raise WorkflowError(
            "Encryption result did not contain an output path."
        )

    if recovery_key is None:
        raise WorkflowError(
            "Encryption result did not contain a recovery key."
        )

    try:
        normalized_output = Path(
            output_path
        )

    except TypeError as exc:
        raise WorkflowError(
            "Encryption returned an invalid output path."
        ) from exc

    if not isinstance(
        recovery_key,
        str,
    ):
        raise WorkflowError(
            "Encryption returned an invalid recovery key."
        )

    if not recovery_key.strip():
        raise WorkflowError(
            "Encryption returned an empty recovery key."
        )

    return (
        normalized_output,
        recovery_key,
    )


# ============================================================================
# DECRYPTION RESULT NORMALIZATION
# ============================================================================

def _normalize_decryption_result(
    result,
    fallback_destination: Path,
) -> Path:
    """
    Supports:
        None
        str
        Path
        tuple/list
        object.output_path
        object.decrypted_output
    """

    if result is None:
        return fallback_destination

    if isinstance(
        result,
        (str, Path),
    ):
        return Path(result)

    if isinstance(
        result,
        (tuple, list),
    ):

        if not result:
            return fallback_destination

        return Path(
            result[0]
        )

    for attribute in (
        "output_path",
        "decrypted_output",
    ):

        if hasattr(
            result,
            attribute,
        ):

            value = getattr(
                result,
                attribute,
            )

            if value is not None:
                return Path(value)

    return fallback_destination


# ============================================================================
# RECOVERY STORAGE
# ============================================================================

def _store_recovery_key(
    recovery_key: str,
    *,
    storage_type: StorageType,
    recovery_directory: str | Path,
    recovery_filename: str | None,
) -> StorageResult:

    directory = _resolve_path(
        recovery_directory
    )

    if not directory.exists():
        raise DestinationError(
            f"Recovery destination does not exist: {directory}"
        )

    if not directory.is_dir():
        raise DestinationError(
            f"Recovery destination is not a directory: {directory}"
        )

    if storage_type == "local":

        return save_recovery_key_local(
            recovery_key,
            directory,
            filename=recovery_filename,
        )

    if storage_type == "usb":

        return save_recovery_key_usb(
            recovery_key,
            directory,
            filename=recovery_filename,
        )

    raise InvalidWorkflowInputError(
        "recovery_storage must be 'local' or 'usb'."
    )


# ============================================================================
# GENERIC ENCRYPT
# ============================================================================

def encrypt(
    source: str | Path,
    destination: str | Path,
    *,
    source_type: SourceType,
    algorithm: str,
    password: str,
    recovery_storage: StorageType | None = None,
    recovery_directory: str | Path | None = None,
    recovery_filename: str | None = None,
) -> EncryptionWorkflowResult:

    # ------------------------------------------------------------------------
    # Source
    # ------------------------------------------------------------------------

    source_path = _resolve_path(
        source
    )

    _validate_source_type(
        source_path,
        source_type,
    )

    # ------------------------------------------------------------------------
    # Destination
    # ------------------------------------------------------------------------

    destination_path = _validate_destination(
        source_path,
        destination,
        source_type=source_type,
        decrypt_operation=False,
    )

    # ------------------------------------------------------------------------
    # Algorithm
    # ------------------------------------------------------------------------

    normalized_algorithm = _normalize_algorithm(
        algorithm
    )

    # ------------------------------------------------------------------------
    # Password
    # ------------------------------------------------------------------------

    _validate_password(
        password
    )

    # ------------------------------------------------------------------------
    # File encryption
    # ------------------------------------------------------------------------

    if source_type == "file":

        crypto_algorithm = (
            _file_crypto_algorithm(
                normalized_algorithm
            )
        )

        result = encrypt_file(
            source_path,
            destination_path,
            password=password,
            algorithm=crypto_algorithm,
        )

    # ------------------------------------------------------------------------
    # Folder encryption
    # ------------------------------------------------------------------------

    else:

        crypto_algorithm = (
            _folder_crypto_algorithm(
                normalized_algorithm
            )
        )

        result = encrypt_folder(
            source_path,
            destination_path,
            password=password,
            algorithm=crypto_algorithm,
        )

    # ------------------------------------------------------------------------
    # Normalize crypto result
    # ------------------------------------------------------------------------

    output_path, recovery_key = (
        _normalize_encryption_result(
            result
        )
    )

    # ------------------------------------------------------------------------
    # Recovery storage
    # ------------------------------------------------------------------------

    storage_result = None

    if recovery_storage is not None:

        if recovery_directory is None:
            raise InvalidWorkflowInputError(
                "recovery_directory is required when "
                "recovery_storage is specified."
            )

        storage_result = _store_recovery_key(
            recovery_key,
            storage_type=recovery_storage,
            recovery_directory=recovery_directory,
            recovery_filename=recovery_filename,
        )

    # ------------------------------------------------------------------------
    # Return
    # ------------------------------------------------------------------------

    return EncryptionWorkflowResult(
        source=source_path,
        encrypted_output=output_path,
        algorithm=normalized_algorithm,
        source_type=source_type,
        recovery_key=recovery_key,
        recovery_storage=storage_result,
    )


# ============================================================================
# GENERIC DECRYPT
# ============================================================================

def decrypt(
    source: str | Path,
    destination: str | Path,
    *,
    source_type: SourceType,
    password: str | None = None,
    recovery_key: str | None = None,
) -> DecryptionWorkflowResult:

    # ------------------------------------------------------------------------
    # IMPORTANT:
    #
    # The encrypted representation of BOTH:
    #
    #     file
    #     folder
    #
    # is a container FILE.
    #
    # Therefore do NOT call _validate_source_type() here.
    # ------------------------------------------------------------------------

    source_path = _resolve_path(
        source
    )

    _validate_encrypted_source(
        source_path
    )

    # ------------------------------------------------------------------------
    # Destination
    # ------------------------------------------------------------------------

    destination_path = _validate_destination(
        source_path,
        destination,
        source_type=source_type,
        decrypt_operation=True,
    )

    # ------------------------------------------------------------------------
    # Credential
    # ------------------------------------------------------------------------

    credential_type = (
        _validate_decryption_credentials(
            password=password,
            recovery_key=recovery_key,
        )
    )

    # ------------------------------------------------------------------------
    # File decryption
    # ------------------------------------------------------------------------

    if source_type == "file":

        result = decrypt_file(
            source_path,
            destination_path,
            password=password,
            recovery_key=recovery_key,
        )

    # ------------------------------------------------------------------------
    # Folder decryption
    # ------------------------------------------------------------------------

    elif source_type == "folder":

        result = decrypt_folder(
            source_path,
            destination_path,
            password=password,
            recovery_key=recovery_key,
        )

    else:

        raise SourceTypeMismatchError(
            "source_type must be 'file' or 'folder'."
        )

    # ------------------------------------------------------------------------
    # Normalize output
    # ------------------------------------------------------------------------

    output_path = _normalize_decryption_result(
        result,
        destination_path,
    )

    # ------------------------------------------------------------------------
    # Return
    # ------------------------------------------------------------------------

    return DecryptionWorkflowResult(
        encrypted_source=source_path,
        decrypted_output=output_path,
        source_type=source_type,
        credential_type=credential_type,
    )


# ============================================================================
# FILE ENCRYPTION API
# ============================================================================

def encrypt_file_workflow(
    source: str | Path,
    destination: str | Path,
    *,
    algorithm: str,
    password: str,
    recovery_storage: StorageType | None = None,
    recovery_directory: str | Path | None = None,
    recovery_filename: str | None = None,
) -> EncryptionWorkflowResult:

    return encrypt(
        source,
        destination,
        source_type="file",
        algorithm=algorithm,
        password=password,
        recovery_storage=recovery_storage,
        recovery_directory=recovery_directory,
        recovery_filename=recovery_filename,
    )


# ============================================================================
# FILE DECRYPTION API
# ============================================================================

def decrypt_file_workflow(
    source: str | Path,
    destination: str | Path,
    *,
    password: str | None = None,
    recovery_key: str | None = None,
) -> DecryptionWorkflowResult:

    return decrypt(
        source,
        destination,
        source_type="file",
        password=password,
        recovery_key=recovery_key,
    )


# ============================================================================
# FOLDER ENCRYPTION API
# ============================================================================

def encrypt_folder_workflow(
    source: str | Path,
    destination: str | Path,
    *,
    algorithm: str,
    password: str,
    recovery_storage: StorageType | None = None,
    recovery_directory: str | Path | None = None,
    recovery_filename: str | None = None,
) -> EncryptionWorkflowResult:

    return encrypt(
        source,
        destination,
        source_type="folder",
        algorithm=algorithm,
        password=password,
        recovery_storage=recovery_storage,
        recovery_directory=recovery_directory,
        recovery_filename=recovery_filename,
    )


# ============================================================================
# FOLDER DECRYPTION API
# ============================================================================

def decrypt_folder_workflow(
    source: str | Path,
    destination: str | Path,
    *,
    password: str | None = None,
    recovery_key: str | None = None,
) -> DecryptionWorkflowResult:

    return decrypt(
        source,
        destination,
        source_type="folder",
        password=password,
        recovery_key=recovery_key,
    )


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    # Types
    "Algorithm",
    "SourceType",
    "StorageType",
    "CredentialType",

    # Constants
    "SUPPORTED_ALGORITHMS",

    # Exceptions
    "WorkflowError",
    "InvalidWorkflowInputError",
    "SourceNotFoundError",
    "SourceTypeMismatchError",
    "DestinationError",
    "SourceDestinationCollisionError",
    "UnsupportedAlgorithmError",

    # Results
    "EncryptionWorkflowResult",
    "DecryptionWorkflowResult",

    # Generic API
    "encrypt",
    "decrypt",

    # File API
    "encrypt_file_workflow",
    "decrypt_file_workflow",

    # Folder API
    "encrypt_folder_workflow",
    "decrypt_folder_workflow",
]