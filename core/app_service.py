"""
CipherForge - Step 17 Application Service Layer
===============================================

Safe GUI/backend boundary.

This module deliberately depends on the already-tested Step 9-16 backend
modules and normalizes their small API differences at the service boundary.
Secrets are accepted only as call arguments and are never copied into
GUI-facing result objects except for the recovery key returned by a
successful encryption operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import workflow
from .app_errors import CipherForgeError, ErrorCode, handle_exception
from .config_manager import (
    get_safe_summary,
    load_config,
    save_config,
    update_config,
)
from .file_crypto import read_encrypted_header
from .folder_crypto import read_folder_header
from .storage_manager import load_recovery_key, save_recovery_key
from .usb_manager import list_usb_drives as _backend_list_usb_drives


# ---------------------------------------------------------------------------
# Public result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EncryptionResult:
    success: bool
    source: str
    output: str
    source_type: str
    algorithm: str
    recovery_key: str | None
    recovery_saved: bool


@dataclass(frozen=True)
class DecryptionResult:
    success: bool
    source: str
    output: str
    source_type: str
    algorithm: str | None


@dataclass(frozen=True)
class RecoveryStorageResult:
    success: bool
    path: str
    storage_type: str


@dataclass(frozen=True)
class UsbDriveInfo:
    path: str
    label: str
    filesystem: str
    total_bytes: int
    free_bytes: int


@dataclass(frozen=True)
class ContainerInfo:
    """Non-secret information needed by the decryption interface."""

    source_type: str
    algorithm: str
    original_name: str


FILE_TYPE = "file"
FOLDER_TYPE = "folder"

STORAGE_LOCAL = "local"
STORAGE_USB = "usb"

PASSWORD = "password"
RECOVERY_KEY = "recovery_key"


# ---------------------------------------------------------------------------
# Algorithm compatibility
# ---------------------------------------------------------------------------

_ALGORITHMS = {
    "aes": "AES-256-GCM",
    "aes256": "AES-256-GCM",
    "aes256gcm": "AES-256-GCM",
    "aes-256-gcm": "AES-256-GCM",
    "chacha": "ChaCha20-Poly1305",
    "chacha20": "ChaCha20-Poly1305",
    "chacha20poly1305": "ChaCha20-Poly1305",
    "chacha20-poly1305": "ChaCha20-Poly1305",
}


# ---------------------------------------------------------------------------
# Compatibility/configuration
# ---------------------------------------------------------------------------

def get_config():
    """
    Return the current configuration through the Step 15 configuration API.
    """
    return load_config()


def save_preferences(**changes: Any) -> dict[str, Any]:
    """Persist validated, non-secret application preferences."""
    try:
        current = load_config()
        updated = update_config(current, **changes)
        save_config(updated)
        return get_safe_summary(updated)
    except CipherForgeError:
        raise
    except Exception as exc:
        raise handle_exception(exc) from None


def inspect_container(source: str | Path) -> ContainerInfo:
    """Identify a supported container without exposing its key envelope."""
    try:
        source_path = _path(source)

        if not source_path.exists() or not source_path.is_file():
            raise CipherForgeError(
                ErrorCode.SOURCE_NOT_FOUND,
                "The selected file or folder could not be found.",
            )

        try:
            header = read_encrypted_header(source_path)
            return ContainerInfo(
                source_type=FILE_TYPE,
                algorithm=str(header["algorithm"]),
                original_name=str(header["original_filename"]),
            )
        except Exception:
            header = read_folder_header(source_path)
            return ContainerInfo(
                source_type=FOLDER_TYPE,
                algorithm=str(header["algorithm"]),
                original_name=str(header["folder_name"]),
            )
    except CipherForgeError:
        raise
    except Exception as exc:
        raise handle_exception(exc) from None


def normalize_algorithm(algorithm: str) -> str:
    """
    Normalize supported algorithm aliases to the canonical identifiers used
    by file_crypto.py and folder_crypto.py.
    """
    if not isinstance(algorithm, str) or not algorithm.strip():
        raise CipherForgeError(
            ErrorCode.UNSUPPORTED_ALGORITHM,
            "The selected encryption algorithm is not supported.",
        )

    value = algorithm.strip().lower()
    value = value.replace("_", "-")
    value = value.replace(" ", "")

    try:
        return _ALGORITHMS[value]
    except KeyError:
        raise CipherForgeError(
            ErrorCode.UNSUPPORTED_ALGORITHM,
            "The selected encryption algorithm is not supported.",
        ) from None


# ---------------------------------------------------------------------------
# Safe validation helpers
# ---------------------------------------------------------------------------

def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CipherForgeError(
            ErrorCode.INVALID_INPUT,
            f"Invalid {field}.",
        )

    return value.strip()


def _path(
    value: str | Path,
    *,
    destination: bool = False,
) -> Path:
    """
    Normalize a path without requiring that it already exists.

    Source existence/type validation is deliberately performed separately.
    This prevents accidental leakage of filesystem details through errors.
    """
    if not isinstance(value, (str, Path)):
        raise CipherForgeError(
            ErrorCode.DESTINATION_INVALID
            if destination
            else ErrorCode.INVALID_INPUT,
            "The selected path is invalid.",
        )

    if isinstance(value, str) and not value.strip():
        raise CipherForgeError(
            ErrorCode.DESTINATION_INVALID
            if destination
            else ErrorCode.INVALID_INPUT,
            "The selected path is invalid.",
        )

    try:
        return Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        raise CipherForgeError(
            ErrorCode.DESTINATION_INVALID
            if destination
            else ErrorCode.INVALID_INPUT,
            "The selected path is invalid.",
        ) from None


def _require_source(path: Path) -> None:
    """
    Validate an ordinary source used for encryption.
    """
    try:
        exists = path.exists()
    except OSError:
        exists = False

    if not exists:
        raise CipherForgeError(
            ErrorCode.SOURCE_NOT_FOUND,
            "The selected file or folder could not be found.",
        )

    if path.is_symlink():
        raise CipherForgeError(
            ErrorCode.SOURCE_TYPE_MISMATCH,
            "The selected item is not the expected file or folder type.",
        )


def _validate_source(
    path: Path,
    source_type: str,
) -> None:
    if source_type not in {
        FILE_TYPE,
        FOLDER_TYPE,
    }:
        raise CipherForgeError(
            ErrorCode.SOURCE_TYPE_MISMATCH,
            "The selected item is not the expected file or folder type.",
        )

    _require_source(path)

    if source_type == FILE_TYPE and not path.is_file():
        raise CipherForgeError(
            ErrorCode.SOURCE_TYPE_MISMATCH,
            "The selected item is not the expected file or folder type.",
        )

    if source_type == FOLDER_TYPE and not path.is_dir():
        raise CipherForgeError(
            ErrorCode.SOURCE_TYPE_MISMATCH,
            "The selected item is not the expected file or folder type.",
        )


def _destination(value: str | Path) -> Path:
    return _path(value, destination=True)


def _collision(
    source: Path,
    destination: Path,
) -> None:
    try:
        if source == destination:
            raise CipherForgeError(
                ErrorCode.SOURCE_DESTINATION_COLLISION,
                "The source and destination cannot be the same location.",
            )
    except OSError:
        pass


def _validate_encrypt_credentials(
    password: str | None,
) -> str:
    if not isinstance(password, str) or not password.strip():
        raise CipherForgeError(
            ErrorCode.INVALID_INPUT,
            "The provided input is invalid.",
        )

    return password


def _validate_decrypt_credentials(
    password: str | None,
    recovery_key: str | None,
) -> None:
    has_password = (
        isinstance(password, str)
        and bool(password.strip())
    )

    has_recovery = (
        isinstance(recovery_key, str)
        and bool(recovery_key.strip())
    )

    if has_password and has_recovery:
        raise CipherForgeError(
            ErrorCode.BOTH_CREDENTIALS,
            "Use only one decryption credential.",
        )

    if not has_password and not has_recovery:
        raise CipherForgeError(
            ErrorCode.MISSING_CREDENTIAL,
            "A valid decryption credential is required.",
        )


# ---------------------------------------------------------------------------
# Backend-result normalization
# ---------------------------------------------------------------------------

def _result_value(
    result: Any,
    *names: str,
    default: Any = None,
) -> Any:
    if isinstance(result, dict):
        for name in names:
            if name in result:
                return result[name]

        return default

    for name in names:
        if hasattr(result, name):
            return getattr(result, name)

    return default


def _output(
    result: Any,
    fallback: Path,
) -> str:
    value = _result_value(
        result,
        "output",
        "encrypted_output",
        "decrypted_output",
        "destination",
        default=str(fallback),
    )

    if isinstance(value, Path):
        return str(value)

    if value is None:
        return str(fallback)

    return str(value)


def _algorithm_from_result(
    result: Any,
) -> str | None:
    value = _result_value(
        result,
        "algorithm",
        default=None,
    )

    if value is None:
        return None

    try:
        return normalize_algorithm(str(value))
    except CipherForgeError:
        return str(value)


def _recovery_from_result(
    result: Any,
) -> str | None:
    value = _result_value(
        result,
        "recovery_key",
        default=None,
    )

    if value is None:
        return None

    return str(value)


def _recovery_saved_from_result(
    result: Any,
) -> bool:
    value = _result_value(
        result,
        "recovery_storage",
        "recovery_saved",
        default=None,
    )

    return value is not None


# ---------------------------------------------------------------------------
# FILE ENCRYPTION
# ---------------------------------------------------------------------------

def encrypt_file(
    source: str | Path,
    destination: str | Path,
    *,
    algorithm: str = "AES-256-GCM",
    password: str | None = None,
    recovery_storage: str | None = None,
    recovery_directory: str | Path | None = None,
    recovery_filename: str | None = None,
    overwrite: bool = False,
) -> EncryptionResult:
    """
    Encrypt a single file through workflow.py.

    The password is accepted only as an input and is never copied into the
    GUI-facing EncryptionResult.
    """
    try:
        _validate_encrypt_credentials(password)

        normalized_algorithm = normalize_algorithm(
            algorithm
        )

        source_path = _path(source)

        _validate_source(
            source_path,
            FILE_TYPE,
        )

        destination_path = _destination(
            destination
        )

        _collision(
            source_path,
            destination_path,
        )

        if destination_path.exists() and not overwrite:
            raise CipherForgeError(
                ErrorCode.FILE_ALREADY_EXISTS,
                "A file with the selected name already exists.",
            )

        result = workflow.encrypt_file_workflow(
            source_path,
            destination_path,
            algorithm=normalized_algorithm,
            password=password,
            recovery_storage=recovery_storage,
            recovery_directory=recovery_directory,
            recovery_filename=recovery_filename,
        )

        recovery_key = _recovery_from_result(
            result
        )

        return EncryptionResult(
            success=True,
            source=str(source_path),
            output=_output(
                result,
                destination_path,
            ),
            source_type=FILE_TYPE,
            algorithm=normalized_algorithm,
            recovery_key=recovery_key,
            recovery_saved=_recovery_saved_from_result(
                result
            ),
        )

    except CipherForgeError:
        raise

    except Exception as exc:
        raise handle_exception(
            exc
        ) from None


# ---------------------------------------------------------------------------
# FOLDER ENCRYPTION
# ---------------------------------------------------------------------------

def encrypt_folder(
    source: str | Path,
    destination: str | Path,
    *,
    algorithm: str = "AES-256-GCM",
    password: str | None = None,
    recovery_storage: str | None = None,
    recovery_directory: str | Path | None = None,
    recovery_filename: str | None = None,
    overwrite: bool = False,
) -> EncryptionResult:
    """
    Encrypt a complete folder into a CipherForge container file.
    """
    try:
        _validate_encrypt_credentials(
            password
        )

        normalized_algorithm = normalize_algorithm(
            algorithm
        )

        source_path = _path(source)

        _validate_source(
            source_path,
            FOLDER_TYPE,
        )

        destination_path = _destination(
            destination
        )

        _collision(
            source_path,
            destination_path,
        )

        if destination_path.exists() and not overwrite:
            raise CipherForgeError(
                ErrorCode.FILE_ALREADY_EXISTS,
                "A file with the selected name already exists.",
            )

        result = workflow.encrypt_folder_workflow(
            source_path,
            destination_path,
            algorithm=normalized_algorithm,
            password=password,
            recovery_storage=recovery_storage,
            recovery_directory=recovery_directory,
            recovery_filename=recovery_filename,
        )

        recovery_key = _recovery_from_result(
            result
        )

        return EncryptionResult(
            success=True,
            source=str(source_path),
            output=_output(
                result,
                destination_path,
            ),
            source_type=FOLDER_TYPE,
            algorithm=normalized_algorithm,
            recovery_key=recovery_key,
            recovery_saved=_recovery_saved_from_result(
                result
            ),
        )

    except CipherForgeError:
        raise

    except Exception as exc:
        raise handle_exception(
            exc
        ) from None


# ---------------------------------------------------------------------------
# FILE DECRYPTION
# ---------------------------------------------------------------------------

def decrypt_file(
    source: str | Path,
    destination: str | Path,
    *,
    password: str | None = None,
    recovery_key: str | None = None,
    overwrite: bool = False,
) -> DecryptionResult:
    """
    Decrypt an encrypted file container.

    Important:
        The encrypted representation is a container FILE.

        Authoritative container existence/header validation belongs to
        workflow.py.  The service layer therefore does not reject a
        nonexistent path before the workflow boundary.  This is also
        important for service-level tests that replace the workflow with
        a mocked backend.
    """
    try:
        _validate_decrypt_credentials(
            password,
            recovery_key,
        )

        source_path = _path(
            source
        )

        # If the path already exists, enforce the expected container type.
        # If it does not exist, workflow.py owns the SOURCE_NOT_FOUND
        # validation and will return a safe mapped application error.
        if source_path.exists():
            if (
                source_path.is_symlink()
                or not source_path.is_file()
            ):
                raise CipherForgeError(
                    ErrorCode.SOURCE_TYPE_MISMATCH,
                    "The selected item is not the expected file or folder type.",
                )

        destination_path = _destination(
            destination
        )

        _collision(
            source_path,
            destination_path,
        )

        result = workflow.decrypt_file_workflow(
            source_path,
            destination_path,
            password=password,
            recovery_key=recovery_key,
        )

        return DecryptionResult(
            success=True,
            source=str(source_path),
            output=_output(
                result,
                destination_path,
            ),
            source_type=FILE_TYPE,
            algorithm=_algorithm_from_result(
                result
            ),
        )

    except CipherForgeError:
        raise

    except Exception as exc:
        raise handle_exception(
            exc
        ) from None


# ---------------------------------------------------------------------------
# FOLDER DECRYPTION
# ---------------------------------------------------------------------------

def decrypt_folder(
    source: str | Path,
    destination: str | Path,
    *,
    password: str | None = None,
    recovery_key: str | None = None,
    overwrite: bool = False,
) -> DecryptionResult:
    """
    Decrypt an encrypted folder container.

    Important:
        A folder is encrypted into a container FILE.  Therefore the source
        is validated as a container file when it exists, not as a directory.
    """
    try:
        _validate_decrypt_credentials(
            password,
            recovery_key,
        )

        source_path = _path(
            source
        )

        if source_path.exists():
            if (
                source_path.is_symlink()
                or not source_path.is_file()
            ):
                raise CipherForgeError(
                    ErrorCode.SOURCE_TYPE_MISMATCH,
                    "The selected item is not the expected file or folder type.",
                )

        destination_path = _destination(
            destination
        )

        _collision(
            source_path,
            destination_path,
        )

        result = workflow.decrypt_folder_workflow(
            source_path,
            destination_path,
            password=password,
            recovery_key=recovery_key,
        )

        return DecryptionResult(
            success=True,
            source=str(source_path),
            output=_output(
                result,
                destination_path,
            ),
            source_type=FOLDER_TYPE,
            algorithm=_algorithm_from_result(
                result
            ),
        )

    except CipherForgeError:
        raise

    except Exception as exc:
        raise handle_exception(
            exc
        ) from None


# ---------------------------------------------------------------------------
# RECOVERY STORAGE
# ---------------------------------------------------------------------------

def store_recovery_key(
    recovery_key: str,
    *,
    storage_type: str = STORAGE_LOCAL,
    destination: str | Path | None = None,
    filename: str | None = None,
    overwrite: bool = False,
) -> RecoveryStorageResult:
    """
    Store a recovery key through the Step 11 storage manager.
    """
    try:
        if (
            not isinstance(recovery_key, str)
            or not recovery_key.strip()
        ):
            raise CipherForgeError(
                ErrorCode.INVALID_RECOVERY_KEY,
                "The provided recovery credential is invalid.",
            )

        if storage_type not in {
            STORAGE_LOCAL,
            STORAGE_USB,
        }:
            raise CipherForgeError(
                ErrorCode.INVALID_INPUT,
                "The provided input is invalid.",
            )

        if destination is None:
            raise CipherForgeError(
                ErrorCode.INVALID_INPUT,
                "The provided input is invalid.",
            )

        destination_path = _destination(
            destination
        )

        if (
            not destination_path.exists()
            or not destination_path.is_dir()
        ):
            raise CipherForgeError(
                ErrorCode.INVALID_INPUT,
                "The provided input is invalid.",
            )

        try:
            result = save_recovery_key(
                recovery_key,
                destination_path,
                storage_type=storage_type,
                filename=filename,
                overwrite=overwrite,
            )
        except TypeError:
            result = save_recovery_key(
                recovery_key,
                destination_path,
                storage_type=storage_type,
                filename=filename,
            )

        path_value = _result_value(
            result,
            "path",
            default=result,
        )

        return RecoveryStorageResult(
            success=True,
            path=(
                str(path_value)
                if path_value is not None
                else ""
            ),
            storage_type=storage_type,
        )

    except CipherForgeError:
        raise

    except Exception as exc:
        raise handle_exception(
            exc
        ) from None


def load_recovery_key_file(recovery_file: str | Path) -> str:
    """Load a validated recovery credential for the decryption UI."""
    try:
        return load_recovery_key(recovery_file)
    except Exception as exc:
        raise handle_exception(exc) from None


# ---------------------------------------------------------------------------
# USB
# ---------------------------------------------------------------------------

def detect_usb_drives():
    """
    Compatibility alias for callers that use the older Step 12 name.
    """
    return _backend_list_usb_drives()


def _drive_value(
    drive: Any,
    name: str,
    default: Any = None,
) -> Any:
    if isinstance(drive, dict):
        if name in drive:
            return drive[name]

        aliases = {
            "path": (
                "mount_point",
                "path",
            ),
            "mount_point": (
                "path",
                "mount_point",
            ),
        }

        for alias in aliases.get(name, ()):
            if alias in drive:
                return drive[alias]

        return default

    return getattr(
        drive,
        name,
        default,
    )


def list_usb_drives() -> list[UsbDriveInfo]:
    """
    Convert backend USB drive objects into GUI-safe immutable objects.

    The returned path is normalized to a stable forward-slash format so
    Windows and POSIX backends expose the same GUI-safe representation.
    """
    try:
        raw = _backend_list_usb_drives()

        if raw is None:
            return []

        result: list[UsbDriveInfo] = []

        for drive in raw:
            mount = _drive_value(
                drive,
                "path",
                _drive_value(
                    drive,
                    "mount_point",
                    "",
                ),
            )

            label = _drive_value(
                drive,
                "label",
                "",
            )

            filesystem = _drive_value(
                drive,
                "filesystem",
                "",
            )

            total = _drive_value(
                drive,
                "total_bytes",
                0,
            )

            free = _drive_value(
                drive,
                "free_bytes",
                0,
            )

            # GUI-safe, platform-independent mount-path representation.
            if mount is None:
                mount_path = ""
            else:
                mount_path = str(mount).replace("\\", "/")

            try:
                total_bytes = max(0, int(total or 0))
            except (TypeError, ValueError):
                total_bytes = 0

            try:
                free_bytes = max(0, int(free or 0))
            except (TypeError, ValueError):
                free_bytes = 0

            result.append(
                UsbDriveInfo(
                    path=mount_path,
                    label=(
                        ""
                        if label is None
                        else str(label)
                    ),
                    filesystem=(
                        ""
                        if filesystem is None
                        else str(filesystem)
                    ),
                    total_bytes=total_bytes,
                    free_bytes=free_bytes,
                )
            )

        return result

    except CipherForgeError:
        raise

    except Exception as exc:
        raise handle_exception(exc) from None
# ---------------------------------------------------------------------------
# GUI-safe configuration
# ---------------------------------------------------------------------------

_SECRET_FIELDS = {
    "password",
    "recovery_key",
    "encryption_key",
    "key",
    "secret",
    "credential",
    "credentials",
}


def _safe_dict(
    value: dict[str, Any],
) -> dict[str, Any]:
    """
    Remove all known secret-bearing configuration fields.
    """
    return {
        key: item
        for key, item in value.items()
        if key not in _SECRET_FIELDS
    }


def get_service_config() -> dict[str, Any]:
    """
    Return a GUI-safe configuration summary.

    No password, recovery key, encryption key, or other secret material is
    returned.
    """
    try:
        config = get_config()

        if isinstance(config, dict):
            return _safe_dict(
                config
            )

        try:
            summary = get_safe_summary(
                config
            )

            if isinstance(summary, dict):
                return _safe_dict(
                    summary
                )
        except Exception:
            pass

        if hasattr(config, "to_dict"):
            data = config.to_dict()

            if isinstance(data, dict):
                return _safe_dict(
                    data
                )

        safe: dict[str, Any] = {}

        for field in (
            "config_version",
            "version",
            "algorithm",
            "theme",
            "recovery_storage",
            "recovery_filename",
            "container_extension",
            "secure_delete",
        ):
            if hasattr(config, field):
                safe[field] = getattr(
                    config,
                    field,
                )

        return _safe_dict(
            safe
        )

    except CipherForgeError:
        raise

    except Exception as exc:
        raise handle_exception(
            exc
        ) from None


# ---------------------------------------------------------------------------
# Safe error API
# ---------------------------------------------------------------------------

def safe_error(
    error: BaseException,
) -> CipherForgeError:
    """
    Convert any backend exception into the safe application error model.
    """
    if isinstance(
        error,
        CipherForgeError,
    ):
        return error

    return handle_exception(
        error
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "EncryptionResult",
    "DecryptionResult",
    "RecoveryStorageResult",
    "UsbDriveInfo",
    "ContainerInfo",

    "FILE_TYPE",
    "FOLDER_TYPE",
    "STORAGE_LOCAL",
    "STORAGE_USB",
    "PASSWORD",
    "RECOVERY_KEY",

    "encrypt_file",
    "encrypt_folder",
    "decrypt_file",
    "decrypt_folder",

    "store_recovery_key",
    "load_recovery_key_file",

    "detect_usb_drives",
    "list_usb_drives",

    "get_config",
    "save_preferences",
    "inspect_container",
    "normalize_algorithm",
    "get_service_config",

    "safe_error",
]
