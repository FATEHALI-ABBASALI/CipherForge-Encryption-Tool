"""
CipherForge - Recovery Key Storage Manager
===========================================

Step 11

Responsible only for storing and loading CipherForge recovery keys.

Supports:
    - Local PC storage
    - USB/removable-drive storage
    - Windows
    - Linux
    - macOS

Security:
    - Validates recovery keys through key_manager
    - Rejects path traversal
    - Rejects absolute paths
    - Does not silently sanitize dangerous filenames
    - Atomic file writes
    - Does not silently overwrite existing files
"""

from __future__ import annotations

import ctypes
import os
import platform
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .key_manager import (
    InvalidRecoveryKeyError,
    parse_recovery_key,
)


# ============================================================================
# TYPES
# ============================================================================

StorageType = Literal["local", "usb"]


# ============================================================================
# CONSTANTS
# ============================================================================

RECOVERY_FILE_EXTENSION = ".cfrecovery"
RECOVERY_FILE_PREFIX = "CipherForge-Recovery"

MAX_RECOVERY_KEY_LENGTH = 4096


# ============================================================================
# EXCEPTIONS
# ============================================================================

class StorageManagerError(Exception):
    """Base storage-manager exception."""


class InvalidStorageTypeError(StorageManagerError):
    """Invalid storage type."""


class InvalidStoragePathError(StorageManagerError):
    """Invalid destination path."""


class RecoveryFileExistsError(StorageManagerError):
    """Recovery file already exists."""


class RecoveryStorageError(StorageManagerError):
    """Recovery key could not be stored."""


class UsbDriveNotFoundError(StorageManagerError):
    """USB/removable drive was not found."""


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass(frozen=True)
class StorageResult:
    """Result of a successful recovery-key save."""

    path: Path
    storage_type: StorageType
    bytes_written: int


@dataclass(frozen=True)
class RemovableDrive:
    """Detected removable-drive information."""

    mount_point: Path
    label: str | None
    filesystem: str | None


# ============================================================================
# VALIDATION
# ============================================================================

def _validate_storage_type(
    storage_type: str,
) -> StorageType:

    if storage_type not in {"local", "usb"}:
        raise InvalidStorageTypeError(
            "Storage type must be 'local' or 'usb'."
        )

    return storage_type  # type: ignore[return-value]


def _validate_recovery_key(
    recovery_key: str,
) -> None:

    if not isinstance(recovery_key, str):
        raise InvalidRecoveryKeyError(
            "Recovery key must be a string."
        )

    recovery_key = recovery_key.strip()

    if not recovery_key:
        raise InvalidRecoveryKeyError(
            "Recovery key cannot be empty."
        )

    if len(recovery_key) > MAX_RECOVERY_KEY_LENGTH:
        raise InvalidRecoveryKeyError(
            "Recovery key is too long."
        )

    # Let key_manager perform canonical validation.
    parse_recovery_key(recovery_key)


# ============================================================================
# FILENAME
# ============================================================================

def build_recovery_filename(
    *,
    base_name: str = RECOVERY_FILE_PREFIX,
) -> str:
    """
    Generate the default recovery filename.

    Example:
        CipherForge-Recovery.cfrecovery
    """

    if not isinstance(base_name, str):
        raise ValueError(
            "base_name must be a string."
        )

    base_name = base_name.strip()

    if not base_name:
        base_name = RECOVERY_FILE_PREFIX

    # This function creates the filename itself, therefore a path is not
    # meaningful here.
    if (
        "/" in base_name
        or "\\" in base_name
        or Path(base_name).name != base_name
    ):
        raise ValueError(
            "base_name must contain only a filename."
        )

    if base_name in {".", ".."}:
        raise ValueError(
            "Invalid base filename."
        )

    if base_name.endswith(
        RECOVERY_FILE_EXTENSION
    ):
        return base_name

    return (
        base_name
        + RECOVERY_FILE_EXTENSION
    )


# ============================================================================
# USER-PROVIDED FILENAME VALIDATION
# ============================================================================

def _validate_filename(
    filename: str,
) -> str:
    """
    Strictly validate a user-provided filename.

    Important:
        Dangerous paths are rejected rather than sanitized.

    Rejected examples:
        ../recovery.cfrecovery
        ..\recovery.cfrecovery
        /tmp/recovery.cfrecovery
        \tmp\recovery.cfrecovery
        C:\recovery.cfrecovery
        C:/recovery.cfrecovery
        folder/recovery.cfrecovery
    """

    if not isinstance(filename, str):
        raise InvalidStoragePathError(
            "Recovery filename must be a string."
        )

    filename = filename.strip()

    if not filename:
        raise InvalidStoragePathError(
            "Recovery filename is empty."
        )

    normalized = filename.replace(
        "\\",
        "/",
    )

    # Absolute POSIX path.
    if normalized.startswith("/"):
        raise InvalidStoragePathError(
            "Absolute recovery filename is not allowed."
        )

    # Windows drive path.
    if (
        len(normalized) >= 2
        and normalized[1] == ":"
    ):
        raise InvalidStoragePathError(
            "Drive-qualified recovery filename is not allowed."
        )

    # Any directory separator means the caller supplied a path instead
    # of a filename.
    if "/" in normalized:
        raise InvalidStoragePathError(
            "Recovery filename must contain only a filename."
        )

    if filename in {".", ".."}:
        raise InvalidStoragePathError(
            "Invalid recovery filename."
        )

    # Extra protection for unusual path-like names.
    path_obj = Path(filename)

    if path_obj.name != filename:
        raise InvalidStoragePathError(
            "Invalid recovery filename."
        )

    if any(
        part == ".."
        for part in path_obj.parts
    ):
        raise InvalidStoragePathError(
            "Path traversal is not allowed."
        )

    return filename


# ============================================================================
# UNIQUE PATH
# ============================================================================

def _unique_path(
    directory: Path,
    filename: str,
) -> Path:
    """
    Return a non-existing path.

    Example:
        file.cfrecovery
        file-2.cfrecovery
        file-3.cfrecovery
    """

    candidate = directory / filename

    if not candidate.exists():
        return candidate

    path = Path(filename)

    stem = path.stem
    suffix = path.suffix

    counter = 2

    while True:

        candidate = (
            directory
            / f"{stem}-{counter}{suffix}"
        )

        if not candidate.exists():
            return candidate

        counter += 1


# ============================================================================
# ATOMIC WRITE
# ============================================================================

def _atomic_write_text(
    destination: Path,
    content: str,
    *,
    overwrite: bool = False,
) -> int:
    """
    Atomically write UTF-8 content.

    By default an existing file is never overwritten.
    """

    if destination.exists() and not overwrite:
        raise RecoveryFileExistsError(
            f"Recovery file already exists: {destination}"
        )

    directory = destination.parent

    if not directory.exists():
        raise InvalidStoragePathError(
            f"Destination directory does not exist: {directory}"
        )

    if not directory.is_dir():
        raise InvalidStoragePathError(
            f"Destination is not a directory: {directory}"
        )

    encoded = content.encode("utf-8")

    fd = -1
    temporary_path: Path | None = None

    try:

        fd, temp_name = tempfile.mkstemp(
            prefix=".cipherforge-recovery-",
            suffix=".tmp",
            dir=directory,
        )

        temporary_path = Path(temp_name)

        with os.fdopen(
            fd,
            "wb",
        ) as output:

            fd = -1

            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())

        # With overwrite=True this deliberately replaces the target.
        os.replace(
            temporary_path,
            destination,
        )

        temporary_path = None

        return len(encoded)

    except RecoveryFileExistsError:
        raise

    except OSError as exc:

        raise RecoveryStorageError(
            f"Could not save recovery key: {exc}"
        ) from exc

    finally:

        if fd != -1:

            try:
                os.close(fd)
            except OSError:
                pass

        if temporary_path is not None:

            try:
                temporary_path.unlink(
                    missing_ok=True
                )
            except OSError:
                pass


# ============================================================================
# SAVE RECOVERY KEY
# ============================================================================

def save_recovery_key(
    recovery_key: str,
    destination_directory: str | Path,
    *,
    storage_type: StorageType = "local",
    filename: str | None = None,
    overwrite: bool = False,
) -> StorageResult:
    """
    Save a validated recovery key.

    storage_type:
        local
        usb

    Note:
        The USB type is a storage mode label. The caller/GUI is responsible
        for selecting the actual USB destination directory.
    """

    storage_type = _validate_storage_type(
        storage_type
    )

    _validate_recovery_key(
        recovery_key
    )

    directory = Path(
        destination_directory
    )

    if not directory.exists():
        raise InvalidStoragePathError(
            f"Destination directory does not exist: {directory}"
        )

    if not directory.is_dir():
        raise InvalidStoragePathError(
            f"Destination is not a directory: {directory}"
        )

    if filename is None:

        filename = build_recovery_filename()

    else:

        filename = _validate_filename(
            filename
        )

    destination = directory / filename

    # Default behavior: never overwrite.
    if not overwrite and destination.exists():

        destination = _unique_path(
            directory,
            filename,
        )

    content = (
        "CipherForge Recovery Key\n"
        "=========================\n"
        f"{recovery_key.strip()}\n"
        "\n"
        "Keep this key in a secure location.\n"
        "Anyone with this recovery key may be able to "
        "decrypt the protected data.\n"
    )

    bytes_written = _atomic_write_text(
        destination,
        content,
        overwrite=overwrite,
    )

    return StorageResult(
        path=destination,
        storage_type=storage_type,
        bytes_written=bytes_written,
    )


# ============================================================================
# LOAD RECOVERY KEY
# ============================================================================

def load_recovery_key(
    recovery_file: str | Path,
) -> str:
    """
    Load and validate a recovery key from a .cfrecovery file.
    """

    path = Path(
        recovery_file
    )

    if not path.exists():
        raise RecoveryStorageError(
            f"Recovery file does not exist: {path}"
        )

    if not path.is_file():
        raise RecoveryStorageError(
            f"Recovery path is not a file: {path}"
        )

    try:

        content = path.read_text(
            encoding="utf-8"
        )

    except OSError as exc:

        raise RecoveryStorageError(
            f"Could not read recovery file: {exc}"
        ) from exc

    for line in content.splitlines():

        candidate = line.strip()

        if candidate.startswith("CF-"):

            _validate_recovery_key(
                candidate
            )

            return candidate

    raise InvalidRecoveryKeyError(
        "No valid CipherForge recovery key found."
    )


# ============================================================================
# PLATFORM
# ============================================================================

def get_platform_name() -> str:

    system = platform.system()

    if system == "Windows":
        return "windows"

    if system == "Linux":
        return "linux"

    if system == "Darwin":
        return "macos"

    return system.lower()


# ============================================================================
# WINDOWS REMOVABLE DRIVES
# ============================================================================

def _list_windows_removable_drives() -> list[RemovableDrive]:

    DRIVE_REMOVABLE = 2

    drives: list[RemovableDrive] = []

    kernel32 = ctypes.windll.kernel32

    get_drive_type = kernel32.GetDriveTypeW

    get_volume_information = (
        kernel32.GetVolumeInformationW
    )

    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":

        root = f"{letter}:\\"

        try:

            drive_type = get_drive_type(
                root
            )

        except Exception:
            continue

        if drive_type != DRIVE_REMOVABLE:
            continue

        label_buffer = ctypes.create_unicode_buffer(
            261
        )

        filesystem_buffer = ctypes.create_unicode_buffer(
            261
        )

        serial_number = ctypes.c_ulong()
        max_component_length = ctypes.c_ulong()
        filesystem_flags = ctypes.c_ulong()

        try:

            result = get_volume_information(
                root,
                label_buffer,
                len(label_buffer),
                ctypes.byref(serial_number),
                ctypes.byref(max_component_length),
                ctypes.byref(filesystem_flags),
                filesystem_buffer,
                len(filesystem_buffer),
            )

        except Exception:

            result = 0

        label = (
            label_buffer.value
            if result
            else None
        )

        filesystem = (
            filesystem_buffer.value
            if result
            else None
        )

        drives.append(
            RemovableDrive(
                mount_point=Path(root),
                label=label or None,
                filesystem=filesystem or None,
            )
        )

    return drives


# ============================================================================
# LINUX REMOVABLE DRIVES
# ============================================================================

def _list_linux_removable_drives() -> list[RemovableDrive]:

    candidates: list[Path] = []

    roots = [
        Path("/media"),
        Path("/run/media"),
    ]

    for root in roots:

        if not root.exists():
            continue

        try:

            for user_dir in root.iterdir():

                if not user_dir.is_dir():
                    continue

                try:

                    for mount in user_dir.iterdir():

                        if mount.is_dir():
                            candidates.append(mount)

                except OSError:
                    continue

        except OSError:
            continue

    drives: list[RemovableDrive] = []

    seen: set[str] = set()

    for mount in candidates:

        try:
            resolved = mount.resolve()
        except OSError:
            resolved = mount

        key = str(resolved)

        if key in seen:
            continue

        seen.add(key)

        drives.append(
            RemovableDrive(
                mount_point=mount,
                label=mount.name,
                filesystem=None,
            )
        )

    return drives


# ============================================================================
# MACOS REMOVABLE DRIVES
# ============================================================================

def _list_macos_removable_drives() -> list[RemovableDrive]:

    root = Path("/Volumes")

    if not root.exists():
        return []

    drives: list[RemovableDrive] = []

    try:

        entries = root.iterdir()

    except OSError:

        return []

    for mount in entries:

        try:

            if not mount.is_dir():
                continue

        except OSError:

            continue

        drives.append(
            RemovableDrive(
                mount_point=mount,
                label=mount.name,
                filesystem=None,
            )
        )

    return drives


# ============================================================================
# REMOVABLE DRIVE API
# ============================================================================

def list_removable_drives() -> list[RemovableDrive]:

    system = platform.system()

    if system == "Windows":
        return _list_windows_removable_drives()

    if system == "Linux":
        return _list_linux_removable_drives()

    if system == "Darwin":
        return _list_macos_removable_drives()

    return []


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def save_recovery_key_local(
    recovery_key: str,
    directory: str | Path,
    *,
    filename: str | None = None,
) -> StorageResult:

    return save_recovery_key(
        recovery_key,
        directory,
        storage_type="local",
        filename=filename,
    )


def save_recovery_key_usb(
    recovery_key: str,
    directory: str | Path,
    *,
    filename: str | None = None,
) -> StorageResult:

    return save_recovery_key(
        recovery_key,
        directory,
        storage_type="usb",
        filename=filename,
    )