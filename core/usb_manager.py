"""
CipherForge - USB / Removable Drive Manager
============================================

Step 12

Responsibilities:
    - Detect removable drives
    - Provide normalized drive information
    - Validate a selected removable drive
    - Safely resolve a destination directory
    - Prevent accidental use of a normal/local path as USB storage

Supported:
    - Windows
    - Linux
    - macOS

This module does NOT encrypt files.
This module does NOT store passwords.
This module does NOT store recovery keys itself.

Storage of recovery keys remains the responsibility of:
    core.storage_manager
"""

from __future__ import annotations

import ctypes
import os
import platform
from dataclasses import dataclass
from pathlib import Path


# ============================================================================
# CONSTANTS
# ============================================================================

WINDOWS_DRIVE_REMOVABLE = 2
WINDOWS_DRIVE_FIXED = 3
WINDOWS_DRIVE_REMOTE = 4
WINDOWS_DRIVE_CDROM = 5


# ============================================================================
# EXCEPTIONS
# ============================================================================


class USBManagerError(Exception):
    """Base USB manager exception."""


class USBDriveNotFoundError(USBManagerError):
    """Requested USB/removable drive was not found."""


class InvalidUSBDriveError(USBManagerError):
    """Selected path is not a valid removable drive."""


class USBPathError(USBManagerError):
    """Invalid path inside a removable drive."""


# ============================================================================
# DATA MODEL
# ============================================================================


@dataclass(frozen=True)
class USBDrive:
    """
    Information about a detected removable drive.
    """

    mount_point: Path
    label: str | None = None
    filesystem: str | None = None
    total_bytes: int | None = None
    free_bytes: int | None = None

    @property
    def name(self) -> str:
        """
        Human-readable drive name.
        """

        if self.label:
            return self.label

        return self.mount_point.name or str(
            self.mount_point
        )

    @property
    def display_name(self) -> str:
        """
        GUI-friendly display name.
        """

        if self.label:
            return (
                f"{self.label} "
                f"({self.mount_point})"
            )

        return str(self.mount_point)


# ============================================================================
# PLATFORM
# ============================================================================


def get_platform_name() -> str:
    """
    Return normalized platform name.
    """

    system = platform.system()

    if system == "Windows":
        return "windows"

    if system == "Linux":
        return "linux"

    if system == "Darwin":
        return "macos"

    return system.lower()


# ============================================================================
# PATH HELPERS
# ============================================================================


def _safe_resolve(
    path: Path,
) -> Path:
    """
    Resolve a path without requiring it to exist.
    """

    try:
        return path.resolve(
            strict=False
        )
    except OSError:
        return path.absolute()


def _get_disk_usage(
    path: Path,
) -> tuple[int | None, int | None]:
    """
    Return total and free bytes.

    Returns:
        (total_bytes, free_bytes)

    If the platform refuses access, returns:
        (None, None)
    """

    try:

        usage = os.statvfs(path)

        total = (
            usage.f_frsize
            * usage.f_blocks
        )

        free = (
            usage.f_frsize
            * usage.f_bavail
        )

        return total, free

    except (AttributeError, OSError):

        return None, None


# ============================================================================
# WINDOWS
# ============================================================================


def _get_windows_volume_info(
    root: str,
) -> tuple[str | None, str | None]:
    """
    Read Windows volume label and filesystem.
    """

    kernel32 = ctypes.windll.kernel32

    get_volume_information = (
        kernel32.GetVolumeInformationW
    )

    label_buffer = ctypes.create_unicode_buffer(
        261
    )

    filesystem_buffer = (
        ctypes.create_unicode_buffer(261)
    )

    serial_number = ctypes.c_ulong()
    max_component_length = ctypes.c_ulong()
    filesystem_flags = ctypes.c_ulong()

    try:

        success = get_volume_information(
            root,
            label_buffer,
            len(label_buffer),
            ctypes.byref(serial_number),
            ctypes.byref(
                max_component_length
            ),
            ctypes.byref(filesystem_flags),
            filesystem_buffer,
            len(filesystem_buffer),
        )

    except Exception:

        return None, None

    if not success:
        return None, None

    label = (
        label_buffer.value
        or None
    )

    filesystem = (
        filesystem_buffer.value
        or None
    )

    return label, filesystem


def _list_windows_removable_drives() -> list[USBDrive]:
    """
    Detect Windows drives reported as DRIVE_REMOVABLE.
    """

    drives: list[USBDrive] = []

    kernel32 = ctypes.windll.kernel32

    get_drive_type = (
        kernel32.GetDriveTypeW
    )

    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":

        root_string = f"{letter}:\\"

        try:

            drive_type = get_drive_type(
                root_string
            )

        except Exception:

            continue

        if (
            drive_type
            != WINDOWS_DRIVE_REMOVABLE
        ):
            continue

        root = Path(root_string)

        if not root.exists():
            continue

        label, filesystem = (
            _get_windows_volume_info(
                root_string
            )
        )

        total_bytes, free_bytes = (
            _get_disk_usage(root)
        )

        drives.append(
            USBDrive(
                mount_point=root,
                label=label,
                filesystem=filesystem,
                total_bytes=total_bytes,
                free_bytes=free_bytes,
            )
        )

    return drives


# ============================================================================
# LINUX
# ============================================================================


def _list_linux_removable_drives() -> list[USBDrive]:
    """
    Detect common Linux removable-media mount points.

    Typical locations:
        /media/<user>/<drive>
        /run/media/<user>/<drive>
    """

    candidates: list[Path] = []

    roots = (
        Path("/media"),
        Path("/run/media"),
    )

    for root in roots:

        if not root.exists():
            continue

        try:

            for entry in root.iterdir():

                if not entry.is_dir():
                    continue

                try:

                    for mount in entry.iterdir():

                        if mount.is_dir():
                            candidates.append(
                                mount
                            )

                except OSError:

                    continue

        except OSError:

            continue

    drives: list[USBDrive] = []

    seen: set[str] = set()

    for mount in candidates:

        resolved = _safe_resolve(
            mount
        )

        key = str(resolved)

        if key in seen:
            continue

        seen.add(key)

        total_bytes, free_bytes = (
            _get_disk_usage(mount)
        )

        drives.append(
            USBDrive(
                mount_point=mount,
                label=mount.name or None,
                filesystem=None,
                total_bytes=total_bytes,
                free_bytes=free_bytes,
            )
        )

    return drives


# ============================================================================
# MACOS
# ============================================================================


def _list_macos_removable_drives() -> list[USBDrive]:
    """
    Detect mounted external volumes under /Volumes.

    macOS does not expose every mounted volume as removable using the same
    simple API available on Windows, so this function intentionally returns
    mounted external-volume candidates.
    """

    root = Path("/Volumes")

    if not root.exists():
        return []

    drives: list[USBDrive] = []

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

        total_bytes, free_bytes = (
            _get_disk_usage(mount)
        )

        drives.append(
            USBDrive(
                mount_point=mount,
                label=mount.name or None,
                filesystem=None,
                total_bytes=total_bytes,
                free_bytes=free_bytes,
            )
        )

    return drives


# ============================================================================
# PUBLIC DETECTION API
# ============================================================================


def list_usb_drives() -> list[USBDrive]:
    """
    Return currently detected removable drives.
    """

    system = platform.system()

    if system == "Windows":
        return _list_windows_removable_drives()

    if system == "Linux":
        return _list_linux_removable_drives()

    if system == "Darwin":
        return _list_macos_removable_drives()

    return []


def get_usb_drives() -> list[USBDrive]:
    """
    Alias for GUI/service layer compatibility.
    """

    return list_usb_drives()


# ============================================================================
# DRIVE LOOKUP
# ============================================================================


def find_usb_drive(
    mount_point: str | Path,
) -> USBDrive:
    """
    Find a currently connected removable drive.

    Raises:
        USBDriveNotFoundError
    """

    requested = _safe_resolve(
        Path(mount_point)
    )

    for drive in list_usb_drives():

        actual = _safe_resolve(
            drive.mount_point
        )

        if actual == requested:
            return drive

    raise USBDriveNotFoundError(
        f"USB/removable drive not found: "
        f"{mount_point}"
    )


# ============================================================================
# USB VALIDATION
# ============================================================================


def is_usb_drive(
    mount_point: str | Path,
) -> bool:
    """
    Return True only if the supplied path corresponds to a currently
    detected removable drive.
    """

    try:

        find_usb_drive(
            mount_point
        )

        return True

    except USBDriveNotFoundError:

        return False


def validate_usb_drive(
    mount_point: str | Path,
) -> USBDrive:
    """
    Validate that a path belongs to a currently detected USB/removable drive.
    """

    path = Path(mount_point)

    if not path.exists():
        raise USBDriveNotFoundError(
            f"USB path does not exist: {path}"
        )

    if not path.is_dir():
        raise InvalidUSBDriveError(
            f"USB mount point is not a directory: "
            f"{path}"
        )

    return find_usb_drive(
        path
    )


# ============================================================================
# SAFE DESTINATION
# ============================================================================


def get_usb_destination(
    mount_point: str | Path,
    *,
    folder_name: str = "CipherForge",
    create: bool = True,
) -> Path:
    """
    Return a safe CipherForge directory inside a removable drive.

    Example:

        E:\\
            CipherForge\\

    The returned path is guaranteed to remain inside the selected
    removable-drive root.
    """

    drive = validate_usb_drive(
        mount_point
    )

    if not isinstance(
        folder_name,
        str,
    ):
        raise USBPathError(
            "folder_name must be a string."
        )

    folder_name = folder_name.strip()

    if not folder_name:
        raise USBPathError(
            "folder_name cannot be empty."
        )

    normalized = folder_name.replace(
        "\\",
        "/",
    )

    if normalized.startswith("/"):
        raise USBPathError(
            "Absolute folder paths are not allowed."
        )

    if "/" in normalized:
        raise USBPathError(
            "folder_name must contain only one directory name."
        )

    if folder_name in {
        ".",
        "..",
    }:
        raise USBPathError(
            "Invalid folder name."
        )

    if any(
        part == ".."
        for part in Path(
            normalized
        ).parts
    ):
        raise USBPathError(
            "Path traversal is not allowed."
        )

    root = _safe_resolve(
        drive.mount_point
    )

    destination = _safe_resolve(
        root / folder_name
    )

    try:

        destination.relative_to(
            root
        )

    except ValueError as exc:

        raise USBPathError(
            "Destination escapes the USB drive."
        ) from exc

    if create:

        try:

            destination.mkdir(
                parents=True,
                exist_ok=True,
            )

        except OSError as exc:

            raise USBPathError(
                f"Could not create USB destination: "
                f"{exc}"
            ) from exc

    return destination


# ============================================================================
# FREE SPACE
# ============================================================================


def get_usb_free_space(
    mount_point: str | Path,
) -> int:
    """
    Return available free space in bytes.
    """

    drive = validate_usb_drive(
        mount_point
    )

    if drive.free_bytes is None:

        raise USBManagerError(
            "Unable to determine free space."
        )

    return drive.free_bytes


def get_usb_total_space(
    mount_point: str | Path,
) -> int:
    """
    Return total capacity in bytes.
    """

    drive = validate_usb_drive(
        mount_point
    )

    if drive.total_bytes is None:

        raise USBManagerError(
            "Unable to determine total space."
        )

    return drive.total_bytes


# ============================================================================
# EXPORTS
# ============================================================================


__all__ = [
    "USBDrive",
    "USBManagerError",
    "USBDriveNotFoundError",
    "InvalidUSBDriveError",
    "USBPathError",
    "get_platform_name",
    "list_usb_drives",
    "get_usb_drives",
    "find_usb_drive",
    "is_usb_drive",
    "validate_usb_drive",
    "get_usb_destination",
    "get_usb_free_space",
    "get_usb_total_space",
]