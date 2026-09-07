"""
CipherForge - Secure Delete / Secure Cleanup
=============================================

Step 13

Provides controlled deletion of files and empty directories.

Security goals:
    - Never follow symbolic links as directories
    - Reject dangerous paths such as filesystem roots
    - Reject paths outside an explicitly supplied allowed root
    - Prevent accidental deletion of directories
    - Optional best-effort overwrite for regular files
    - Verify deletion
    - Handle read-only files where possible

IMPORTANT:
    Overwriting a file is NOT guaranteed forensic erasure on SSDs,
    flash storage, copy-on-write filesystems, snapshots, backups, etc.

    Therefore this module should be considered secure application cleanup,
    not guaranteed physical media sanitization.
"""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path


# ============================================================================
# CONSTANTS
# ============================================================================

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB


# ============================================================================
# EXCEPTIONS
# ============================================================================


class SecureDeleteError(Exception):
    """Base secure-delete exception."""


class UnsafeDeletePathError(SecureDeleteError):
    """Path is unsafe to delete."""


class DeleteTargetNotFoundError(SecureDeleteError):
    """Requested target does not exist."""


class DeleteTargetTypeError(SecureDeleteError):
    """Target type is not supported by the requested operation."""


class SecureDeleteVerificationError(SecureDeleteError):
    """Deletion could not be verified."""


# ============================================================================
# RESULT
# ============================================================================


@dataclass(frozen=True)
class SecureDeleteResult:
    """
    Result of a successful file deletion.
    """

    path: Path
    bytes_processed: int
    overwrite_passes: int
    deleted: bool


# ============================================================================
# PATH SAFETY
# ============================================================================


def _resolve_existing_path(
    path: str | Path,
) -> Path:
    """
    Resolve an existing filesystem path.

    strict=True prevents resolving a nonexistent target.
    """

    candidate = Path(path)

    try:
        return candidate.resolve(
            strict=True
        )
    except OSError as exc:
        raise DeleteTargetNotFoundError(
            f"Target does not exist: {path}"
        ) from exc


def _is_filesystem_root(
    path: Path,
) -> bool:
    """
    Return True if path is a filesystem root.
    """

    resolved = path.resolve()

    return resolved.parent == resolved


def _validate_allowed_root(
    target: Path,
    allowed_root: str | Path,
) -> None:
    """
    Ensure target is inside allowed_root.

    The root itself is not considered a valid file target.
    """

    root = _resolve_existing_path(
        allowed_root
    )

    if not root.is_dir():
        raise UnsafeDeletePathError(
            f"Allowed root is not a directory: {root}"
        )

    if target == root:
        raise UnsafeDeletePathError(
            "Deleting the allowed root itself is forbidden."
        )

    try:

        target.relative_to(root)

    except ValueError as exc:

        raise UnsafeDeletePathError(
            "Delete target is outside the allowed root."
        ) from exc


def _validate_file_target(
    path: str | Path,
    *,
    allowed_root: str | Path | None = None,
) -> Path:
    """
    Validate a regular-file deletion target.
    """

    target = _resolve_existing_path(
        path
    )

    if _is_filesystem_root(target):
        raise UnsafeDeletePathError(
            "Filesystem root cannot be deleted."
        )

    if target.is_symlink():
        raise UnsafeDeletePathError(
            "Symbolic links are not accepted as delete targets."
        )

    if not target.is_file():
        raise DeleteTargetTypeError(
            f"Target is not a regular file: {target}"
        )

    if allowed_root is not None:

        _validate_allowed_root(
            target,
            allowed_root,
        )

    return target


# ============================================================================
# FILE PERMISSION
# ============================================================================


def _make_writable(
    path: Path,
) -> None:
    """
    Best-effort permission adjustment for read-only files.
    """

    try:

        current_mode = stat.S_IMODE(
            path.stat().st_mode
        )

        path.chmod(
            current_mode
            | stat.S_IWRITE
        )

    except OSError:
        # The actual delete operation will provide the final error.
        pass


# ============================================================================
# OVERWRITE
# ============================================================================


def _overwrite_file(
    path: Path,
    *,
    passes: int,
    chunk_size: int,
) -> int:
    """
    Best-effort overwrite of file contents.

    Returns total bytes processed.

    Pass 1:
        Cryptographically secure random bytes.

    Additional passes:
        Fresh cryptographically secure random bytes.

    The final deletion is still required.
    """

    if passes < 0:
        raise ValueError(
            "passes cannot be negative."
        )

    if chunk_size <= 0:
        raise ValueError(
            "chunk_size must be positive."
        )

    if passes == 0:
        return 0

    file_size = path.stat().st_size

    if file_size == 0:
        return 0

    total_processed = 0

    for _ in range(passes):

        remaining = file_size

        with path.open(
            "r+b",
            buffering=0,
        ) as file:

            while remaining > 0:

                current_size = min(
                    chunk_size,
                    remaining,
                )

                data = secrets.token_bytes(
                    current_size
                )

                file.write(data)

                total_processed += (
                    current_size
                )

                remaining -= current_size

            file.flush()

            try:
                os.fsync(
                    file.fileno()
                )
            except OSError:
                pass

    return total_processed


# ============================================================================
# DELETE FILE
# ============================================================================


def secure_delete_file(
    path: str | Path,
    *,
    allowed_root: str | Path | None = None,
    overwrite_passes: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> SecureDeleteResult:
    """
    Securely clean up and delete one regular file.

    By default one best-effort random overwrite pass is performed.

    For modern SSDs this does NOT guarantee forensic erasure.
    """

    target = _validate_file_target(
        path,
        allowed_root=allowed_root,
    )

    _make_writable(
        target
    )

    bytes_processed = _overwrite_file(
        target,
        passes=overwrite_passes,
        chunk_size=chunk_size,
    )

    try:

        target.unlink()

    except OSError as exc:

        raise SecureDeleteError(
            f"Could not delete file: {target}"
        ) from exc

    if target.exists():

        raise SecureDeleteVerificationError(
            f"File still exists after deletion: {target}"
        )

    return SecureDeleteResult(
        path=target,
        bytes_processed=bytes_processed,
        overwrite_passes=overwrite_passes,
        deleted=True,
    )


# ============================================================================
# NORMAL DELETE WITHOUT OVERWRITE
# ============================================================================


def delete_file(
    path: str | Path,
    *,
    allowed_root: str | Path | None = None,
) -> SecureDeleteResult:
    """
    Delete a regular file without an overwrite pass.

    Useful for non-sensitive temporary files.
    """

    return secure_delete_file(
        path,
        allowed_root=allowed_root,
        overwrite_passes=0,
    )


# ============================================================================
# EMPTY DIRECTORY
# ============================================================================


def delete_empty_directory(
    path: str | Path,
    *,
    allowed_root: str | Path | None = None,
) -> Path:
    """
    Delete an empty directory.

    This operation never recursively deletes contents.
    """

    target = _resolve_existing_path(
        path
    )

    if _is_filesystem_root(target):
        raise UnsafeDeletePathError(
            "Filesystem root cannot be deleted."
        )

    if target.is_symlink():
        raise UnsafeDeletePathError(
            "Symbolic links cannot be deleted as directories."
        )

    if not target.is_dir():
        raise DeleteTargetTypeError(
            f"Target is not a directory: {target}"
        )

    if allowed_root is not None:

        _validate_allowed_root(
            target,
            allowed_root,
        )

    try:

        target.rmdir()

    except OSError as exc:

        raise SecureDeleteError(
            f"Directory is not empty or cannot be removed: "
            f"{target}"
        ) from exc

    if target.exists():

        raise SecureDeleteVerificationError(
            f"Directory still exists: {target}"
        )

    return target


# ============================================================================
# DIRECTORY TREE CLEANUP
# ============================================================================


def secure_delete_tree(
    directory: str | Path,
    *,
    allowed_root: str | Path,
    overwrite_passes: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> int:
    """
    Delete a directory tree safely.

    Every file is validated against allowed_root before deletion.

    Symbolic links are deleted as links only and are NEVER followed.

    Returns:
        Number of deleted filesystem objects.
    """

    root = _resolve_existing_path(
        directory
    )

    if not root.is_dir():
        raise DeleteTargetTypeError(
            f"Target is not a directory: {root}"
        )

    if root.is_symlink():
        raise UnsafeDeletePathError(
            "Symbolic-link directory is not allowed."
        )

    _validate_allowed_root(
        root,
        allowed_root,
    )

    deleted_count = 0

    # Walk bottom-up so directories can be removed after their contents.
    for current_root, dir_names, file_names in os.walk(
        root,
        topdown=False,
        followlinks=False,
    ):

        current_path = Path(
            current_root
        )

        # Files
        for filename in file_names:

            file_path = (
                current_path / filename
            )

            # Symlinks are removed as links, never followed.
            if file_path.is_symlink():

                _validate_allowed_root(
                    file_path.resolve(
                        strict=False
                    ),
                    allowed_root,
                )

                try:
                    file_path.unlink()
                except OSError as exc:
                    raise SecureDeleteError(
                        f"Could not remove symbolic link: "
                        f"{file_path}"
                    ) from exc

                deleted_count += 1
                continue

            secure_delete_file(
                file_path,
                allowed_root=allowed_root,
                overwrite_passes=overwrite_passes,
                chunk_size=chunk_size,
            )

            deleted_count += 1

        # Directories
        for dirname in dir_names:

            directory_path = (
                current_path / dirname
            )

            if directory_path.is_symlink():

                try:
                    directory_path.unlink()
                except OSError as exc:
                    raise SecureDeleteError(
                        f"Could not remove symbolic directory link: "
                        f"{directory_path}"
                    ) from exc

                deleted_count += 1
                continue

            delete_empty_directory(
                directory_path,
                allowed_root=allowed_root,
            )

            deleted_count += 1

    # The requested root directory itself is removed last.
    delete_empty_directory(
        root,
        allowed_root=allowed_root,
    )

    deleted_count += 1

    return deleted_count


# ============================================================================
# TEMPORARY FILE SAFETY
# ============================================================================


def is_safe_delete_target(
    path: str | Path,
    *,
    allowed_root: str | Path,
) -> bool:
    """
    Return True only when a regular file is safely inside allowed_root.
    """

    try:

        _validate_file_target(
            path,
            allowed_root=allowed_root,
        )

        return True

    except SecureDeleteError:

        return False


# ============================================================================
# EXPORTS
# ============================================================================


__all__ = [
    "SecureDeleteError",
    "UnsafeDeletePathError",
    "DeleteTargetNotFoundError",
    "DeleteTargetTypeError",
    "SecureDeleteVerificationError",
    "SecureDeleteResult",
    "secure_delete_file",
    "delete_file",
    "delete_empty_directory",
    "secure_delete_tree",
    "is_safe_delete_target",
]