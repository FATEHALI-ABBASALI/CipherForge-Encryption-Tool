"""
CipherForge - Configuration Manager
===================================

Step 15

Provides secure, validated, cross-platform application configuration.

Security principles:
    - Never store passwords in configuration.
    - Never store recovery keys in configuration.
    - Never store encryption keys in configuration.
    - Validate every configuration value.
    - Reject unknown configuration keys.
    - Use atomic writes.
    - Use restrictive permissions where supported.
    - Provide safe defaults.
"""

from __future__ import annotations

import json
import os
import platform
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


# ============================================================================
# CONSTANTS
# ============================================================================

APP_NAME = "CipherForge"

CONFIG_FILENAME = "config.json"

CONFIG_VERSION = 1

DEFAULT_ALGORITHM = "aes-256-gcm"

DEFAULT_THEME = "dark"

DEFAULT_RECOVERY_STORAGE = "local"

DEFAULT_RECOVERY_FILENAME = "cipherforge_recovery"

DEFAULT_SECURE_DELETE = True

DEFAULT_CONTAINER_EXTENSION = ".cforge"


SUPPORTED_ALGORITHMS = frozenset(
    {
        "aes-256-gcm",
        "chacha20-poly1305",
    }
)

SUPPORTED_THEMES = frozenset(
    {
        "dark",
        "light",
    }
)

SUPPORTED_RECOVERY_STORAGE = frozenset(
    {
        "local",
        "usb",
    }
)

SUPPORTED_CONTAINER_EXTENSIONS = frozenset(
    {
        ".cforge",
    }
)


# ============================================================================
# EXCEPTIONS
# ============================================================================

class ConfigError(Exception):
    """Base configuration exception."""


class ConfigValidationError(ConfigError):
    """Raised when configuration values are invalid."""


class ConfigFileError(ConfigError):
    """Raised when configuration cannot be read or written."""


class UnknownConfigKeyError(ConfigValidationError):
    """Raised when an unsupported configuration key is supplied."""


# ============================================================================
# DATACLASS
# ============================================================================

@dataclass(frozen=True)
class CipherForgeConfig:
    """
    Application configuration.

    IMPORTANT:
        This object intentionally contains no password, recovery key,
        encryption key, or other secret material.
    """

    config_version: int = CONFIG_VERSION

    algorithm: str = DEFAULT_ALGORITHM

    theme: str = DEFAULT_THEME

    recovery_storage: str = DEFAULT_RECOVERY_STORAGE

    recovery_filename: str = DEFAULT_RECOVERY_FILENAME

    secure_delete: bool = DEFAULT_SECURE_DELETE

    container_extension: str = DEFAULT_CONTAINER_EXTENSION


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _normalize_algorithm(
    value: Any,
) -> str:

    if not isinstance(value, str):
        raise ConfigValidationError(
            "algorithm must be a string."
        )

    normalized = (
        value
        .strip()
        .lower()
        .replace("_", "-")
        .replace(" ", "")
    )

    aliases = {
        "aes": "aes-256-gcm",
        "aes256": "aes-256-gcm",
        "aes-256": "aes-256-gcm",
        "aes256gcm": "aes-256-gcm",
        "aes-256-gcm": "aes-256-gcm",

        "chacha": "chacha20-poly1305",
        "chacha20": "chacha20-poly1305",
        "chacha20poly1305": "chacha20-poly1305",
        "chacha20-poly1305": "chacha20-poly1305",
    }

    normalized = aliases.get(
        normalized,
        normalized,
    )

    if normalized not in SUPPORTED_ALGORITHMS:
        raise ConfigValidationError(
            f"Unsupported algorithm: {value}"
        )

    return normalized


def _normalize_theme(
    value: Any,
) -> str:

    if not isinstance(value, str):
        raise ConfigValidationError(
            "theme must be a string."
        )

    normalized = value.strip().lower()

    if normalized not in SUPPORTED_THEMES:
        raise ConfigValidationError(
            f"Unsupported theme: {value}"
        )

    return normalized


def _normalize_recovery_storage(
    value: Any,
) -> str:

    if not isinstance(value, str):
        raise ConfigValidationError(
            "recovery_storage must be a string."
        )

    normalized = value.strip().lower()

    if normalized not in SUPPORTED_RECOVERY_STORAGE:
        raise ConfigValidationError(
            f"Unsupported recovery storage: {value}"
        )

    return normalized


def _normalize_recovery_filename(
    value: Any,
) -> str:

    if not isinstance(value, str):
        raise ConfigValidationError(
            "recovery_filename must be a string."
        )

    filename = value.strip()

    if not filename:
        raise ConfigValidationError(
            "recovery_filename cannot be empty."
        )

    if len(filename) > 120:
        raise ConfigValidationError(
            "recovery_filename is too long."
        )

    # ------------------------------------------------------------------------
    # Filename must be a filename only.
    # No path traversal or directory separators.
    # ------------------------------------------------------------------------

    if "/" in filename or "\\" in filename:
        raise ConfigValidationError(
            "recovery_filename must not contain path separators."
        )

    if filename in {".", ".."}:
        raise ConfigValidationError(
            "Invalid recovery filename."
        )

    # ------------------------------------------------------------------------
    # Windows-invalid filename characters
    # ------------------------------------------------------------------------

    invalid_chars = set('<>:"|?*')

    if any(
        character in invalid_chars
        for character in filename
    ):
        raise ConfigValidationError(
            "recovery_filename contains invalid characters."
        )

    # ------------------------------------------------------------------------
    # Windows reserved device names
    # ------------------------------------------------------------------------

    reserved_names = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }

    stem = filename.split(".", 1)[0].upper()

    if stem in reserved_names:
        raise ConfigValidationError(
            "Reserved system filename is not allowed."
        )

    # ------------------------------------------------------------------------
    # Prevent hidden extension manipulation.
    # ------------------------------------------------------------------------

    if filename.lower().endswith(".cfrecovery"):
        filename = filename[:-10]

    if not filename:
        raise ConfigValidationError(
            "Invalid recovery filename."
        )

    return filename


def _normalize_secure_delete(
    value: Any,
) -> bool:

    if not isinstance(value, bool):
        raise ConfigValidationError(
            "secure_delete must be a boolean."
        )

    return value


def _normalize_container_extension(
    value: Any,
) -> str:

    if not isinstance(value, str):
        raise ConfigValidationError(
            "container_extension must be a string."
        )

    extension = value.strip().lower()

    if not extension.startswith("."):
        raise ConfigValidationError(
            "container_extension must start with '.'."
        )

    if extension not in SUPPORTED_CONTAINER_EXTENSIONS:
        raise ConfigValidationError(
            f"Unsupported container extension: {value}"
        )

    return extension


# ============================================================================
# CONFIGURATION VALIDATION
# ============================================================================

def validate_config(
    config: CipherForgeConfig,
) -> CipherForgeConfig:

    if not isinstance(
        config,
        CipherForgeConfig,
    ):
        raise ConfigValidationError(
            "config must be a CipherForgeConfig instance."
        )

    if config.config_version != CONFIG_VERSION:
        raise ConfigValidationError(
            f"Unsupported config version: "
            f"{config.config_version}"
        )

    return CipherForgeConfig(
        config_version=CONFIG_VERSION,

        algorithm=_normalize_algorithm(
            config.algorithm
        ),

        theme=_normalize_theme(
            config.theme
        ),

        recovery_storage=_normalize_recovery_storage(
            config.recovery_storage
        ),

        recovery_filename=_normalize_recovery_filename(
            config.recovery_filename
        ),

        secure_delete=_normalize_secure_delete(
            config.secure_delete
        ),

        container_extension=_normalize_container_extension(
            config.container_extension
        ),
    )


# ============================================================================
# DEFAULT CONFIG
# ============================================================================

def default_config() -> CipherForgeConfig:
    """
    Return a validated safe default configuration.
    """

    return validate_config(
        CipherForgeConfig()
    )


# ============================================================================
# PLATFORM CONFIG DIRECTORY
# ============================================================================

def get_config_directory() -> Path:
    """
    Return the platform-appropriate CipherForge configuration directory.

    Windows:
        %APPDATA%/CipherForge

    Linux:
        $XDG_CONFIG_HOME/CipherForge
        or ~/.config/CipherForge

    macOS:
        ~/Library/Application Support/CipherForge
    """

    system = platform.system().lower()

    # ------------------------------------------------------------------------
    # Windows
    # ------------------------------------------------------------------------

    if system == "windows":

        appdata = os.environ.get(
            "APPDATA"
        )

        if appdata:
            return (
                Path(appdata)
                / APP_NAME
            )

        return (
            Path.home()
            / "AppData"
            / "Roaming"
            / APP_NAME
        )

    # ------------------------------------------------------------------------
    # macOS
    # ------------------------------------------------------------------------

    if system == "darwin":

        return (
            Path.home()
            / "Library"
            / "Application Support"
            / APP_NAME
        )

    # ------------------------------------------------------------------------
    # Linux / Kali / Ubuntu
    # ------------------------------------------------------------------------

    xdg_config_home = os.environ.get(
        "XDG_CONFIG_HOME"
    )

    if xdg_config_home:
        return (
            Path(xdg_config_home)
            / APP_NAME
        )

    return (
        Path.home()
        / ".config"
        / APP_NAME
    )


# ============================================================================
# CONFIG PATH
# ============================================================================

def get_config_path() -> Path:
    """
    Return the complete configuration file path.
    """

    return (
        get_config_directory()
        / CONFIG_FILENAME
    )


# ============================================================================
# SECRET KEY PROTECTION
# ============================================================================

_SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "recovery_key",
        "recovery-key",
        "encryption_key",
        "encryption-key",
        "file_key",
        "file-key",
        "key",
        "secret",
        "secret_key",
        "secret-key",
    }
)


def _reject_secret_keys(
    data: dict[str, Any],
) -> None:

    for key in data:

        normalized = (
            str(key)
            .strip()
            .lower()
            .replace(" ", "_")
        )

        if normalized in _SECRET_KEYS:
            raise ConfigValidationError(
                f"Secret material cannot be stored "
                f"in configuration: {key}"
            )


# ============================================================================
# CONFIG SERIALIZATION
# ============================================================================

def config_to_dict(
    config: CipherForgeConfig,
) -> dict[str, Any]:

    validated = validate_config(
        config
    )

    return asdict(
        validated
    )


def config_from_dict(
    data: dict[str, Any],
) -> CipherForgeConfig:

    if not isinstance(
        data,
        dict,
    ):
        raise ConfigValidationError(
            "Configuration data must be a JSON object."
        )

    _reject_secret_keys(
        data
    )

    allowed_keys = {
        "config_version",
        "algorithm",
        "theme",
        "recovery_storage",
        "recovery_filename",
        "secure_delete",
        "container_extension",
    }

    unknown_keys = set(data) - allowed_keys

    if unknown_keys:
        raise UnknownConfigKeyError(
            "Unknown configuration keys: "
            + ", ".join(
                sorted(
                    str(key)
                    for key in unknown_keys
                )
            )
        )

    try:
        config = CipherForgeConfig(
            config_version=data.get(
                "config_version",
                CONFIG_VERSION,
            ),

            algorithm=data.get(
                "algorithm",
                DEFAULT_ALGORITHM,
            ),

            theme=data.get(
                "theme",
                DEFAULT_THEME,
            ),

            recovery_storage=data.get(
                "recovery_storage",
                DEFAULT_RECOVERY_STORAGE,
            ),

            recovery_filename=data.get(
                "recovery_filename",
                DEFAULT_RECOVERY_FILENAME,
            ),

            secure_delete=data.get(
                "secure_delete",
                DEFAULT_SECURE_DELETE,
            ),

            container_extension=data.get(
                "container_extension",
                DEFAULT_CONTAINER_EXTENSION,
            ),
        )

    except TypeError as exc:
        raise ConfigValidationError(
            "Invalid configuration structure."
        ) from exc

    return validate_config(
        config
    )


# ============================================================================
# FILE PERMISSIONS
# ============================================================================

def _restrict_file_permissions(
    path: Path,
) -> None:
    """
    Attempt to restrict configuration permissions.

    On POSIX:
        owner read/write only.

    Windows ACL behavior is managed by the operating system and user
    profile permissions; chmod alone is not treated as a full ACL
    security boundary.
    """

    if os.name != "nt":

        try:
            path.chmod(
                0o600
            )

        except OSError:
            # Do not hide a successfully written config because a
            # permission hardening operation is unavailable.
            pass


def _restrict_directory_permissions(
    path: Path,
) -> None:

    if os.name != "nt":

        try:
            path.chmod(
                0o700
            )

        except OSError:
            pass


# ============================================================================
# DIRECTORY CREATION
# ============================================================================

def ensure_config_directory() -> Path:

    directory = get_config_directory()

    try:

        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    except OSError as exc:
        raise ConfigFileError(
            f"Unable to create configuration directory: "
            f"{directory}"
        ) from exc

    _restrict_directory_permissions(
        directory
    )

    return directory


# ============================================================================
# ATOMIC CONFIG WRITE
# ============================================================================

def save_config(
    config: CipherForgeConfig,
    path: str | Path | None = None,
) -> Path:
    """
    Atomically save configuration.

    Process:
        1. Validate configuration.
        2. Create configuration directory.
        3. Write JSON to temporary file.
        4. Flush and fsync.
        5. Atomically replace target file.
        6. Restrict permissions where supported.
    """

    validated = validate_config(
        config
    )

    if path is None:

        target = get_config_path()

        directory = ensure_config_directory()

    else:

        target = Path(
            path
        ).expanduser().resolve(
            strict=False
        )

        directory = target.parent

        try:
            directory.mkdir(
                parents=True,
                exist_ok=True,
            )

        except OSError as exc:
            raise ConfigFileError(
                f"Unable to create config directory: "
                f"{directory}"
            ) from exc

        _restrict_directory_permissions(
            directory
        )

    data = config_to_dict(
        validated
    )

    payload = json.dumps(
        data,
        indent=4,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"

    temp_path: Path | None = None

    try:

        fd, temp_name = tempfile.mkstemp(
            prefix=".cipherforge-config-",
            suffix=".tmp",
            dir=str(directory),
            text=True,
        )

        temp_path = Path(
            temp_name
        )

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:

            handle.write(
                payload
            )

            handle.flush()

            os.fsync(
                handle.fileno()
            )

        _restrict_file_permissions(
            temp_path
        )

        os.replace(
            temp_path,
            target,
        )

        temp_path = None

        _restrict_file_permissions(
            target
        )

    except OSError as exc:

        raise ConfigFileError(
            f"Unable to save configuration: "
            f"{target}"
        ) from exc

    finally:

        if temp_path is not None:

            try:
                temp_path.unlink(
                    missing_ok=True
                )

            except OSError:
                pass

    return target


# ============================================================================
# LOAD CONFIG
# ============================================================================

def load_config(
    path: str | Path | None = None,
) -> CipherForgeConfig:
    """
    Load and validate configuration.

    Missing configuration:
        Returns safe defaults.

    Invalid configuration:
        Raises ConfigFileError / ConfigValidationError.

    It does NOT silently accept malformed security-related configuration.
    """

    target = (
        get_config_path()
        if path is None
        else Path(path)
        .expanduser()
        .resolve(strict=False)
    )

    if not target.exists():
        return default_config()

    if not target.is_file():
        raise ConfigFileError(
            f"Configuration path is not a file: "
            f"{target}"
        )

    try:

        raw_text = target.read_text(
            encoding="utf-8"
        )

    except OSError as exc:
        raise ConfigFileError(
            f"Unable to read configuration: "
            f"{target}"
        ) from exc

    try:

        data = json.loads(
            raw_text
        )

    except json.JSONDecodeError as exc:
        raise ConfigFileError(
            "Configuration contains invalid JSON."
        ) from exc

    return config_from_dict(
        data
    )


# ============================================================================
# INITIALIZE CONFIG
# ============================================================================

def initialize_config(
    path: str | Path | None = None,
) -> CipherForgeConfig:
    """
    Load existing configuration or create a safe default configuration.
    """

    target = (
        get_config_path()
        if path is None
        else Path(path)
        .expanduser()
        .resolve(strict=False)
    )

    if target.exists():

        return load_config(
            target
        )

    config = default_config()

    save_config(
        config,
        target,
    )

    return config


# ============================================================================
# UPDATE CONFIG
# ============================================================================

def update_config(
    config: CipherForgeConfig,
    **changes: Any,
) -> CipherForgeConfig:
    """
    Return a new validated configuration with requested changes.

    This function does not write to disk.
    Use save_config() to persist the result.
    """

    if not isinstance(
        config,
        CipherForgeConfig,
    ):
        raise ConfigValidationError(
            "config must be a CipherForgeConfig instance."
        )

    _reject_secret_keys(
        changes
    )

    allowed_keys = {
        "config_version",
        "algorithm",
        "theme",
        "recovery_storage",
        "recovery_filename",
        "secure_delete",
        "container_extension",
    }

    unknown_keys = set(changes) - allowed_keys

    if unknown_keys:
        raise UnknownConfigKeyError(
            "Unknown configuration keys: "
            + ", ".join(
                sorted(
                    str(key)
                    for key in unknown_keys
                )
            )
        )

    current = config_to_dict(
        config
    )

    current.update(
        changes
    )

    return config_from_dict(
        current
    )


# ============================================================================
# RESET CONFIG
# ============================================================================

def reset_config(
    path: str | Path | None = None,
) -> CipherForgeConfig:
    """
    Replace existing configuration with secure defaults.
    """

    config = default_config()

    save_config(
        config,
        path,
    )

    return config


# ============================================================================
# SAFE CONFIG SUMMARY
# ============================================================================

def get_safe_summary(
    config: CipherForgeConfig,
) -> dict[str, Any]:
    """
    Return a GUI-safe configuration summary.

    This function intentionally contains no secret material.
    """

    validated = validate_config(
        config
    )

    return {
        "application": APP_NAME,
        "config_version": validated.config_version,
        "algorithm": validated.algorithm,
        "theme": validated.theme,
        "recovery_storage": validated.recovery_storage,
        "recovery_filename": validated.recovery_filename,
        "secure_delete": validated.secure_delete,
        "container_extension": validated.container_extension,
    }


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    # Constants
    "APP_NAME",
    "CONFIG_FILENAME",
    "CONFIG_VERSION",
    "DEFAULT_ALGORITHM",
    "DEFAULT_THEME",
    "DEFAULT_RECOVERY_STORAGE",
    "DEFAULT_RECOVERY_FILENAME",
    "DEFAULT_SECURE_DELETE",
    "DEFAULT_CONTAINER_EXTENSION",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_THEMES",
    "SUPPORTED_RECOVERY_STORAGE",
    "SUPPORTED_CONTAINER_EXTENSIONS",

    # Exceptions
    "ConfigError",
    "ConfigValidationError",
    "ConfigFileError",
    "UnknownConfigKeyError",

    # Dataclass
    "CipherForgeConfig",

    # Validation
    "validate_config",
    "default_config",

    # Paths
    "get_config_directory",
    "get_config_path",

    # Serialization
    "config_to_dict",
    "config_from_dict",

    # File operations
    "ensure_config_directory",
    "save_config",
    "load_config",
    "initialize_config",

    # Modification
    "update_config",
    "reset_config",

    # Safe GUI summary
    "get_safe_summary",
]