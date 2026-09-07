"""
CipherForge
-----------
Custom exceptions used by the encryption backend.

Keeping application-specific exceptions in one module makes
error handling predictable across the GUI and backend.
"""


class CipherForgeError(Exception):
    """Base exception for all CipherForge errors."""


class InvalidPasswordError(CipherForgeError):
    """Raised when the supplied password is invalid."""


class InvalidRecoveryKeyError(CipherForgeError):
    """Raised when the supplied recovery key is invalid."""


class InvalidContainerError(CipherForgeError):
    """Raised when an encrypted CipherForge container is invalid."""


class UnsupportedAlgorithmError(CipherForgeError):
    """Raised when an unsupported encryption algorithm is requested."""


class AuthenticationError(CipherForgeError):
    """
    Raised when authenticated decryption fails.

    This can happen when:
    - password/key is incorrect
    - ciphertext was modified
    - authentication data is invalid
    """


class IntegrityError(CipherForgeError):
    """Raised when encrypted data fails an integrity check."""


class EncryptionError(CipherForgeError):
    """Raised when encryption cannot be completed."""


class DecryptionError(CipherForgeError):
    """Raised when decryption cannot be completed."""


class OperationCancelledError(CipherForgeError):
    """Raised when the user cancels an encryption/decryption operation."""