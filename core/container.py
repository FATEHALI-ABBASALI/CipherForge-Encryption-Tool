"""
CipherForge
-----------
Encrypted-container format.

This module defines the binary structure used by CipherForge
encrypted files.

Responsibilities:

    - Create a CipherForge header
    - Parse a CipherForge header
    - Encode/decode chunk lengths
    - Read/write encrypted chunks

This module does NOT perform encryption or decryption.
"""

from __future__ import annotations

import json
import struct
from typing import BinaryIO

from .crypto import (
    ALGORITHM_IDS,
    ID_TO_ALGORITHM,
)
from .exceptions import (
    InvalidContainerError,
)


# ============================================================================
# Container constants
# ============================================================================

MAGIC = b"CFRG"

VERSION = 1

MAX_METADATA_SIZE = 1024 * 1024

MAX_CHUNK_SIZE = 64 * 1024 * 1024


# ============================================================================
# Integer helpers
# ============================================================================

def pack_u32(value: int) -> bytes:
    """
    Encode an unsigned 32-bit integer.
    """

    if not isinstance(value, int):
        raise TypeError(
            "Value must be an integer."
        )

    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError(
            "Value does not fit in uint32."
        )

    return struct.pack(
        ">I",
        value,
    )


def unpack_u32(data: bytes) -> int:
    """
    Decode an unsigned 32-bit integer.
    """

    if len(data) != 4:
        raise ValueError(
            "uint32 data must be exactly 4 bytes."
        )

    return struct.unpack(
        ">I",
        data,
    )[0]


def pack_u64(value: int) -> bytes:
    """
    Encode an unsigned 64-bit integer.
    """

    if not isinstance(value, int):
        raise TypeError(
            "Value must be an integer."
        )

    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(
            "Value does not fit in uint64."
        )

    return struct.pack(
        ">Q",
        value,
    )


def unpack_u64(data: bytes) -> int:
    """
    Decode an unsigned 64-bit integer.
    """

    if len(data) != 8:
        raise ValueError(
            "uint64 data must be exactly 8 bytes."
        )

    return struct.unpack(
        ">Q",
        data,
    )[0]


# ============================================================================
# Exact stream reading
# ============================================================================

def read_exact(
    stream: BinaryIO,
    size: int,
) -> bytes:
    """
    Read exactly `size` bytes from a binary stream.

    Raises:
        InvalidContainerError:
            If the stream ends before enough data is read.
    """

    if size < 0:
        raise ValueError(
            "Read size cannot be negative."
        )

    data = stream.read(
        size
    )

    if len(data) != size:
        raise InvalidContainerError(
            "Unexpected end of CipherForge container."
        )

    return data


# ============================================================================
# Header creation
# ============================================================================

def build_header(
    algorithm: str,
    salt: bytes,
    nonce_prefix: bytes,
    metadata: dict,
) -> bytes:
    """
    Build a CipherForge v1 container header.

    Header structure:

        MAGIC
        VERSION
        ALGORITHM_ID
        RESERVED
        SALT_LENGTH
        SALT
        NONCE_PREFIX_LENGTH
        NONCE_PREFIX
        METADATA_LENGTH
        METADATA

    Args:
        algorithm:
            Supported CipherForge algorithm.

        salt:
            Password KDF salt.

        nonce_prefix:
            Random nonce prefix used for chunk encryption.

        metadata:
            JSON-compatible metadata dictionary.

    Returns:
        Serialized binary header.
    """

    # ------------------------------------------------------------------------
    # Validate algorithm
    # ------------------------------------------------------------------------

    if algorithm not in ALGORITHM_IDS:
        raise InvalidContainerError(
            f"Unsupported algorithm: {algorithm}"
        )

    # ------------------------------------------------------------------------
    # Validate salt
    # ------------------------------------------------------------------------

    if not isinstance(
        salt,
        bytes,
    ):
        raise TypeError(
            "Salt must be bytes."
        )

    if not salt:
        raise InvalidContainerError(
            "Salt cannot be empty."
        )

    # ------------------------------------------------------------------------
    # Validate nonce prefix
    # ------------------------------------------------------------------------

    if not isinstance(
        nonce_prefix,
        bytes,
    ):
        raise TypeError(
            "Nonce prefix must be bytes."
        )

    if len(nonce_prefix) != 4:
        raise InvalidContainerError(
            "Nonce prefix must be exactly 4 bytes."
        )

    # ------------------------------------------------------------------------
    # Serialize metadata
    # ------------------------------------------------------------------------

    if not isinstance(
        metadata,
        dict,
    ):
        raise TypeError(
            "Metadata must be a dictionary."
        )

    try:

        metadata_bytes = json.dumps(
            metadata,
            ensure_ascii=False,
            separators=(
                ",",
                ":",
            ),
        ).encode(
            "utf-8"
        )

    except (
        TypeError,
        ValueError,
    ) as exc:

        raise InvalidContainerError(
            "Metadata cannot be serialized."
        ) from exc

    if len(metadata_bytes) > MAX_METADATA_SIZE:
        raise InvalidContainerError(
            "Metadata exceeds maximum allowed size."
        )

    # ------------------------------------------------------------------------
    # Build header
    # ------------------------------------------------------------------------

    header = bytearray()

    # Magic
    header.extend(
        MAGIC
    )

    # Version
    header.extend(
        struct.pack(
            ">B",
            VERSION,
        )
    )

    # Algorithm ID
    header.extend(
        struct.pack(
            ">B",
            ALGORITHM_IDS[algorithm],
        )
    )

    # Reserved bytes
    header.extend(
        b"\x00\x00"
    )

    # Salt
    header.extend(
        pack_u32(
            len(salt)
        )
    )

    header.extend(
        salt
    )

    # Nonce prefix
    header.extend(
        pack_u32(
            len(nonce_prefix)
        )
    )

    header.extend(
        nonce_prefix
    )

    # Metadata
    header.extend(
        pack_u32(
            len(metadata_bytes)
        )
    )

    header.extend(
        metadata_bytes
    )

    return bytes(
        header
    )


# ============================================================================
# Header parsing
# ============================================================================

def parse_header(
    stream: BinaryIO,
) -> dict:
    """
    Parse a CipherForge v1 header from a binary stream.

    Returns:

        {
            "version": 1,
            "algorithm": "...",
            "salt": bytes,
            "nonce_prefix": bytes,
            "metadata": dict,
        }
    """

    # ------------------------------------------------------------------------
    # Magic
    # ------------------------------------------------------------------------

    magic = read_exact(
        stream,
        4,
    )

    if magic != MAGIC:
        raise InvalidContainerError(
            "Invalid CipherForge magic."
        )

    # ------------------------------------------------------------------------
    # Version
    # ------------------------------------------------------------------------

    version = read_exact(
        stream,
        1,
    )[0]

    if version != VERSION:
        raise InvalidContainerError(
            f"Unsupported container version: {version}"
        )

    # ------------------------------------------------------------------------
    # Algorithm
    # ------------------------------------------------------------------------

    algorithm_id = read_exact(
        stream,
        1,
    )[0]

    algorithm = ID_TO_ALGORITHM.get(
        algorithm_id
    )

    if algorithm is None:
        raise InvalidContainerError(
            f"Unknown algorithm ID: {algorithm_id}"
        )

    # ------------------------------------------------------------------------
    # Reserved bytes
    # ------------------------------------------------------------------------

    read_exact(
        stream,
        2,
    )

    # ------------------------------------------------------------------------
    # Salt
    # ------------------------------------------------------------------------

    salt_size = unpack_u32(
        read_exact(
            stream,
            4,
        )
    )

    if salt_size == 0:
        raise InvalidContainerError(
            "Container contains an empty salt."
        )

    # Defensive limit.
    if salt_size > 1024:
        raise InvalidContainerError(
            "Container salt is unreasonably large."
        )

    salt = read_exact(
        stream,
        salt_size,
    )

    # ------------------------------------------------------------------------
    # Nonce prefix
    # ------------------------------------------------------------------------

    nonce_prefix_size = unpack_u32(
        read_exact(
            stream,
            4,
        )
    )

    if nonce_prefix_size != 4:
        raise InvalidContainerError(
            "Invalid nonce-prefix size."
        )

    nonce_prefix = read_exact(
        stream,
        nonce_prefix_size,
    )

    # ------------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------------

    metadata_size = unpack_u32(
        read_exact(
            stream,
            4,
        )
    )

    if metadata_size > MAX_METADATA_SIZE:
        raise InvalidContainerError(
            "Container metadata is too large."
        )

    metadata_bytes = read_exact(
        stream,
        metadata_size,
    )

    try:

        metadata = json.loads(
            metadata_bytes.decode(
                "utf-8"
            )
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:

        raise InvalidContainerError(
            "Container metadata is invalid."
        ) from exc

    if not isinstance(
        metadata,
        dict,
    ):
        raise InvalidContainerError(
            "Container metadata must be an object."
        )

    return {
        "version": version,
        "algorithm": algorithm,
        "salt": salt,
        "nonce_prefix": nonce_prefix,
        "metadata": metadata,
    }


# ============================================================================
# Chunk records
# ============================================================================

def build_chunk_record(
    ciphertext: bytes,
) -> bytes:
    """
    Build one encrypted chunk record.

    Format:

        4-byte ciphertext length
        ciphertext
    """

    if not isinstance(
        ciphertext,
        bytes,
    ):
        raise TypeError(
            "Ciphertext must be bytes."
        )

    if len(ciphertext) == 0:
        raise InvalidContainerError(
            "Ciphertext chunk cannot be empty."
        )

    if len(ciphertext) > MAX_CHUNK_SIZE:
        raise InvalidContainerError(
            "Ciphertext chunk exceeds maximum size."
        )

    return (
        pack_u32(
            len(ciphertext)
        )
        + ciphertext
    )


def read_chunk_record(
    stream: BinaryIO,
) -> bytes | None:
    """
    Read one encrypted chunk from a stream.

    Returns:
        bytes:
            Ciphertext of the next chunk.

        None:
            Clean end-of-file.

    Raises:
        InvalidContainerError:
            If the chunk record is malformed.
    """

    length_bytes = stream.read(
        4
    )

    # Clean EOF.
    if not length_bytes:
        return None

    # Partial length field.
    if len(length_bytes) != 4:
        raise InvalidContainerError(
            "Corrupted chunk length."
        )

    chunk_size = unpack_u32(
        length_bytes
    )

    if chunk_size == 0:
        raise InvalidContainerError(
            "Encrypted chunk cannot have zero length."
        )

    if chunk_size > MAX_CHUNK_SIZE:
        raise InvalidContainerError(
            "Encrypted chunk exceeds maximum size."
        )

    return read_exact(
        stream,
        chunk_size,
    )