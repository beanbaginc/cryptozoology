"""Encoding/decoding utilities.

Version Added:
    1.0
"""

from __future__ import annotations

import base64
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import TypeAlias


#: A type alias for a byte string, byte array, or memory view.
#:
#: Version Added:
#:     1.0
BytesLike: TypeAlias = bytes | bytearray | memoryview


def b64u_encode(
    b: BytesLike,
) -> str:
    """Return a URL-safe Base64-encoded payload without padding.

    Version Added:
        1.0

    Args:
        b (bytearray or bytes or memoryview):
            The bytes to encode.

    Returns:
        str:
        The resulting encoded string.

    Raises:
        TypeError:
            The type provided is not a byte string.
    """
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise TypeError(f'b64u_encode takes bytes, not {type(b)}.')

    return (
        base64.urlsafe_b64encode(b)
        .rstrip(b'=')
        .decode('ascii')
    )


def b64u_decode(
    s: str,
) -> bytes:
    """Return decoded data from a padding-less URL-safe base64 payload.

    Version Added:
        1.0

    Args:
        s (str):
            The string to decode.

    Returns:
        bytes:
        The decoded data.
    """
    if not isinstance(s, str):
        raise TypeError(f'b64u_decode takes str, not {type(s)}.')

    padding = '=' * (-len(s) % 4)

    return base64.urlsafe_b64decode(s + padding)


def build_length_prefixed_bytes(
    data: bytes,
) -> bytes:
    """Return the provided bytes prefixed with an encoded byte length.

    This is useful for AAD data, providing a 4-byte length prefix in Big
    Endian.

    Version Added:
        1.0

    Args:
        data (bytes):
            The bytes to prefix and return.

    Returns:
        bytes:
        The length-prefixed data.
    """
    return struct.pack('>I', len(data)) + data
