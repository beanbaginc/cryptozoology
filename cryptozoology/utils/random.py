"""Utilities for generating random values.

Version Added:
    1.0
"""

from __future__ import annotations

import os
from typing import NewType, TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Final


#: The size of an AES nonce/IV.
#:
#: Version Added:
#:     1.0
AES_NONCE_SIZE: Final[int] = 12


#: The size of an AES salt.
#:
#: Version Added:
#:     1.0
AES_SALT_SIZE: Final[int] = 32


#: A type representing a nonce/IV value.
#:
#: This is a strong subtype for a byte string, used to indicate a nonce value.
#:
#: Version Added:
#:     1.0
Nonce = NewType('Nonce', bytes)


#: A type representing a salt value.
#:
#: This is a strong subtype for a byte string, used to indicate a salt value.
#:
#: Version Added:
#:     1.0
Salt = NewType('Salt', bytes)


def generate_nonce(
    size_bytes: int,
) -> Nonce:
    """Return a random nonce of a given size.

    Version Added:
        1.0

    Args:
        size_bytes (int):
            The size of the nonce in bytes.

    Returns:
        Nonce:
        The new nonce.
    """
    return Nonce(os.urandom(size_bytes))


def generate_aes_nonce() -> Nonce:
    """Return a random 96-bit nonce for AES.

    Version Added:
        1.0

    Returns:
        Nonce:
        The new nonce.
    """
    return generate_nonce(AES_NONCE_SIZE)


def generate_salt(
    size_bytes: int,
) -> Salt:
    """Return a random salt of a given size.

    Version Added:
        1.0

    Args:
        size_bytes (int):
            The size of the salt in bytes.

    Returns:
        Salt:
        The new salt.
    """
    return Salt(os.urandom(size_bytes))


def generate_aes_salt() -> Salt:
    """Return a random 256-bit salt for AES.

    Version Added:
        1.0

    Returns:
        Salt:
        The new salt.
    """
    return generate_salt(AES_SALT_SIZE)
