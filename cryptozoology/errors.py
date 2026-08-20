"""Errors for Cryptozoology functions.

Version Added:
    1.0
"""

from __future__ import annotations


class CryptozoologyError(Exception):
    """Base class for a Cryptozoology error.

    Version Added:
        1.0
    """


class DecryptionError(CryptozoologyError):
    """Error with decrypting a secret.

    Version Added:
        1.0
    """


class InvalidatedError(CryptozoologyError):
    """Error indicating an object has been invalidated.

    Invalidated objects can no longer be used.

    Version Added:
        1.0
    """


class KeyDerivationError(CryptozoologyError):
    """An error deriving a key.

    Version Added:
        1.0
    """


class KeyUnwrapError(CryptozoologyError):
    """An error unwrapping a key.

    Version Added:
        1.0
    """


class UnsupportedAlgorithmError(CryptozoologyError):
    """An error indicating an operation with an unsupported algorithm.

    Version Added:
        1.0
    """

    ######################
    # Instance variables #
    ######################

    #: The algorithm that was attempted.
    alg: str

    def __init__(
        self,
        alg: str,
    ) -> None:
        """Initialize the error.

        Args:
            alg (str):
                The algorithm that was attempted.
        """
        super().__init__(
            f'The algorithm {alg!r} was not supported by this key.'
        )

        self.alg = alg
