"""Elliptic Curve keys.

Version Added:
    1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)

from cryptozoology.keys.base import BasePKIPublicKey, BasePKIPrivateKey

if TYPE_CHECKING:
    from typing import Self

    from cryptozoology.keys.base import BytesLike


class ECPublicKey(BasePKIPublicKey['ECPrivateKey',
                                   ec.EllipticCurvePublicKey]):
    """A public key used for Elliptic Curve cryptography.

    Version Added:
        1.0
    """

    key_type_id = 'ec'

    @classmethod
    def from_bytes(
        cls,
        key_bytes: BytesLike,
        *,
        key_id: (str | None) = None,
    ) -> Self:
        """Return a new EC public key from DER/PKCS8-encoded bytes.

        This expects the same encoding produced by
        :py:meth:`~cryptozoology.keys.base.BasePKIPublicKey.to_bytes`.

        Args:
            key_bytes (bytes or bytearray):
                The DER/PKCS8-encoded public key bytes to build the key from.

            key_id (str, optional):
                The KID (Key ID) of the key.

        Returns:
            ECPrivateKey:
            The new key instance.
        """
        # We ignore the type here because the function's typed for bytes
        # only, but in actuality it accepts any bytes-like.
        try:
            impl_public_key = load_der_public_key(cast(bytes, key_bytes))
        except ValueError:
            impl_public_key = None

        if not isinstance(impl_public_key, ec.EllipticCurvePublicKey):
            raise ValueError(
                'The provided key is not an Elliptic Curve public key.'
            )

        return cls(impl_public_key=impl_public_key,
                   key_id=key_id)


class ECPrivateKey(BasePKIPrivateKey['ECPublicKey',
                                     ec.EllipticCurvePrivateKey]):
    """A private key used for Elliptic Curve cryptography.

    Version Added:
        1.0
    """

    key_type_id = 'ec'
    public_key_cls = ECPublicKey

    @classmethod
    def generate(
        cls,
        *,
        curve: ec.EllipticCurve = ec.SECP256R1(),
        key_id: (str | None) = None,
    ) -> Self:
        """Generate a new EC private key.

        Args:
            curve (cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve,
                   optional):
                The curve to generate the key on.

                This defaults to NIST P-256 (``SECP256R1``).

            key_id (str, optional):
                The KID (Key ID) of the key.

        Returns:
            ECPrivateKey:
            The new key instance.
        """
        return cls(ec.generate_private_key(curve),
                   key_id=key_id)

    @classmethod
    def from_bytes(
        cls,
        key_bytes: BytesLike,
        *,
        key_id: (str | None) = None,
        password: (bytes | None) = None,
    ) -> Self:
        """Return a new EC private key from DER/PKCS8-encoded bytes.

        This expects the same encoding produced by
        :py:meth:`~cryptozoology.keys.base.BasePKIPrivateKey.to_bytes`.

        Args:
            key_bytes (bytes or bytearray):
                The DER/PKCS8-encoded key bytes to build the key from.

            key_id (str, optional):
                The KID (Key ID) of the key.

            password (bytes, optional):
                The optional password protecting the key.

        Returns:
            ECPrivateKey:
            The new key instance.
        """
        try:
            impl_private_key = load_der_private_key(cast(bytes, key_bytes),
                                                    password=password)
        except TypeError as e:
            # This may be a "Password was given but private key is not
            # encrypted" error. We don't have a more specific type for
            # things like this.
            raise ValueError(str(e)) from e
        except ValueError:
            # This can be a non-EC key, the password may not be valid,
            # or a password may not be specified when required. There is
            # no specific error, so we just fall back to the default below.
            impl_private_key = None

        if not isinstance(impl_private_key, ec.EllipticCurvePrivateKey):
            raise ValueError(
                'The provided key could not be loaded as an Elliptic '
                'Curve private key.'
            )

        return cls(impl_private_key=impl_private_key,
                   key_id=key_id)

    def exchange(
        self,
        public_key: ECPublicKey,
    ) -> bytearray:
        """Perform a key exchange with another public key.

        Args:
            public_key (ECPublicKey):
                The other public key to exchange with.

        Returns:
            bytearray:
            The resulting shared key.

        Raises:
            cryptozoology.errors.InvalidatedError:
                This key is no longer valid.
        """
        self.assert_valid()

        impl_private_key = self.impl_private_key
        impl_public_key = public_key.impl_public_key

        assert impl_private_key is not None
        assert impl_public_key is not None

        return bytearray(impl_private_key.exchange(ec.ECDH(),
                                                   impl_public_key))
