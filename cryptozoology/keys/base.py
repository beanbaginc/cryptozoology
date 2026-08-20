"""Base classes for cryptographic keys.

Version Added:
    1.0
"""

from __future__ import annotations

import hashlib
from typing import Generic, TYPE_CHECKING, TypeVar

from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from cryptozoology.utils.invalidation import (
    InvalidatableMixin,
    SensitiveBytes,
)

if TYPE_CHECKING:
    from typing import ClassVar, Self, TypedDict

    from cryptography.hazmat.primitives.asymmetric.types import (
        PrivateKeyTypes,
        PublicKeyTypes,
    )
    from cryptography.hazmat.primitives.serialization import (
        KeySerializationEncryption,
    )
    from typelets.funcs import KwargsDict

    from cryptozoology.utils.encoding import BytesLike

    class EncryptedDataKwargs(TypedDict):
        """Keyword arguments supported by the EncryptedData constructor.

        Version Added:
            1.0
        """

        #: The algorithm used for encryption.
        alg: str

        #: The full ciphertext to encode.
        ciphertext: bytes

        #: The ciphertext excluding any nonce, tag, or other state.
        raw_ciphertext: bytes


#: A type variable for a key.
#:
#: Version Added:
#:     1.0
TKey = TypeVar('TKey', bound='BaseKey')


_PKIPrivateKeyType = TypeVar('_PKIPrivateKeyType',
                             bound='BasePKIPrivateKey')
_PKIPublicKeyType = TypeVar('_PKIPublicKeyType',
                            bound='BasePKIPublicKey')
_ImplPublicKeyType = TypeVar('_ImplPublicKeyType',
                             bound='PublicKeyTypes')
_ImplPrivateKeyType = TypeVar('_ImplPrivateKeyType',
                              bound='PrivateKeyTypes')


class EncryptedData:
    """The result of an encryption operation.

    This stores the ciphertext and algorithm resulting from an encryption
    operation.

    Keys can subclass this to provide additional information.

    Version Added:
        1.0
    """

    ######################
    # Instance variables #
    ######################

    #: The algorithm used for encryption.
    alg: str

    #: The full ciphertext to encode.
    ciphertext: bytes

    #: The ciphertext excluding any nonce, tag, or other state.
    raw_ciphertext: bytes

    def __init__(
        self,
        *,
        alg: str,
        ciphertext: bytes,
        raw_ciphertext: bytes,
    ) -> None:
        """Initialize the encrypted data.

        Args:
            alg (str):
                The algorithm used for encryption.

            ciphertext (bytes):
                The full ciphertext from the encryption operation.

            raw_ciphertext (bytes):
                The ciphertext excluding any nonce, tag, or other state.
        """
        self.alg = alg
        self.ciphertext = ciphertext
        self.raw_ciphertext = raw_ciphertext


class WrappedKeyData:
    """The result of a key wrapping operation.

    This stores the algorithm and EDEK (Encrypted Data Encryption Key)
    resulting from a key wrapping algorithm.

    Version Added:
        1.0
    """

    ######################
    # Instance variables #
    ######################

    #: The algorithm used for key wrapping.
    alg: str

    #: The full EDEK ciphertext.
    edek: bytes

    def __init__(
        self,
        alg: str,
        edek: bytes,
    ) -> None:
        """Initialize the key wrapping result.

        Args:
            alg (str):
                The algorithm used for key wrapping.

            edek (bytes):
                The full ciphertext from the key wrapping operation.
        """
        self.alg = alg
        self.edek = edek


class BaseKey(InvalidatableMixin):
    """Base class for a cryptographic key.

    Keys are the primary interface for performing cryptographic operations
    in Cryptozoology. They can be used to perform certain operations,
    depending on the key type.

    Each key may have an optional KID (Key ID), which is an identifier that
    can be used along with key storage to look up or store a key.

    A key is invalidated on deletion and can be manually invalidated. This
    will make a best-attempt at clearing out cryptographic state from memory
    (although this is inherently limited to what is possible in Python).

    Version Added:
        1.0
    """

    ######################
    # Class variables     #
    ######################

    #: The short ID used to identify this key type in storage metadata.
    #:
    #: See :py:mod:`cryptozoology.keys.registry`.
    key_type_id: ClassVar[str]

    ######################
    # Instance variables #
    ######################

    #: The optional KID (Key ID) for this key.
    key_id: str | None

    #: The cached SHA-256 fingerprint of the key.
    _fingerprint_sha256: bytes | None

    @classmethod
    def supports_encryption_alg(
        cls,
        alg: str,
    ) -> bool:
        """Return whether this class supports an encryption algorithm.

        Args:
            alg (str):
                The algorithm to check.

        Returns:
            bool:
            ``True`` if the algorithm is supported. ``False`` if not.
        """
        return False

    @classmethod
    def supports_keywrap_alg(
        cls,
        alg: str,
    ) -> bool:
        """Return whether this class supports a keywrap algorithm.

        Args:
            alg (str):
                The algorithm to check.

        Returns:
            bool:
            ``True`` if the algorithm is supported. ``False`` if not.
        """
        return False

    @classmethod
    def from_bytes(
        cls,
        key_bytes: BytesLike,
    ) -> Self:
        """Return a new key from raw bytes.

        Args:
            key_bytes (bytes or bytearray):
                The key bytes to build the key from.

        Returns:
            BaseKey:
            The new key instance.
        """
        raise NotImplementedError

    def __init__(
        self,
        *,
        key_id: (str | None) = None
    ) -> None:
        """Initialize the key.

        Args:
            key_id (str, optional):
                An optional KID (Key ID) for this key.
        """
        self.key_id = key_id
        self._fingerprint_sha256 = None

    @property
    def fingerprint_sha256(self) -> bytes:
        """The SHA-256 fingerprint for this key in binary digest form.

        This is cached for repeated calls.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The key is no longer valid.
        """
        if not (fingerprint := self._fingerprint_sha256):
            fingerprint = (
                hashlib.sha256(self.get_fingerprint_bytes())
                .digest()
            )
            self._fingerprint_sha256 = fingerprint

        return fingerprint

    def is_valid(self) -> bool:
        """Return whether this key is still valid.

        This must be implemented by subclasses.

        Returns:
            bool:
            ``True`` if the key is valid. ``False`` if it is invalid.
        """
        raise NotImplementedError

    def get_fingerprint_bytes(self) -> BytesLike:
        """Return the bytes of the key used to generate a fingerprint.

        This must be implemented by subclasses.

        Returns:
            bytes or bytearray or memoryview:
            The bytes used to generate the fingerprint.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The key is no longer valid.
        """
        raise NotImplementedError

    def to_bytes(self) -> SensitiveBytes:
        """Return the bytes representation of the key.

        Returns:
            cryptozoology.utils.encoding.SensitiveBytes:
            The bytes of the key.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The key is no longer valid.
        """
        raise NotImplementedError

    def encrypt(
        self,
        plaintext: BytesLike,
        *,
        alg: (str | None) = None,
    ) -> EncryptedData:
        """Encrypt a plaintext with this key.

        Args:
            plaintext (bytes or bytearray or memoryview):
                The plaintext content to encrypt.

            alg (str, optional):
                The supported algorithm used for encryption.

                If not provided, the key will choose a default algorithm.

        Returns:
            EncryptedData:
            The encrypted data information.

        Raises:
            cryptozoology.errors.UnsupportedAlgorithmError:
                The provided algorithm was not supported by this key.
        """
        raise NotImplementedError

    def decrypt(
        self,
        ciphertext: BytesLike,
        *,
        alg: str,
    ) -> SensitiveBytes:
        """Decrypt a ciphertext with this key.

        Args:
            ciphertext (bytes or bytearray or memoryview):
                The ciphertext to decrypt.

            alg (str):
                The algorithm that was used for encryption.

        Returns:
            cryptozoology.utils.encoding.SensitiveBytes:
            The decrypted plaintext.

        Raises:
            cryptozoology.errors.UnsupportedAlgorithmError:
                The provided algorithm was not supported by this key.
        """
        raise NotImplementedError

    def wrap_key(
        self,
        key: BaseKey,
        *,
        alg: (str | None) = None,
    ) -> WrappedKeyData:
        """Wrap another key with this key.

        Args:
            key (BaseKey):
                The other key to wrap.

            alg (str, optional):
                The supported algorithm used for key wrapping.

                If not provided, the subclass may choose a default.

        Returns:
            WrappedKeyData:
            The wrapped key information.

        Raises:
            cryptozoology.errors.UnsupportedAlgorithmError:
                The provided algorithm was not supported by this key.
        """
        raise NotImplementedError

    def unwrap_key(
        self,
        wrapped_key_bytes: bytes,
        *,
        alg: str,
        key_cls: type[TKey],
        key_cls_kwargs: (KwargsDict | None) = None,
    ) -> TKey:
        """Unwrap an encrypted key using this key.

        Args:
            wrapped_key_bytes (bytes):
                The encrypted key bytes to unwrap.

            alg (str):
                The algorithm used to wrap the key.

            key_cls (type):
                The key class type to construct.

            key_cls_kwargs (dict, optional):
                Additional keyword arguments for the key instance.

        Returns:
            BaseKey:
            The resulting key.

            This will be of the provided ``key_cls`` type.

        Raises:
            cryptozoology.errors.KeyUnwrapError:
                There was an error unwrapping the key.

            cryptozoology.errors.UnsupportedAlgorithmError:
                The provided algorithm was not supported by this key.
        """
        raise NotImplementedError

    def invalidate(self) -> None:
        """Invalidate the key.

        Subclasses must override and call the parent method.
        """
        self._fingerprint_sha256 = None


class BaseBytesKey(BaseKey):
    """Base class for a key defined as a series of bytes.

    Bytes-based keys store their key data as a :py:class:`bytearray`, which
    will be cleared from memory when invalidated.

    The raw bytes of the key can be returned for usage.

    Version Added:
        1.0
    """

    ######################
    # Instance variables #
    ######################

    #: The array of bytes comprising the key.
    _key_bytes: SensitiveBytes

    @property
    def key_size(self) -> int:
        """The size of the key in bytes."""
        return len(self._key_bytes) * 8

    def __init__(
        self,
        key_bytes: BytesLike,
        *,
        key_id: (str | None) = None
    ) -> None:
        """Initialize the key.

        Args:
            key_bytes (bytes or bytearray or memoryview):
                The key bytes.

            key_id (str, optional):
                The KID (Key ID) for the key.
        """
        super().__init__(key_id=key_id)

        self._key_bytes = SensitiveBytes(key_bytes)

    def is_valid(self) -> bool:
        """Return whether this key is still valid.

        Returns:
            bool:
            ``True`` if the key is valid. ``False`` if it is invalid.
        """
        return bool(self._key_bytes)

    def to_bytes(self) -> SensitiveBytes:
        """Return the bytes of the key.

        Returns:
            cryptozoology.utils.encoding.SensitiveBytes:
            The bytes of the key.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The key is no longer valid.
        """
        self.assert_valid()

        return self._key_bytes

    def get_fingerprint_bytes(self) -> BytesLike:
        """Return the bytes of the key used to generate a fingerprint.

        Returns:
            bytearray:
            The bytes used to generate the fingerprint.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The key is no longer valid.
        """
        return self.to_bytes()

    def invalidate(self) -> None:
        """Invalidate the key."""
        super().invalidate()

        self._key_bytes.invalidate()


class BasePKIPublicKey(Generic[_PKIPrivateKeyType,
                               _ImplPublicKeyType],
                       BaseKey):
    """Base class for a public key used in Public Key Infrastructure.

    Subclasses must type this to indicate the associated private key type
    and the underlying Python Cryptography key type(s).

    Version Added:
        1.0
    """

    ######################
    # Instance variables #
    ######################

    #: The Python Cryptography public key backing this object.
    impl_public_key: _ImplPublicKeyType | None

    def __init__(
        self,
        impl_public_key: _ImplPublicKeyType,
        *,
        key_id: (str | None) = None,
    ) -> None:
        """Initialize the public key.

        Args:
            impl_public_key (type):
                The Python Cryptography public key backing this object.

            key_id (str, optional):
                An optional KID (Key ID) for this key.
        """
        super().__init__(key_id=key_id)

        self.impl_public_key = impl_public_key

    def is_valid(self) -> bool:
        """Return whether this key is still valid.

        Returns:
            bool:
            ``True`` if the key is valid. ``False`` if it is invalid.
        """
        return self.impl_public_key is not None

    def get_fingerprint_bytes(self) -> BytesLike:
        """Return the bytes of the key used to generate a fingerprint.

        This will be generated based off the public key's bytes.

        Returns:
            bytes:
            The bytes used to generate the fingerprint.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The key is no longer valid.
        """
        return self.to_bytes()

    def to_bytes(self) -> SensitiveBytes:
        """Return the bytes representation of the key.

        Returns:
            bytearray:
            The bytes of the key.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The key is no longer valid.
        """
        self.assert_valid()

        impl_public_key = self.impl_public_key
        assert impl_public_key is not None

        return SensitiveBytes(impl_public_key.public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo,
        ))

    def invalidate(self) -> None:
        """Invalidate the key."""
        super().invalidate()

        self.impl_public_key = None


class BasePKIPrivateKey(Generic[_PKIPublicKeyType,
                                _ImplPrivateKeyType],
                        BaseKey):
    """Base class for a private key used in Public Key Infrastructure.

    Subclasses must type this to indicate the associated public key type
    and the underlying Python Cryptography key type(s).

    Version Added:
        1.0
    """

    #: The PKI class used for the accompanying public key type.
    public_key_cls: type[_PKIPublicKeyType]

    ######################
    # Instance variables #
    ######################

    #: The Python Cryptography private key backing this object.
    impl_private_key: _ImplPrivateKeyType | None

    #: The cached public key for this private key.
    _public_key: _PKIPublicKeyType | None

    def __init__(
        self,
        impl_private_key: _ImplPrivateKeyType,
        *,
        key_id: (str | None) = None,
    ) -> None:
        """Initialize the private key.

        Args:
            impl_private_key (type):
                The Python Cryptography private key backing this object.

            key_id (str, optional):
                An optional KID (Key ID) for this key.
        """
        super().__init__(key_id=key_id)

        self.impl_private_key = impl_private_key
        self._public_key = None

    def is_valid(self) -> bool:
        """Return whether this key is still valid.

        Returns:
            bool:
            ``True`` if the key is valid. ``False`` if it is invalid.
        """
        return self.impl_private_key is not None

    def get_public_key(self) -> _PKIPublicKeyType:
        """Return the public key for this private key.

        This is cached for repeated calls.

        Returns:
            BasePKIPublicKey:
            The private key's associated public key.
        """
        self.assert_valid()

        public_key = self._public_key

        if public_key is None:
            impl_private_key = self.impl_private_key
            assert impl_private_key is not None

            public_key = self.public_key_cls(
                impl_private_key.public_key(),
                key_id=self.key_id,
            )
            self._public_key = public_key

        return public_key

    def get_fingerprint_bytes(self) -> BytesLike:
        """Return the bytes of the key used to generate a fingerprint.

        This will be generated based off the public key's bytes.

        Returns:
            bytes or bytearray or memoryview:
            The bytes used to generate the fingerprint.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The key is no longer valid.
        """
        return self.get_public_key().get_fingerprint_bytes()

    def to_bytes(
        self,
        *,
        password: (bytes | None) = None,
    ) -> SensitiveBytes:
        """Return the bytes representation of the key.

        Args:
            password (bytes, optional):
                An optional password to use to protect the private key.

        Returns:
            cryptozoology.utils.encoding.SensitiveBytes:
            The bytes of the key.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The key is no longer valid.
        """
        self.assert_valid()

        impl_private_key = self.impl_private_key
        assert impl_private_key is not None

        encryption_algorithm: KeySerializationEncryption

        if password:
            encryption_algorithm = BestAvailableEncryption(password=password)
        else:
            encryption_algorithm = NoEncryption()

        return SensitiveBytes(impl_private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        ))

    def exchange(
        self,
        public_key: _PKIPublicKeyType,
    ) -> bytearray:
        """Perform a key exchange with another public key.

        Args:
            public_key (BasePKIPublicKey):
                The other public key to exchange with.

        Returns:
            bytearray:
            The resulting shared key.
        """
        raise NotImplementedError

    def invalidate(self) -> None:
        """Invalidate the key."""
        super().invalidate()

        if (public_key := self._public_key) is not None:
            public_key.invalidate()
            self._public_key = None

        self.impl_private_key = None
