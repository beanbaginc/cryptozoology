"""AES encryption keys.

Version Added:
    1.0
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap,
    aes_key_wrap_with_padding,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptozoology.errors import (
    DecryptionError,
    KeyDerivationError,
    KeyUnwrapError,
    UnsupportedAlgorithmError,
)
from cryptozoology.keys.base import (
    BaseBytesKey,
    BaseKey,
    BasePKIPrivateKey,
    BasePKIPublicKey,
    EncryptedData,
    TKey,
    WrappedKeyData,
)
from cryptozoology.utils.invalidation import SensitiveBytes
from cryptozoology.utils.random import AES_NONCE_SIZE, generate_nonce

try:
    # Not all cryptography versions/OpenSSL builds provide AES-GCM-SIV.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
except ImportError:
    AESGCMSIV = None

try:
    # cryptography >= 49.0.0
    from cryptography.hazmat.decrepit.ciphers.modes import CFB8
except ImportError:
    # cryptography < 49.0.0
    from cryptography.hazmat.primitives.ciphers.modes import CFB8

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import (ClassVar, Final, NotRequired, Protocol,
                        Self, TypeAlias, TypedDict, Unpack)

    from cryptography.utils import Buffer
    from typelets.funcs import KwargsDict

    from cryptozoology.keys.base import EncryptedDataKwargs
    from cryptozoology.utils.encoding import BytesLike
    from cryptozoology.utils.random import Nonce, Salt

    # cryptography doesn't have a base class for the AEAD mode classes, so
    # we'll manage it as a protocol.
    class _AEADMode(Protocol):
        def __init__(
            self,
            key: Buffer,
        ) -> None:
            ...

        def decrypt(
            self,
            nonce: Buffer,
            data: Buffer,
            associated_data: Buffer | None,
        ) -> bytes:
            ...

        def encrypt(
            self,
            nonce: Buffer,
            data: Buffer,
            associated_data: Buffer | None,
        ) -> bytes:
            ...

    # cryptography does not have a base class for Cipher modes that take
    # in an IV, nor does it have a type that encompasses all the ones that
    # do. We can't use a Protocol for this, because Cipher needs to take a
    # Mode generic, and type checkers will complain if we pass in a Protocol
    # (and type narrowing doesn't do the job, as it produces
    # "subclass of _CipherMode and Mode", at best). So we're best off just
    # aliasing supported types here.
    _CipherMode: TypeAlias = CFB8

    class _AESEncryptionModeInfo(TypedDict):
        nonce_size: int
        tag_size: int
        aead_cls: NotRequired[type[_AEADMode]]
        cipher_mode_cls: NotRequired[type[_CipherMode]]
        supports_aad: NotRequired[bool]

    class _AESKeyWrapModeInfo(TypedDict):
        wrap_func: Callable[[bytes, bytes], bytes]
        unwrap_func: Callable[[bytes, bytes], bytes]


#: A set of all supported AES key sizes in bits.
#:
#: Version Added:
#:     1.0
_AES_KEY_SIZES_BITS = {
    128,
    192,
    256,
}


#: A set of all supported AES key sizes in bytes.
#:
#: Version Added:
#:     1.0
_AES_KEY_SIZES_BYTES = {
    key_size // 8
    for key_size in _AES_KEY_SIZES_BITS
}


#: The size of a block of AES-encrypted data in bytes.
#:
#: Version Added:
#:     1.0
AES_BLOCK_SIZE_BYTES: Final[int] = 16


#: Base information on the AES encryption modes supported.
#:
#: This is careful to support only the algorithms that the installed version
#: of the Python cryptography package and OpenSSL support.
#:
#: GCM and GCM-SIV are AEAD modes that use a 96-bit nonce.
#:
#: CFB8 is a block cipher mode that requires a full-block (128-bit) IV.
#:
#: Version Added:
#:     1.0
_AES_ENCRYPTION_MODES: dict[str, _AESEncryptionModeInfo] = {
    'CFB8': {
        'cipher_mode_cls': CFB8,
        'nonce_size': AES_BLOCK_SIZE_BYTES,
        'tag_size': 0,
    },
    'GCM': {
        'aead_cls': AESGCM,
        'nonce_size': AES_NONCE_SIZE,
        'supports_aad': True,
        'tag_size': AES_BLOCK_SIZE_BYTES,
    },
}

if AESGCMSIV is not None:
    _AES_ENCRYPTION_MODES['GCM-SIV'] = {
        'aead_cls': AESGCMSIV,
        'nonce_size': AES_NONCE_SIZE,
        'supports_aad': True,
        'tag_size': AES_BLOCK_SIZE_BYTES,
    }


#: Base information on the AES keywrap modes supported.
#:
#: Version Added:
#:     1.0
_AES_KEYWRAP_MODES: dict[str, _AESKeyWrapModeInfo] = {
    'KW': {
        'wrap_func': aes_key_wrap,
        'unwrap_func': aes_key_unwrap,
    },
    'KWP': {
        'wrap_func': aes_key_wrap_with_padding,
        'unwrap_func': aes_key_unwrap_with_padding,
    },
}


#: All supported AES encryption algorithms.
#:
#: Version Added:
#:     1.0
_AES_ENCRYPTION_ALGS = frozenset(
    f'AES-{bits}-{mode}'
    for bits in _AES_KEY_SIZES_BITS
    for mode in _AES_ENCRYPTION_MODES.keys()
)


#: All supported AES key wrapping algorithms.
#:
#: Version Added:
#:     1.0
_AES_KEYWRAP_ALGS = frozenset(
    f'AES-{bits}-{mode}'
    for bits in _AES_KEY_SIZES_BITS
    for mode in _AES_KEYWRAP_MODES.keys()
)


class AESEncryptedData(EncryptedData):
    """AES-encrypted data.

    Version Added:
        1.0
    """

    ######################
    # Instance variables #
    ######################

    #: The recorded nonce.
    nonce: Nonce

    #: The recorded tag.
    tag: bytes

    def __init__(
        self,
        *,
        nonce: Nonce,
        tag: bytes,
        **kwargs: Unpack[EncryptedDataKwargs],
    ) -> None:
        """Initialize the encrypted data.

        Args:
            nonce (cryptozoology.utils.random.Nonce):
                The nonce used for encryption.

            tag (bytes):
                The recorded tag.

            **kwargs (dict):
                Additional keyword arguments for the parent constructor.
        """
        super().__init__(**kwargs)

        self.nonce = nonce
        self.tag = tag


class AESKey(BaseBytesKey):
    """A representation of an AES key.

    This stores the raw key contents and provides operations for encrypting
    or decrypting using this key.

    Version Added:
        1.0
    """

    #: The short ID used to identify this key type in storage metadata.
    #:
    #: Version Added:
    #:     1.0
    key_type_id: ClassVar[str] = 'aes'

    ######################
    # Instance variables #
    ######################

    key_id: str | None

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
        return alg in _AES_ENCRYPTION_ALGS

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
        return alg in _AES_KEYWRAP_ALGS

    @classmethod
    def from_bytes(
        cls,
        key_bytes: BytesLike,
        *,
        key_id: (str | None) = None,
    ) -> Self:
        """Return a new AES key from raw bytes.

        Args:
            key_bytes (bytes or bytearray):
                The key bytes to build the key from.

            key_id (str, optional):
                The KID (Key ID) of the key.

        Returns:
            AESKey:
            The new key instance.
        """
        key_len = len(key_bytes)

        if key_len not in _AES_KEY_SIZES_BYTES:
            raise ValueError(f'Unsupported AES key bytes length: {key_len}')

        return cls(key_bytes=key_bytes,
                   key_id=key_id)

    @classmethod
    def generate(
        cls,
        *,
        key_id: (str | None) = None,
        key_size: int = 256,
    ) -> Self:
        """Generate a new key.

        Args:
            key_id (str, optional):
                The KID (Key ID) of the key.

            key_size (int, optional):
                The size of the key in bits.

                This defaults to a 256-bit key.

        Returns:
            AESKey:
            The new key instance.
        """
        if key_size not in _AES_KEY_SIZES_BITS:
            raise ValueError(f'Unsupported AES key size: {key_size}')

        key_bytes = os.urandom(key_size // 8)

        return cls(key_bytes=key_bytes,
                   key_id=key_id)

    @classmethod
    def derive_from_bytes(
        cls,
        base_key: BaseKey | BytesLike,
        *,
        hkdf_info: bytes,
        salt: Salt,
        key_id: (str | None) = None,
        key_size: int = 256,
    ) -> Self:
        """Derive an AES key from the bytes-based key.

        Args:
            base_key (bytes or cryptozoology.keys.base.BaseKey):
                The key to derive from.

            hkdf_info (bytes):
                The HKDF info to use for key derivation.

            salt (cryptozoology.utils.random.Salt):
                The salt to use during key derivation.

            key_id (str, optional):
                The KID (Key ID) for the new key.

            key_size (int, optional):
                The size of the derived key.

                If not provided, the largest key size (256 bits) will be
                used.

        Returns:
            AESKey:
            The new key instance.

        Raises:
            cryptozoology.errors.KeyDerivationError:
                There was an error deriving a key.
        """
        if key_size not in _AES_KEY_SIZES_BITS:
            raise ValueError(f'Unsupported AES key size: {key_size}')

        if isinstance(base_key, BaseKey):
            base_key = base_key.to_bytes()

        try:
            return cls(
                key_bytes=(
                    HKDF(algorithm=hashes.SHA256(),
                         length=key_size // 8,
                         salt=salt,
                         info=hkdf_info)
                    .derive(cast(bytes, base_key))
                ),
                key_id=key_id,
            )
        except Exception as e:
            raise KeyDerivationError(
                f'Failed to perform HKDF key derivation: {e}'
            ) from e

    @classmethod
    def derive_from_key_exchange(
        cls,
        private_key: BasePKIPrivateKey,
        public_key: BasePKIPublicKey,
        *,
        hkdf_info: bytes,
        salt: Salt,
        key_id: (str | None) = None,
        key_size: int = 256,
    ) -> Self:
        """Derive an AES key from a key exchange.

        Args:
            private_key (cryptozoology.keys.base.BasePKIPrivateKey):
                The private key used for the key exchange.

            public_key (cryptozoology.keys.base.BasePKIPublicKey):
                The public key used for the key exchange.

            hkdf_info (bytes):
                The HKDF info to use for key derivation.

            salt (cryptozoology.utils.random.Salt):
                The salt to use during key derivation.

            key_id (str, optional):
                The KID (Key ID) for the new key.

            key_size (int, optional):
                The size of the derived key.

                If not provided, the largest key size (256 bits) will be
                used.

        Returns:
            AESKey:
            The new key instance.

        Raises:
            cryptozoology.errors.KeyDerivationError:
                There was an error deriving a key.
        """
        try:
            shared_key = private_key.exchange(public_key)
        except Exception as e:
            raise KeyDerivationError(
                f'Failed to perform ECDH key exchange: {e}'
            )

        return cls.derive_from_bytes(
            base_key=shared_key,
            hkdf_info=hkdf_info,
            key_id=key_id,
            key_size=key_size,
            salt=salt,
        )

    def encrypt(
        self,
        plaintext: BytesLike,
        *,
        aad: (bytes | None) = None,
        alg: (str | None) = None,
        nonce: (Nonce | None) = None,
    ) -> AESEncryptedData:
        """Encrypt a plaintext with this key.

        Args:
            plaintext (bytes):
                The plaintext content to encrypt.

            aad (bytes, optional):
                The Additional Authenticated Data to use during encryption.

            alg (str, optional):
                The supported AES algorithm used for encryption.

            nonce (cryptozoology.utils.random.Nonce, optional):
                An explicit (randomly-generated) nonce used for the encryption.

                If not provided, a new one will randomly be generated.

                Callers should only provide a value here if they have taken
                care to securely, randomly generate a nonce. In most cases,
                they should let this function handle it.

        Returns:
            AESEncryptedData:
            The encrypted data information.

        Raises:
            cryptozoology.errors.UnsupportedAlgorithmError:
                The provided algorithm was unsupported.
        """
        self.assert_valid()

        if not alg:
            alg = f'AES-{self.key_size}-GCM'

        mode, mode_info = self._get_enc_mode_info_for_alg(alg)

        if aad and not mode_info.get('supports_aad'):
            raise ValueError(
                f'aad is not supported for AES mode {mode}.'
            )

        # If a nonce hasn't been provided, generate a new one of the correct
        # size for the mode.
        if nonce is None:
            nonce = generate_nonce(mode_info['nonce_size'])

        if aead_cls := mode_info.get('aead_cls'):
            ciphertext = (
                aead_cls(self._key_bytes)
                .encrypt(nonce, plaintext, aad)
            )
        elif cipher_mode_cls := mode_info.get('cipher_mode_cls'):
            encryptor = (
                Cipher(algorithms.AES(cast(bytes, self._key_bytes)),
                       cipher_mode_cls(nonce),
                       default_backend())
                .encryptor()
            )

            ciphertext = (
                encryptor.update(cast(bytes, plaintext)) +
                encryptor.finalize()
            )
        else:
            # We should never be here unless we did something really bad
            # with our implementation.
            raise AssertionError('Not reached.')

        if tag_size := mode_info['tag_size']:
            raw_ciphertext = ciphertext[:-tag_size]
            tag = ciphertext[-tag_size:]
        else:
            raw_ciphertext = ciphertext
            tag = b''

        return AESEncryptedData(
            alg=alg,
            ciphertext=nonce + ciphertext,
            raw_ciphertext=raw_ciphertext,
            nonce=nonce,
            tag=tag,
        )

    def decrypt(
        self,
        ciphertext: BytesLike,
        *,
        aad: (bytes | None) = None,
        alg: str,
    ) -> SensitiveBytes:
        """Decrypt a ciphertext with this key.

        Args:
            ciphertext (bytes):
                The ciphertext to decrypt.

            aad (bytes, optional):
                The AAD that was used during encryption.

            alg (str):
                The supported algorithm that was used for encryption.

        Returns:
            cryptozoology.utils.encoding.SensitiveBytes:
            The decrypted plaintext.

        Raises:
            cryptozoology.errors.DecryptionError:
                The ciphertext could not be decrypted.

            cryptozoology.errors.UnsupportedAlgorithmError:
                The provided algorithm was unsupported.
        """
        self.assert_valid()

        mode, mode_info = self._get_enc_mode_info_for_alg(alg)

        if aad and not mode_info.get('supports_aad'):
            raise ValueError(
                f'aad is not supported for AES mode {mode}.'
            )

        nonce_size = mode_info['nonce_size']

        try:
            with memoryview(ciphertext) as memview:
                nonce = cast(bytes, memview[:nonce_size])
                raw_ciphertext = cast(bytes, memview[nonce_size:])

                if aead_cls := mode_info.get('aead_cls'):
                    return SensitiveBytes(
                        aead_cls(self._key_bytes)
                        .decrypt(nonce, raw_ciphertext, aad)
                    )
                elif cipher_mode_cls := mode_info.get('cipher_mode_cls'):
                    decryptor = (
                        Cipher(algorithms.AES(cast(bytes, self._key_bytes)),
                               cipher_mode_cls(nonce),
                               default_backend())
                        .decryptor()
                    )

                    return SensitiveBytes(
                        decryptor.update(raw_ciphertext) +
                        decryptor.finalize()
                    )
                else:
                    # We should never be here unless we did something
                    # really bad with our implementation.
                    raise AssertionError('Not reached.')
        except (ValueError, InvalidTag):
            # This error will be raised for missing/bad AAD, for any
            # ciphertext that can't be decrypted, or for truncated ciphertext.
            # The error will be kept to just a class.
            raise DecryptionError()

    def wrap_key(
        self,
        key: BaseKey,
        *,
        alg: (str | None) = None,
    ) -> WrappedKeyData:
        """Wrap another key with this key.

        Args:
            key (cryptozoology.keys.base.BaseKey):
                The other key to wrap.

            alg (str, optional):
                The supported algorithm used for key wrapping.

                If not provided, ``AES-256-KW`` (or an equivalent for this
                key's size) is used.

        Returns:
            cryptozoology.keys.base.WrappedKeyData:
            The wrapped key information.

        Raises:
            cryptozoology.errors.UnsupportedAlgorithmError:
                The provided algorithm was unsupported.
        """
        self.assert_valid()

        if not alg:
            alg = f'AES-{self.key_size}-KW'

        mode_info = self._get_keywrap_mode_info_for_alg(alg)
        edek = mode_info['wrap_func'](cast(bytes, self.to_bytes()),
                                      cast(bytes, key.to_bytes()))

        return WrappedKeyData(
            alg=alg,
            edek=edek,
        )

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
                Additional keyword arguments for the resulting unwrapped
                key class.

        Returns:
            cryptozoology.keys.base.BaseKey:
            The resulting key.

            This will be of the provided ``key_cls`` type.

        Raises:
            cryptozoology.errors.KeyUnwrapError:
                There was an error unwrapping the key.

            cryptozoology.errors.UnsupportedAlgorithmError:
                The provided algorithm was unsupported.
        """
        self.assert_valid()

        mode_info = self._get_keywrap_mode_info_for_alg(alg)

        try:
            key_bytes = mode_info['unwrap_func'](cast(bytes, self.to_bytes()),
                                                 wrapped_key_bytes)
        except InvalidUnwrap:
            raise KeyUnwrapError()

        return key_cls.from_bytes(
            key_bytes=key_bytes,
            **(key_cls_kwargs or {}),
        )

    def _get_enc_mode_info_for_alg(
        self,
        alg: str,
    ) -> tuple[str, _AESEncryptionModeInfo]:
        """Return the mode information for an encryption algorithm.

        The encryption algorithm provided must be compatible with this key's
        size, or the algorithm will be considered unsupported.

        The resulting mode information can be used for encryption and
        decryption algorithms.

        Args:
            alg (str):
                The algorithm to return mode information for.

        Returns:
            tuple:
            A 2-tuple of:

            Tuple:
                0 (str):
                    The mode name.

                1 (_AESEncryptionModeInfo):
                    The resulting mode information.

        Raises:
            cryptozoology.errors.UnsupportedAlgorithmError:
                The algorithm is not supported for this key or environment.
        """
        mode = self._get_mode_string_for_alg(alg)

        # Validate the mode and pull information from it.
        try:
            return mode, _AES_ENCRYPTION_MODES[mode]
        except KeyError:
            raise UnsupportedAlgorithmError(alg=alg)

    def _get_keywrap_mode_info_for_alg(
        self,
        alg: str,
    ) -> _AESKeyWrapModeInfo:
        """Return the mode information for a keywrap algorithm.

        The keywrap algorithm provided must be compatible with this key's
        size, or the algorithm will be considered unsupported.

        The resulting mode information can be used for key wrapping and
        unwrapping algorithms.

        Args:
            alg (str):
                The algorithm to return mode information for.

        Returns:
            _AESKeyWrapModeInfo:
            The resulting mode information.

        Raises:
            cryptozoology.errors.UnsupportedAlgorithmError:
                The algorithm is not supported for this key or environment.
        """
        mode = self._get_mode_string_for_alg(alg)

        # Validate the mode and pull information from it.
        try:
            return _AES_KEYWRAP_MODES[mode]
        except KeyError:
            raise UnsupportedAlgorithmError(alg=alg)

    def _get_mode_string_for_alg(
        self,
        alg: str,
    ) -> str:
        """Return the mode name parsed from an algorithm.

        The algorithm provided must be compatible with this key's size, or the
        algorithm will be considered unsupported.

        Args:
            alg (str):
                The algorithm to return the mode name for.

        Returns:
            str:
            The resulting mode name.

        Raises:
            cryptozoology.errors.UnsupportedAlgorithmError:
                The algorithm is not supported for this key or environment.
        """
        alg_prefix = f'AES-{self.key_size}-'

        # Check the algorithm type at the beginning of the string, extracting
        # the mode if found.
        if alg and alg.startswith(alg_prefix):
            return alg[len(alg_prefix):]
        else:
            raise UnsupportedAlgorithmError(alg=alg)
