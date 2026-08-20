"""Secrets encoding and decoding.

Version Added:
    1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import quote, unquote

from cryptozoology.errors import CryptozoologyError, SecretDecodeError
from cryptozoology.keys.aes import AESKey
from cryptozoology.keys.registry import key_type_registry
from cryptozoology.utils.encoding import b64u_decode, b64u_encode
from cryptozoology.utils.invalidation import (InvalidatableMixin,
                                              SensitiveBytes)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping
    from typing import Final, Self, TypeAlias

    from cryptozoology.utils.encoding import BytesLike
    from cryptozoology.keys.base import BaseKey

    #: A callable used to look up a Key Encryption Key by its KID.
    #:
    #: Version Added:
    #:     1.0
    KekResolver: TypeAlias = Callable[[str], BaseKey | None]


#: A reserved list of field names to include in envelopes.
#:
#: These fields cannot be present in a secret's list of custom envelope
#: fields.
#:
#: Version Added:
#:     1.0
_RESERVED_FIELDS = frozenset({
    'alg',
    'edek',
    'kid',
    'wrap',
})


class Secret(InvalidatableMixin):
    """An encrypted secret value, encoded along with an envelope.

    A "Secret" is a combination of a ciphertext and an envelope describing
    out to decrypt it.

    The ciphertext is encrypted using a one-time-use Data Encryption Key
    (or DEK), which is then used for decryption. That key is key-wrapped
    using a caller-supplied Key Encryption Key (KEK) and stored in the
    envelope as an Encrypted Data Encryption Key (EDEK).

    The KEK is identified using a Key ID (KID) in the envelope. To unwrap
    the DEK, the caller must have access to that KEK. The caller is
    responsible for providing a function that will return a KEK for a given
    KID.

    The DEK itself is randomly-generated, rather than being derived from
    the KEK. If the parent KEK ever needs to be rotated, the DEK would just
    need to be re-wrapped, leaving the ciphertext the same. This avoids the
    issue of a rotated KEK forcing a new key to be derived, which would force
    new ciphertext.

    Secrets are encoded in the following format::

        encv=2;alg=AES-256-GCM;kid=...;wrap=AES-256-KW;edek=...!<ciphertext>

    Additional custom fields can be provided by the caller, if needed.

    Version Added:
        1.0
    """

    #: The latest envelope version produced by :py:meth:`encode`.
    LATEST_VERSION: Final[int] = 2

    #: The envelope versions that :py:meth:`from_encoded` can parse.
    SUPPORTED_VERSIONS: Final[frozenset[int]] = frozenset({
        2,
    })

    ######################
    # Instance variables #
    ######################

    #: The key used to encrypt/decrypt the payload.
    dek: BaseKey

    #: Any additional fields to include in the envelope.
    extra_fields: dict[str, str]

    #: The plaintext payload.
    plaintext: SensitiveBytes

    @classmethod
    def from_encoded(
        cls,
        encoded: str,
        *,
        kek_resolver: KekResolver,
        version_field: str = 'encv',
    ) -> Self:
        """Return a new Secret decoded from an envelope.

        Version Added:
            1.0

        Args:
            encoded (str):
                The encoded envelope string, as produced by
                :py:meth:`encode`.

            kek_resolver (callable):
                A callable that takes the envelope's KID (Key ID) and
                returns a new instance of the Key Encryption Key used to
                unwrap the DEK.

                The returned instance will be immediately invalidated after
                use.

            version_field (str, optional):
                The name of the envelope's leading version field.

                This can be changed to help differentiate between different
                kinds of stored secrets, if needed.

        Returns:
            Secret:
            The decoded secret.

        Raises:
            cryptozoology.errors.SecretDecodeError:
                The envelope could not be parsed, unwrapped, or
                decrypted, or a key could not be found.
        """
        if not encoded.startswith(version_field):
            # This does not contain the expected leader version field.
            # Raise a decode error.
            raise SecretDecodeError('Envelope version field is missing.')

        i = encoded.find('!')

        if i == -1:
            # This was not an encoded value. Raise a decode error.
            raise SecretDecodeError('Invalid envelope format.')

        # Parse the envelope.
        envelope = encoded[:i]
        fields: dict[str, str] = {}

        for field in envelope.split(';'):
            try:
                key, value = field.split('=', 1)
            except ValueError:
                raise SecretDecodeError(f'Envelope field parse error: {field}')

            fields[unquote(key)] = unquote(value)

        try:
            version_str = fields[version_field]
        except KeyError:
            raise SecretDecodeError(
                'Envelope version field is missing.'
            ) from None

        try:
            version = int(version_str)
        except ValueError:
            raise SecretDecodeError(
                f'Invalid envelope version string {version_str!r}.'
            ) from None

        if version not in cls.SUPPORTED_VERSIONS:
            raise SecretDecodeError(
                f'Unsupported envelope version {version!r}.'
            ) from None

        # Pull state out of the envelope for decryption and key unwrapping.
        try:
            edek = fields['edek']
            enc_alg = fields['alg']
            kid = fields['kid']
            wrap_alg = fields['wrap']
        except KeyError as e:
            raise SecretDecodeError(
                f'Missing envelope field "{e}".'
            ) from None

        ignored_fields = _RESERVED_FIELDS | {version_field}

        extra_fields = {
            key: value
            for key, value in fields.items()
            if key not in ignored_fields
        }

        # Check if the encryption algorithm is supported.
        enc_key_cls = key_type_registry.get_for_encryption_alg(enc_alg)

        if enc_key_cls is None:
            raise SecretDecodeError(
                f'Unsupported encryption algorithm {enc_alg!r}.'
            )

        # Resolve the KEK and make sure it supports the provided key wrap
        # algorithm.
        kek = kek_resolver(kid)

        if kek is None:
            raise SecretDecodeError(
                f'Could not locate the key required to decrypt this secret '
                f'(key ID {kid!r}).'
            )

        if not kek.supports_keywrap_alg(wrap_alg):
            raise SecretDecodeError(
                f'Unsupported key wrapping algorithm {wrap_alg!r}.'
            )

        with kek:
            # Unwrap the key.
            try:
                dek = kek.unwrap_key(
                    b64u_decode(edek),
                    alg=wrap_alg,
                    key_cls=enc_key_cls,
                )
            except (CryptozoologyError, ValueError) as e:
                message = str(e)

                if message:
                    raise SecretDecodeError(
                        f'Failed to unwrap encryption key: {message}'
                    ) from None
                else:
                    raise SecretDecodeError(
                        'Failed to unwrap encryption key.'
                    ) from None

        # Pull out and base64-decode the ciphertext.
        try:
            ciphertext = b64u_decode(encoded[i + 1:])
        except ValueError as e:
            raise SecretDecodeError(f'Corrupted ciphertext: {e}')

        try:
            plaintext = dek.decrypt(
                ciphertext,
                aad=envelope.encode('utf-8'),
                alg=enc_alg,
            )
        except (CryptozoologyError, ValueError) as e:
            message = str(e)

            if message:
                raise SecretDecodeError(
                    f'Failed to decrypt payload: {message}'
                ) from None
            else:
                raise SecretDecodeError(
                    'Failed to decrypt payload.'
                ) from None

        return cls(dek=dek,
                   plaintext=plaintext,
                   extra_fields=extra_fields)

    def __init__(
        self,
        *,
        plaintext: BytesLike,
        dek: (BaseKey | None) = None,
        extra_fields: (Mapping[str, str] | None) = None,
    ) -> None:
        """Initialize the secret.

        Version Added:
            1.0

        Args:
            plaintext (bytes or bytearray or memoryview):
                The plaintext payload to encrypt.

            dek (cryptozoology.keys.base.BaseKey, optional):
                The key used to encrypt/decrypt the payload.

                The DEK will be generated automatically if not provided.
                This is the recommended approach in actual use.

                This class will manage the DEK, invalidating it once the
                secret is invalidated.

            extra_fields (dict, optional):
                Any additional fields to include in the envelope.
        """
        self.dek = dek or AESKey.generate(key_size=256)
        self.plaintext = SensitiveBytes(plaintext)
        self.extra_fields = dict(extra_fields or {})

    def encode(
        self,
        *,
        kek: BaseKey,
        enc_alg: (str | None) = None,
        wrap_alg: (str | None) = None,
        version_field: str = 'encv',
    ) -> str:
        """Return this secret encoded as an envelope string.

        Version Added:
            1.0

        Args:
            kek (cryptozoology.keys.base.BaseKey):
                The Key Encryption Key used to wrap :py:attr:`dek`.

                This must have a
                :py:attr:`~cryptozoology.keys.base.BaseKey.key_id` set,
                which will become the envelope's KID.

            enc_alg (str, optional):
                The algorithm used to encrypt :py:attr:`plaintext`.

                If not provided, and :py:attr:`dek` is an
                :py:class:`~cryptozoology.keys.aes.AESKey`, this defaults to
                AES-GCM at the key's size.

            wrap_alg (str, optional):
                The algorithm used to wrap :py:attr:`dek`.

                If not provided, ``kek`` will choose a default.

            version_field (str, optional):
                The name of the envelope's version field.

        Returns:
            str:
            The encoded envelope string.

        Raises:
            ValueError:
                ``enc_alg`` could not be determined, ``kek`` has no
                ``key_id``, or :py:attr:`extra_fields` contains a reserved
                field name.

            cryptozoology.errors.InvalidatedError:
                The secret is no longer valid.
        """
        self.assert_valid()

        if not kek.key_id:
            raise ValueError('kek must have a key_id to encode a Secret.')

        dek = self.dek

        if enc_alg is None:
            if not isinstance(dek, AESKey):
                raise ValueError(
                    'enc_alg must be provided explicitly for this dek type.'
                )

            enc_alg = f'AES-{dek.key_size}-GCM'

        ignored_fields = _RESERVED_FIELDS | {version_field}
        extra_fields = self.extra_fields

        if field_names := (ignored_fields & extra_fields.keys()):
            field_names_str = ', '.join(sorted(field_names))

            raise ValueError(
                f'extra_fields cannot contain reserved field name(s): '
                f'{field_names_str}.'
            )

        # Generate the eDEK for the envelope.
        wrapped = kek.wrap_key(dek,
                               alg=wrap_alg)

        # Now generate the envelope.
        fields = {
            'alg': enc_alg,
            'kid': kek.key_id,
            'wrap': wrapped.alg,
            'edek': b64u_encode(wrapped.edek),
            **extra_fields,
        }

        envelope = ';'.join(
            f'{key}={value}'
            for key, value in self._normalize_fields(fields)
        )
        envelope = f'{version_field}={self.LATEST_VERSION};{envelope}'

        # Encrypt the plaintext for storage.
        enc_data = dek.encrypt(
            self.plaintext,
            alg=enc_alg,
            aad=envelope.encode('utf-8'),
        )

        return f'{envelope}!{b64u_encode(enc_data.ciphertext)}'

    def is_valid(self) -> bool:
        """Return whether the Secret instance is still valid.

        Version Added:
            1.0

        Returns:
            bool:
            ``True`` if the Secret is valid. ``False`` if not.
        """
        return (
            self.dek.is_valid() and
            self.plaintext.is_valid()
        )

    def invalidate(self) -> None:
        """Invalidate the secret.

        This will in turn invalidate the DEK and plaintext.

        Version Added:
            1.0
        """
        self.dek.invalidate()
        self.plaintext.invalidate()
        self.extra_fields = {}

    def _normalize_fields(
        self,
        fields: Mapping[str, str],
    ) -> Iterator[tuple[str, str]]:
        """Validate and return normalized keys/values for fields.

        This will make sure that none of the keys or values are empty,
        yielding escaped versions of each pair for encoding in an envelope.

        Args:
            fields (dict):
                The fields to validate and escape.

        Yields:
            tuple:
            A 2-tuple of:

            Tuple:
                0 (str):
                    The field's escaped key.

                1 (str):
                    The field's escaped value.

        Raises:
            ValueError:
                A key or value is empty.
        """
        for key, value in sorted(fields.items()):
            key = key.strip()
            value = value.strip()

            if not key:
                raise ValueError('Field keys cannot be empty.')

            if not value:
                raise ValueError(
                    f'Field value for key {key!r} cannot be empty.'
                )

            yield (
                quote(key, safe=''),
                quote(value, safe=''),
            )
