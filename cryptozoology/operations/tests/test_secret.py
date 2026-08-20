"""Tests for cryptozoology.secrets.Secret"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from unittest import TestCase, skipUnless

import kgb

from cryptozoology.errors import SecretDecodeError
from cryptozoology.keys.aes import AESKey
from cryptozoology.operations.secrets import Secret
from cryptozoology.utils.random import Nonce, generate_nonce

try:
    # Not all cryptography versions/OpenSSL builds provide AES-GCM-SIV.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    has_gcm_siv = True
except ImportError:
    AESGCMSIV = None
    has_gcm_siv = False

if TYPE_CHECKING:
    from collections.abc import Callable


AES_256_KEK_BYTES = (
    b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc\xe8\xae*'
    b'\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
)

AES_256_DEK_BYTES = (
    b'\xf2d\xf7\x8d\x92\xc2\x88\xdb`\x91\xce\tM\x8dax1\xb6c\xb3\x9d\xccO'
    b'\xeaH\xc4\xa6\xb5\x1e9?\x9c'
)

GCM_NONCE = Nonce(b'\n-*\xa9\xe8nB\r6n\xb4h')
CFB8_NONCE = Nonce(b'1\xc9\xc2\xde\xb1\xa7R\xa5\xbcJAk\xaf\xee\x91\xf3')


class SecretTests(kgb.SpyAgency, TestCase):
    """Unit tests for Secret.

    Version Added:
        1.0
    """

    def test_encode(self) -> None:
        """Testing Secret.encode"""
        self.spy_on(generate_nonce,
                    op=kgb.SpyOpReturn(GCM_NONCE))

        with (AESKey.from_bytes(AES_256_KEK_BYTES,
                                key_id='my-kek-1') as kek,
              AESKey.from_bytes(AES_256_DEK_BYTES) as dek,
              Secret(dek=dek,
                     plaintext=b'test') as secret):

            encoded = secret.encode(kek=kek)

        self.assertEqual(
            encoded,
            'encv=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIqYk4mxvGfg0adJAv9LJsVg')

    @skipUnless(has_gcm_siv,
                'GCM-SIV is not available on this build of cryptography.')
    def test_encode_with_enc_alg(self) -> None:
        """Testing Secret.encode with enc_alg="""
        self.spy_on(generate_nonce,
                    op=kgb.SpyOpReturn(GCM_NONCE))

        with (AESKey.from_bytes(AES_256_KEK_BYTES,
                                key_id='my-kek-1') as kek,
              AESKey.from_bytes(AES_256_DEK_BYTES) as dek,
              Secret(dek=dek,
                     plaintext=b'test') as secret):

            encoded = secret.encode(
                kek=kek,
                enc_alg='AES-256-GCM-SIV',
            )

        self.assertEqual(
            encoded,
            'encv=2;alg=AES-256-GCM-SIV;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRoW3rOl01T6SlRkoNrwj9lp1APprY')

    def test_encode_with_wrap_alg(self) -> None:
        """Testing Secret.encode with wrap_alg="""
        self.spy_on(generate_nonce,
                    op=kgb.SpyOpReturn(GCM_NONCE))

        with (AESKey.from_bytes(AES_256_KEK_BYTES,
                                key_id='my-kek-1') as kek,
              AESKey.from_bytes(AES_256_DEK_BYTES) as dek,
              Secret(dek=dek,
                     plaintext=b'test') as secret):

            encoded = secret.encode(
                kek=kek,
                wrap_alg='AES-256-KWP',
            )

        self.assertEqual(
            encoded,
            'encv=2;alg=AES-256-GCM;edek=TGGevvt_89CHJy9UQptqDiGFyQx'
            'O39j-StF2IcQZxJ9Y2HUTi_k77Q;kid=my-kek-1;wrap=AES-256-KWP!'
            'Ci0qqehuQg02brRowJ2uIoNSNaMSWsdjQ3vrZA7zdvQ')

    def test_encode_with_version_field(self) -> None:
        """Testing Secret.encode with version_field="""
        self.spy_on(generate_nonce,
                    op=kgb.SpyOpReturn(GCM_NONCE))

        with (AESKey.from_bytes(AES_256_KEK_BYTES,
                                key_id='my-kek-1') as kek,
              AESKey.from_bytes(AES_256_DEK_BYTES) as dek,
              Secret(dek=dek,
                     plaintext=b'test') as secret):

            encoded = secret.encode(
                kek=kek,
                version_field='foov',
            )

        self.assertEqual(
            encoded,
            'foov=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIjZGUlzUKGzz6ATN964XTSs')

    def test_encode_with_extra_fields(self) -> None:
        """Testing Secret.encode with extra_fields="""
        self.spy_on(generate_nonce,
                    op=kgb.SpyOpReturn(GCM_NONCE))

        with (AESKey.from_bytes(AES_256_KEK_BYTES,
                                key_id='my-kek-1') as kek,
              AESKey.from_bytes(AES_256_DEK_BYTES) as dek,
              Secret(dek=dek,
                     extra_fields={
                         'field1': 'value1',
                         ';field2!': ';value2!',
                     },
                     plaintext=b'test') as secret):

            encoded = secret.encode(kek=kek)

        self.assertEqual(
            encoded,
            'encv=2;%3Bfield2%21=%3Bvalue2%21;alg=AES-256-GCM;edek=OUBk'
            'q65QOnO0YcwPwne2J3WTPxB9uM0cCPaHun8bGuIAzeKQgq-BnQ;'
            'field1=value1;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIoMOKUH37twmoOlya9Y_JzE')

    def test_encode_with_no_key_id(self) -> None:
        """Testing Secret.encode with missing key ID"""
        message = 'kek must have a key_id to encode a Secret.'

        with (AESKey.from_bytes(AES_256_KEK_BYTES) as kek,
              Secret(plaintext=b'test') as secret,
              self.assertRaisesRegex(ValueError, re.escape(message))):
            secret.encode(kek=kek)

    def test_encode_with_reserved_field(self) -> None:
        """Testing Secret.encode with reserved field"""
        message = (
            "extra_fields cannot contain reserved field name(s): alg, "
            "encv, kid"
        )

        with (AESKey.from_bytes(AES_256_KEK_BYTES,
                                key_id='my-key-1') as kek,
              Secret(plaintext=b'test',
                     extra_fields={
                         'alg': 'zzz',
                         'encv': '123',
                         'kid': 'xxx',
                     }) as secret,
              self.assertRaisesRegex(ValueError, re.escape(message))):
            secret.encode(kek=kek)

    def test_from_encoded(self) -> None:
        """Testing Secret.from_encoded"""
        encoded = (
            'encv=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIqYk4mxvGfg0adJAv9LJsVg'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            secret = Secret.from_encoded(
                encoded,
                kek_resolver=self._build_kek_resolver(kek=kek),
            )

            self.assertEqual(secret.dek.to_bytes(), AES_256_DEK_BYTES)
            self.assertEqual(secret.plaintext, b'test')
            self.assertEqual(secret.extra_fields, {})

    def test_from_encoded_with_extra_fields(self) -> None:
        """Testing Secret.from_encoded with extra fields"""
        encoded = (
            'encv=2;%3Bfield2%21=%3Bvalue2%21;alg=AES-256-GCM;edek=OUBk'
            'q65QOnO0YcwPwne2J3WTPxB9uM0cCPaHun8bGuIAzeKQgq-BnQ;'
            'field1=value1;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIoMOKUH37twmoOlya9Y_JzE'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            secret = Secret.from_encoded(
                encoded,
                kek_resolver=self._build_kek_resolver(kek=kek),
            )

            self.assertEqual(secret.dek.to_bytes(), AES_256_DEK_BYTES)
            self.assertEqual(secret.plaintext, b'test')
            self.assertEqual(secret.extra_fields, {
                'field1': 'value1',
                ';field2!': ';value2!',
            })

    def test_from_encoded_with_missing_kek(self) -> None:
        """Testing Secret.from_encoded with missing KEK"""
        encoded = (
            'encv=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        message = (
            "Could not locate the key required to decrypt this secret "
            "(key ID 'my-kek-1')."
        )

        with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
            Secret.from_encoded(
                encoded,
                kek_resolver=self._build_kek_resolver(kek=None),
            )

    def test_from_encoded_with_missing_version_field(self) -> None:
        """Testing Secret.from_encoded with missing version field"""
        encoded = (
            'v=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = 'Envelope version field is missing.'

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_missing_envelope_sep(self) -> None:
        """Testing Secret.from_encoded with missing envelope separator"""
        encoded = (
            'encv=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = 'Invalid envelope format.'

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_field_parse_error(self) -> None:
        """Testing Secret.from_encoded with envelope field parse error"""
        encoded = (
            'encv=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = 'Envelope field parse error: kid'

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_non_int_version(self) -> None:
        """Testing Secret.from_encoded with non-int version"""
        encoded = (
            'encv=xxx;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = "Invalid envelope version string 'xxx'."

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_unsupported_version(self) -> None:
        """Testing Secret.from_encoded with unsupported version"""
        encoded = (
            'encv=9999;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = 'Unsupported envelope version 9999.'

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_unknown_encryption_alg(self) -> None:
        """Testing Secret.from_encoded with unknown encryption algorithm"""
        encoded = (
            'encv=2;alg=AES-512-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = "Unsupported encryption algorithm 'AES-512-GCM'."

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_unsupported_encryption_alg(self) -> None:
        """Testing Secret.from_encoded with unsupported encryption algorithm
        """
        encoded = (
            'encv=2;alg=AES-256-KW;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = "Unsupported encryption algorithm 'AES-256-KW'."

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_unknown_keywrap_alg(self) -> None:
        """Testing Secret.from_encoded with unknown keywrap algorithm"""
        encoded = (
            'encv=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-512-KW!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = "Unsupported key wrapping algorithm 'AES-512-KW'."

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_unsupported_keywrap_alg(self) -> None:
        """Testing Secret.from_encoded with unsupported keywrap algorithm"""
        encoded = (
            'encv=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-GCM!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = "Unsupported key wrapping algorithm 'AES-256-GCM'."

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_key_unwrap_failed(self) -> None:
        """Testing Secret.from_encoded with key unwrap failure"""
        encoded = (
            'encv=2;alg=AES-256-GCM;edek=B9uM0cCPaHun8bGuIAzeKQgq-BnQ;'
            'kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ2uIjlHEoXTmL_AdxCACtJUNKw'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = 'Failed to unwrap encryption key.'

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_decrypt_failed(self) -> None:
        """Testing Secret.from_encoded with decryption failure"""
        encoded = (
            'encv=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRowJ'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = 'Failed to decrypt payload.'

            with self.assertRaisesRegex(SecretDecodeError, re.escape(message)):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_from_encoded_with_corrupt_ciphertext(self) -> None:
        """Testing Secret.from_encoded with corrupt ciphertext"""
        encoded = (
            'encv=2;alg=AES-256-GCM;edek=OUBkq65QOnO0YcwPwne2J3WTPx'
            'B9uM0cCPaHun8bGuIAzeKQgq-BnQ;kid=my-kek-1;wrap=AES-256-KW!'
            'Ci0qqehuQg02brRow'
        )

        with AESKey.from_bytes(AES_256_KEK_BYTES,
                               key_id='my-kek-1') as kek:
            message = 'Corrupted ciphertext: .+'

            with self.assertRaisesRegex(SecretDecodeError, message):
                Secret.from_encoded(
                    encoded,
                    kek_resolver=self._build_kek_resolver(kek=kek),
                )

    def test_invalidation(self) -> None:
        """Testing Secret invalidation"""
        dek = AESKey.generate(key_size=256)

        with Secret(plaintext=b'test',
                    dek=dek,
                    extra_fields={'key': 'value'}) as secret:
            self.assertTrue(secret.is_valid())
            self.assertEqual(secret.plaintext, b'test')
            self.assertEqual(secret.extra_fields, {'key': 'value'})
            self.assertIs(secret.dek, dek)
            self.assertTrue(dek.is_valid())

        self.assertFalse(secret.is_valid())
        self.assertEqual(secret.plaintext, b'')
        self.assertEqual(secret.extra_fields, {})
        self.assertIs(secret.dek, dek)
        self.assertFalse(dek.is_valid())

    def _build_kek_resolver(
        self,
        *,
        kek: AESKey | None,
        expected_key_id: str = 'my-kek-1',
    ) -> Callable[[str], AESKey | None]:
        """Return a KEK resolver function for a test.

        Args:
            kek (cryptozoology.keys.aes.AESKey):
                The KEK result to return.

                This may be ``None``.

            expected_key_id (str, optional):
                The expected key ID to assert on.

        Returns:
            cryptozoology.keys.aes.AESKey:
            The resulting key value.
        """
        def _resolve_kek(
            kek_id: str,
        ) -> AESKey | None:
            self.assertEqual(kek_id, expected_key_id)

            return kek

        return _resolve_kek
