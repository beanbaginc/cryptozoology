"""Tests for cryptozoology.keys.ec.ECPrivateKey.

Version Added:
    1.0
"""

from __future__ import annotations

import re
from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric import ec

from cryptozoology.errors import InvalidatedError
from cryptozoology.keys.ec import ECPrivateKey, ECPublicKey


EC_PRIVATE_KEY_BYTES = (
    b'0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06'
    b'\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 (U\x19'
    b'\xeaQ\x8e\xff\xf9e\xdc\xe3\xee@\x8c\x88\xea\x87\xff8\xb4'
    b'\xf2\xe5U\xd6W\xc5\xb5&\x9b\xa1\x07\x97\xa1D\x03B\x00\x04'
    b'\xc2\x12ezl\x8f\xec4N\xe1~\xbc`\ra\x16\xbfR&\x1f5\x0b\xc9'
    b'=/\xa5\x91$\x8e6\x8e\x00P\xf0%(L\x95\xfc\x9c|]\xb8\xd1\xdf'
    b'K\xdd\xee\xd5&\xdc\xae\xe6-V\xb5\xabc`\xdb\x00x\x91\xe5'
)

EC_PRIVATE_KEY_PASSWORD_BYTES = (
    b'0\x81\xf40_\x06\t*\x86H\x86\xf7\r\x01\x05\r0R01\x06\t*\x86H'
    b'\x86\xf7\r\x01\x05\x0c0$\x04\x10\xe1\xffg\x89\xc2\xed\x8b'
    b'\x1c\xac\x1ep\xdc=\x82\x9ao\x02\x02\x08\x000\x0c\x06\x08*'
    b'\x86H\x86\xf7\r\x02\t\x05\x000\x1d\x06\t`\x86H\x01e\x03\x04'
    b'\x01*\x04\x10\xc3I\x0f\x14\xad\xd7\xd3U\xec\xa4O\\\x82\r\xbb'
    b'\x82\x04\x81\x90\x1b-\xadpF/T\xf6\x91\x95\xd1\xd1\xfe(\x16'
    b'\xc9\xa49R")\xcb\xfc\x93\xf8\xc0T\xb1\xb6w\x8c\\*h\xa2u#'
    b'\xd0\x893K\xdd\x8a[\x1b\xbc\xb8brcL\x80\xac\xed\xbd\x85,\xdc'
    b'\x1f\xd2\x0f\xcc\xec\xde\x85_\x8c\x1c\xfb\'\x88\x1c\x1b\\\x81'
    b's\x83\x8d\xf3\xb2#\xde\xea7\xb1\xd2\x11\xc5 k\xf2\x89\xb2\x88'
    b'\x88?\xd4\x87\xday>\xaf[+S\xd6\xe9\x83R5Fi|y\xcb\x1a\xf4\xadw'
    b'\x93\xc0\x11\xf4\xc84\xb4\ts\xd5\x8dF}9\x96\x98\x1b\x93\xed9'
    b'\xe7\xc3"\xa1\x96'
)


class ECPrivateKeyTests(TestCase):
    """Unit tests for ECPrivateKey.

    Version Added:
        1.0
    """

    def test_exchange(self) -> None:
        """Testing ECPrivateKey.exchange"""
        other_public_key_bytes = (
            b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03'
            b'\x01\x07\x03B\x00\x04f\x1d\xfc\xed\xcf7X\x82O\x9c\xf8\x14'
            b'k\x19\xc6U?m\xa7n\xe9vMC\xb8\xc6\x1a\x14\xa57\xee\x82\xc4'
            b'\xdb\xe9(\xa9\x8b\x93\x07\xff\xeb\xa6\xa1\xc3M\xb4\x8cZ'
            b'\xc0I,\x8a\xffh0\xda\xe7\x10G}\xb7\xd6\x18'
        )

        with (ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES) as private_key,
              ECPublicKey.from_bytes(other_public_key_bytes) as public_key):
            shared_key = private_key.exchange(public_key)

            self.assertEqual(
                shared_key,
                b'\xdc-\xc5\x83\xe2\xe7\xc2\x83\xd2\xee4\x7f\xc6n\xf8H'
                b'\x12*`o\xeb\xdbs\x9ed\x94\x90\x90\x9bI\x1cG')

    def test_fingerprint_sha256(self) -> None:
        """Testing ECPrivateKey.fingerprint_sha256"""
        with ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES) as private_key:
            self.assertEqual(
                private_key.fingerprint_sha256,
                b';\xb1\x11\x9f\x92\xb6\xe57\xbe|k\xdb\xf8\x9ds\xf6'
                b'\x15\xb0\xb9;\xcf\rE\xaa\xd1-0\x95W1Y;')

            self.assertEqual(
                private_key._fingerprint_sha256,
                b';\xb1\x11\x9f\x92\xb6\xe57\xbe|k\xdb\xf8\x9ds\xf6'
                b'\x15\xb0\xb9;\xcf\rE\xaa\xd1-0\x95W1Y;')

    def test_fingerprint_sha256_after_invalidate(self) -> None:
        """Testing ECPrivateKey.fingerprint_sha256 after invalidation"""
        with ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES) as private_key:
            private_key.fingerprint_sha256

        message = (
            'This ECPrivateKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            private_key.fingerprint_sha256

        self.assertIsNone(private_key._fingerprint_sha256)

    def test_from_bytes(self) -> None:
        """Testing ECPrivateKey.from_bytes"""
        with ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES) as private_key:
            self.assertIsNone(private_key.key_id)

            impl_private_key = private_key.impl_private_key

            assert impl_private_key is not None
            self.assertIsInstance(impl_private_key.curve, ec.SECP256R1)

    def test_from_bytes_with_password(self) -> None:
        """Testing ECPrivateKey.from_bytes with password"""
        with (ECPrivateKey.from_bytes(EC_PRIVATE_KEY_PASSWORD_BYTES,
                                      password=b's3cr3t')
              as private_key):
            self.assertIsNone(private_key.key_id)

            impl_private_key = private_key.impl_private_key

            assert impl_private_key is not None
            self.assertIsInstance(impl_private_key.curve, ec.SECP256R1)

    def test_from_bytes_with_wrong_password(self) -> None:
        """Testing ECPrivateKey.from_bytes with wrong password"""
        message = (
            'The provided key could not be loaded as an Elliptic Curve '
            'private key.'
        )

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            ECPrivateKey.from_bytes(EC_PRIVATE_KEY_PASSWORD_BYTES,
                                    password=b'xxx')

    def test_from_bytes_with_unwanted_password(self) -> None:
        """Testing ECPrivateKey.from_bytes with password for key without
        password
        """
        message = 'Password was given but private key is not encrypted.'

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES,
                                    password=b'xxx')

    def test_from_bytes_with_kid(self) -> None:
        """Testing ECPrivateKey.from_bytes"""
        with ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES,
                                     key_id='my-key') as private_key:
            self.assertEqual(private_key.key_id, 'my-key')

            impl_private_key = private_key.impl_private_key

            assert impl_private_key is not None
            self.assertIsInstance(impl_private_key.curve, ec.SECP256R1)

    def test_from_bytes_with_ec_public_key(self) -> None:
        """Testing ECPrivateKey.from_bytes with EC public key"""
        message = (
            'The provided key could not be loaded as an Elliptic Curve '
            'private key.'
        )

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            ECPrivateKey.from_bytes(
                b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03'
                b'\x01\x07\x03B\x00\x04f\x1d\xfc\xed\xcf7X\x82O\x9c\xf8\x14'
                b'k\x19\xc6U?m\xa7n\xe9vMC\xb8\xc6\x1a\x14\xa57\xee\x82\xc4'
                b'\xdb\xe9(\xa9\x8b\x93\x07\xff\xeb\xa6\xa1\xc3M\xb4\x8cZ'
                b'\xc0I,\x8a\xffh0\xda\xe7\x10G}\xb7\xd6\x18'
            )

    def test_from_bytes_with_rsa_public_key(self) -> None:
        """Testing ECPrivateKey.from_bytes with RSA private key"""
        message = (
            'The provided key could not be loaded as an Elliptic Curve '
            'private key.'
        )

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            ECPrivateKey.from_bytes(
                b'0\x82\x01\n\x02\x82\x01\x01\x00\xc4gJ\xbb\xa2\xc9.\x88l'
                b'\x08\xe1\xb4\xb8\x8e\x8b\x10\xcd\xa5\xf1\xc1\xcf \xfe'
                b'\xd4S\x98\xbdy\x1e\x8bYI\xb5\xd41\xb3\xfa\xbe\xc7\x00'
                b'\x9e\x13\xba\x11\x04\xd8\xb3\xc5(\xdf\xa5\xf3`V\x9c\xd4'
                b'\xf9[\x04N\x8dD\xbc\\\xa6B\xd4\xe6j\xe3t_\x90\xf7\x17oV'
                b'\x191O\xeb\xf7a\xa8X\xce\x00\xd5d]<\xac[\x88\x0b\xe4\xe8'
                b' I\xf2\xfa\xa5Y\x01<\xe4\xd0\x17\xca\xa5\x1f\xf3\xba\xc7'
                b'\x0e\xde[\xd8f1\xfe\xfd}h\xf7\x13\xff\xbf\x87YC\x96\xae'
                b'\xd7?\xf3\xd6V\xdc\x9fa\x8bgT\xcb\\0\xde\xeb\x084{\xc9sF'
                b'\xe6.\xd9\xa6\xa4,tx\x85\x02-u\x18c+O\x9f\x861\xaaH\xe6B'
                b'\x9c{\x1a\xca\x1cG\x80[m\xd7\xc9u\xae\xfa\xa5\x1d\xaa\xaf'
                b'y\x8d\xe8\x0f\xac\xa3\xe7.\x8d\xa1\xb1_[~\x82\xfa\xec'
                b'\x0e`\x8e\xa8\x89\xe7\x13\xb9\t\xf3%\xc3$\xfb8aB\x9e\xf9'
                b'M\xd4\x9f\x18\x1e\x89\xc7+e\xbbO0H\xfd\x8e\xed\x93\xf5'
                b'\xd9w*\xc6\x93G\x02\x03\x01\x00\x01'
            )

    def test_get_public_key(self) -> None:
        """Testing ECPrivateKey.get_public_key"""
        with ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES) as private_key:
            public_key = private_key.get_public_key()

            self.assertIs(private_key.get_public_key(), public_key)
            self.assertEqual(public_key.fingerprint_sha256,
                             private_key.fingerprint_sha256)

    def test_get_public_key_after_invalidate(self) -> None:
        """Testing ECPrivateKey.get_public_key after invalidation"""
        with ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES) as private_key:
            public_key = private_key.get_public_key()

        self.assertFalse(public_key.is_valid())

        message = (
            'This ECPrivateKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            private_key.get_public_key()

    def test_to_bytes(self) -> None:
        """Testing ECPrivateKey.to_bytes"""
        with ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES) as private_key:
            self.assertEqual(private_key.to_bytes(), EC_PRIVATE_KEY_BYTES)

    def test_to_bytes_with_password(self) -> None:
        """Testing ECPrivateKey.to_bytes with password"""
        with ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES) as private_key:
            private_key_bytes = private_key.to_bytes(password=b's3cr3t')

            # Make sure this can be loaded without raising an exception.
            with ECPrivateKey.from_bytes(private_key_bytes,
                                         password=b's3cr3t'):
                pass

    def test_to_bytes_after_invalidate(self) -> None:
        """Testing ECPrivateKey.to_bytes after invalidation"""
        with ECPrivateKey.from_bytes(EC_PRIVATE_KEY_BYTES) as private_key:
            pass

        message = (
            'This ECPrivateKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            private_key.to_bytes()
