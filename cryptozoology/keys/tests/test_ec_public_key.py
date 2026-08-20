"""Tests for cryptozoology.keys.ec.ECPublicKey.

Version Added:
    1.0
"""

from __future__ import annotations

import re
from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric import ec

from cryptozoology.errors import InvalidatedError
from cryptozoology.keys.ec import ECPublicKey


EC_PUBLIC_KEY_BYTES = (
    b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03'
    b'\x01\x07\x03B\x00\x04f\x1d\xfc\xed\xcf7X\x82O\x9c\xf8\x14'
    b'k\x19\xc6U?m\xa7n\xe9vMC\xb8\xc6\x1a\x14\xa57\xee\x82\xc4'
    b'\xdb\xe9(\xa9\x8b\x93\x07\xff\xeb\xa6\xa1\xc3M\xb4\x8cZ'
    b'\xc0I,\x8a\xffh0\xda\xe7\x10G}\xb7\xd6\x18'
)


class ECPublicKeyTests(TestCase):
    """Unit tests for ECPublicKey.

    Version Added:
        1.0
    """

    def test_fingerprint_sha256(self) -> None:
        """Testing ECPublicKey.fingerprint_sha256"""
        with ECPublicKey.from_bytes(EC_PUBLIC_KEY_BYTES) as public_key:
            self.assertEqual(
                public_key.fingerprint_sha256,
                b'\xf3\x8d\x8e\xad\x8cr/\xcfBI\xa3\xad\xb8\x8c\xf8\xb9'
                b'\xafP\xa6C\x83\xc7\x18\x81\xe2\xdc3\x18\x0e\xacc\xad')

            self.assertEqual(
                public_key._fingerprint_sha256,
                b'\xf3\x8d\x8e\xad\x8cr/\xcfBI\xa3\xad\xb8\x8c\xf8\xb9'
                b'\xafP\xa6C\x83\xc7\x18\x81\xe2\xdc3\x18\x0e\xacc\xad')

    def test_fingerprint_sha256_after_invalidate(self) -> None:
        """Testing ECPublicKey.fingerprint_sha256 after invalidation"""
        with ECPublicKey.from_bytes(EC_PUBLIC_KEY_BYTES) as public_key:
            public_key.fingerprint_sha256

        message = (
            'This ECPublicKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            public_key.fingerprint_sha256

        self.assertIsNone(public_key._fingerprint_sha256)

    def test_from_bytes(self) -> None:
        """Testing ECPublicKey.from_bytes"""
        with ECPublicKey.from_bytes(EC_PUBLIC_KEY_BYTES) as public_key:
            self.assertIsNone(public_key.key_id)

            impl_public_key = public_key.impl_public_key

            assert impl_public_key is not None
            self.assertIsInstance(impl_public_key.curve, ec.SECP256R1)

    def test_from_bytes_with_kid(self) -> None:
        """Testing ECPublicKey.from_bytes"""
        with ECPublicKey.from_bytes(EC_PUBLIC_KEY_BYTES,
                                    key_id='my-key') as public_key:
            self.assertEqual(public_key.key_id, 'my-key')

            impl_public_key = public_key.impl_public_key

            assert impl_public_key is not None
            self.assertIsInstance(impl_public_key.curve, ec.SECP256R1)

    def test_from_bytes_with_ec_private_key(self) -> None:
        """Testing ECPublicKey.from_bytes with EC private key"""
        message = (
            'The provided key is not an Elliptic Curve public key.'
        )

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            ECPublicKey.from_bytes(
                b'0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06'
                b'\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 (U\x19'
                b'\xeaQ\x8e\xff\xf9e\xdc\xe3\xee@\x8c\x88\xea\x87\xff8\xb4'
                b'\xf2\xe5U\xd6W\xc5\xb5&\x9b\xa1\x07\x97\xa1D\x03B\x00\x04'
                b'\xc2\x12ezl\x8f\xec4N\xe1~\xbc`\ra\x16\xbfR&\x1f5\x0b\xc9'
                b'=/\xa5\x91$\x8e6\x8e\x00P\xf0%(L\x95\xfc\x9c|]\xb8\xd1\xdf'
                b'K\xdd\xee\xd5&\xdc\xae\xe6-V\xb5\xabc`\xdb\x00x\x91\xe5'
            )

    def test_from_bytes_with_rsa_public_key(self) -> None:
        """Testing ECPublicKey.from_bytes with RSA public key"""
        message = (
            'The provided key is not an Elliptic Curve public key.'
        )

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            ECPublicKey.from_bytes(
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

    def test_to_bytes(self) -> None:
        """Testing ECPublicKey.to_bytes"""
        with ECPublicKey.from_bytes(EC_PUBLIC_KEY_BYTES) as public_key:
            self.assertEqual(public_key.to_bytes(), EC_PUBLIC_KEY_BYTES)

    def test_to_bytes_after_invalidate(self) -> None:
        """Testing ECPublicKey.to_bytes after invalidation"""
        with ECPublicKey.from_bytes(EC_PUBLIC_KEY_BYTES) as public_key:
            pass

        message = (
            'This ECPublicKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            public_key.to_bytes()
