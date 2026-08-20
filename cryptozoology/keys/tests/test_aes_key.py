"""Tests for cryptozoology.keys.aes.AESKey.

Version Added:
    1.0
"""

from __future__ import annotations

import re
from unittest import TestCase, skipUnless

from cryptozoology.errors import (DecryptionError,
                                  InvalidatedError,
                                  KeyUnwrapError,
                                  UnsupportedAlgorithmError)
from cryptozoology.keys.aes import AESKey
from cryptozoology.keys.ec import ECPrivateKey, ECPublicKey
from cryptozoology.utils.random import Nonce, Salt

try:
    # Not all cryptography versions/OpenSSL builds provide AES-GCM-SIV.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    has_gcm_siv = True
except ImportError:
    AESGCMSIV = None
    has_gcm_siv = False


AES_128_KEY_BYTES = b'f\xabpX\xc1g;W\x97\x80\xf5\xa1\xad\x05\xb7\n'

AES_192_KEY_BYTES = \
    b'\xba)\xcf\x87P\x0b\xde\xdc\x07\xf6rrOl\x10\x9d\x15]\n\xbf\xde\x8b}W'

AES_256_KEY_BYTES = (
    b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc\xe8\xae*'
    b'\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
)

GCM_NONCE = Nonce(b'\n-*\xa9\xe8nB\r6n\xb4h')
CFB8_NONCE = Nonce(b'1\xc9\xc2\xde\xb1\xa7R\xa5\xbcJAk\xaf\xee\x91\xf3')


class AESKeyClassTests(TestCase):
    """Unit tests for AESKey class methods.

    Version Added:
        1.0
    """

    def test_derive_from_bytes_with_base_aeskey(self) -> None:
        """Testing AESKey.derive_from_bytes with base AESKey"""
        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        # We'll derive from a smaller key to test that we always get a
        # stronger key.
        with (AESKey.from_bytes(AES_128_KEY_BYTES) as base_key,
              AESKey.derive_from_bytes(base_key=base_key,
                                       hkdf_info=hkdf_info,
                                       salt=salt) as derived_key):
            self.assertEqual(derived_key.key_size, 256)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\xba)\xcf\x87P\x0b\xde\xdc\x07\xf6rrOl\x10\x9d\x15]\n'
                b'\xbf\xde\x8b}W{\xb0\x15f\xe7\x8c\x1f\x9e')

        # A different HKDF info will produce a different result.
        hkdf_info = b'my-hkdf-info-2'

        with (AESKey.from_bytes(AES_128_KEY_BYTES) as base_key,
              AESKey.derive_from_bytes(base_key=base_key,
                                       hkdf_info=hkdf_info,
                                       salt=salt) as derived_key):
            self.assertEqual(derived_key.key_size, 256)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'm"V\xcd\x19\t\x1d3\x8d\x94\x9b)\xc1\xf3\x85\x15\x1b'
                b'\xbe3xl\x17\x8e\xaba\r\x8d\xc8\tQ\x81\x17')

        # Same with a different salt.
        salt = Salt(b'00045678123456781234567812345678')

        with (AESKey.from_bytes(AES_128_KEY_BYTES) as base_key,
              AESKey.derive_from_bytes(base_key=base_key,
                                       hkdf_info=hkdf_info,
                                       salt=salt) as derived_key):
            self.assertEqual(derived_key.key_size, 256)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\xc7\xedU\xcej4\x81\xfd\n\x9a7\xf2\x17X\x9f\x85.\x9d'
                b'V\x18\xddn&\x923u\x8d\xdb\xbeL\x89\xfd')

        # And a different base key.
        key_bytes = (
            b'?P>\xc1\xc8z]t\xe4P\xbc\xd2\x9a\x94\xcb\xa3\x00\xe2\x88'
            b'vbp_T\x17I\xac\xb1\x18*\xe1\x8f'
        )

        with (AESKey.from_bytes(key_bytes) as base_key,
              AESKey.derive_from_bytes(base_key=base_key,
                                       hkdf_info=hkdf_info,
                                       salt=salt) as derived_key):
            self.assertEqual(derived_key.key_size, 256)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'L\x119=O\xea\x1a\xcem\xecAG\xd8Ub!\x15\xa1\xd2\x93\xc3'
                b'\x83h\xd4]\xc6$\xfc\xa7QO\x90')

    def test_derive_from_bytes_with_base_bytes(self) -> None:
        """Testing AESKey.derive_from_bytes with base bytes key"""
        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        # We'll derive from a smaller key to test that we always get a
        # stronger key.
        with AESKey.derive_from_bytes(base_key=AES_128_KEY_BYTES,
                                      hkdf_info=hkdf_info,
                                      salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 256)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\xba)\xcf\x87P\x0b\xde\xdc\x07\xf6rrOl\x10\x9d\x15]\n'
                b'\xbf\xde\x8b}W{\xb0\x15f\xe7\x8c\x1f\x9e')

    def test_derive_from_bytes_with_with_128_bit(self) -> None:
        """Testing AESKey.derive_from_bytes with derived 128-bit key"""
        # We'll derive from a larger key to test that we always get the
        # expected resulting key size.
        key_bytes = (
            b'L\x119=O\xea\x1a\xcem\xecAG\xd8Ub!\x15\xa1\xd2\x93\xc3'
            b'\x83h\xd4]\xc6$\xfc\xa7QO\x90'
        )

        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        with AESKey.derive_from_bytes(base_key=key_bytes,
                                      hkdf_info=hkdf_info,
                                      key_size=128,
                                      salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 128)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\x93Y\x84\xe2\x0f\xcf\xf5\xcbt\xb9\x06iI#\x07\x95')

    def test_derive_from_bytes_with_with_192_bit(self) -> None:
        """Testing AESKey.derive_from_bytes with derived 192-bit key"""
        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        # We'll derive from a smaller key to test that we always get the
        # expected resulting key size.
        with AESKey.derive_from_bytes(base_key=AES_128_KEY_BYTES,
                                      hkdf_info=hkdf_info,
                                      key_size=192,
                                      salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 192)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\xba)\xcf\x87P\x0b\xde\xdc\x07\xf6rrOl\x10\x9d\x15]'
                b'\n\xbf\xde\x8b}W')

    def test_derive_from_bytes_with_with_256_bit(self) -> None:
        """Testing AESKey.derive_from_bytes with derived 256-bit key"""
        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        # We'll derive from a smaller key to test that we always get the
        # expected resulting key size.
        with AESKey.derive_from_bytes(base_key=AES_128_KEY_BYTES,
                                      hkdf_info=hkdf_info,
                                      key_size=256,
                                      salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 256)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\xba)\xcf\x87P\x0b\xde\xdc\x07\xf6rrOl\x10\x9d\x15]\n'
                b'\xbf\xde\x8b}W{\xb0\x15f\xe7\x8c\x1f\x9e')

    def test_derive_from_bytes_with_with_invalid_size(self) -> None:
        """Testing AESKey.derive_from_bytes with invalid key size"""
        hkdf_info = b'my-hkdf-info'
        salt = Salt(b'12345678123456781234567812345678')

        message = 'Unsupported AES key size: 64'

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            AESKey.derive_from_bytes(base_key=AES_128_KEY_BYTES,
                                     hkdf_info=hkdf_info,
                                     key_size=64,
                                     salt=salt)

    def test_derive_from_bytes_with_with_key_id(self) -> None:
        """Testing AESKey.derive_from_bytes with key_id"""
        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        # We'll derive from a smaller key to test that we always get a
        # stronger key.
        with AESKey.derive_from_bytes(base_key=AES_128_KEY_BYTES,
                                      hkdf_info=hkdf_info,
                                      salt=salt,
                                      key_id='my-key') as derived_key:
            self.assertEqual(derived_key.key_size, 256)
            self.assertEqual(derived_key.key_id, 'my-key')
            self.assertEqual(
                derived_key.to_bytes(),
                b'\xba)\xcf\x87P\x0b\xde\xdc\x07\xf6rrOl\x10\x9d\x15]\n'
                b'\xbf\xde\x8b}W{\xb0\x15f\xe7\x8c\x1f\x9e')

    def test_derive_from_key_exchange(self) -> None:
        """Testing AESKey.derive_from_key_exchange"""
        ec_private_key = ECPrivateKey.from_bytes(
            b'0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06'
            b'\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 (U\x19'
            b'\xeaQ\x8e\xff\xf9e\xdc\xe3\xee@\x8c\x88\xea\x87\xff8\xb4'
            b'\xf2\xe5U\xd6W\xc5\xb5&\x9b\xa1\x07\x97\xa1D\x03B\x00\x04'
            b'\xc2\x12ezl\x8f\xec4N\xe1~\xbc`\ra\x16\xbfR&\x1f5\x0b\xc9'
            b'=/\xa5\x91$\x8e6\x8e\x00P\xf0%(L\x95\xfc\x9c|]\xb8\xd1\xdf'
            b'K\xdd\xee\xd5&\xdc\xae\xe6-V\xb5\xabc`\xdb\x00x\x91\xe5'
        )

        ec_public_key = ECPublicKey.from_bytes(
            b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03'
            b'\x01\x07\x03B\x00\x04f\x1d\xfc\xed\xcf7X\x82O\x9c\xf8\x14'
            b'k\x19\xc6U?m\xa7n\xe9vMC\xb8\xc6\x1a\x14\xa57\xee\x82\xc4'
            b'\xdb\xe9(\xa9\x8b\x93\x07\xff\xeb\xa6\xa1\xc3M\xb4\x8cZ'
            b'\xc0I,\x8a\xffh0\xda\xe7\x10G}\xb7\xd6\x18'
        )

        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        with AESKey.derive_from_key_exchange(public_key=ec_public_key,
                                             private_key=ec_private_key,
                                             hkdf_info=hkdf_info,
                                             salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 256)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\x8930\xe5\x87\xf9\x137\xc7\xb3\x81<\xb0$S_\xad\x0e\xf6'
                b'\xc4\xf9\x18\xd78\x86\x905\xb1\x0b\xf6\xc9:')

        # A different HKDF info will produce a different result.
        hkdf_info = b'my-hkdf-info-2'

        with AESKey.derive_from_key_exchange(public_key=ec_public_key,
                                             private_key=ec_private_key,
                                             hkdf_info=hkdf_info,
                                             salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 256)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b":\xa5\'X\xb0\x18q\x82\xc0\xbf\x05<Y;\xa76GqjW\x91\xda"
                b"\x80\xc66\xcaXR4\x9f4/")

        # Same with a different salt.
        salt = Salt(b'00045678123456781234567812345678')

        with AESKey.derive_from_key_exchange(public_key=ec_public_key,
                                             private_key=ec_private_key,
                                             hkdf_info=hkdf_info,
                                             salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 256)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'5\x94D\xad\xce-}L\xa6\x9d\xb1gL\xa2vl\x1f\xa6Q!u\x9e'
                b'\xf7\\p\xb1\xe0\x1e\x01\x15:?')

    def test_derive_from_key_exchange_with_128_bit(self) -> None:
        """Testing AESKey.derive_from_key_exchange with derived 128-bit key
        """
        ec_private_key = ECPrivateKey.from_bytes(
            b'0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06'
            b'\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 (U\x19'
            b'\xeaQ\x8e\xff\xf9e\xdc\xe3\xee@\x8c\x88\xea\x87\xff8\xb4'
            b'\xf2\xe5U\xd6W\xc5\xb5&\x9b\xa1\x07\x97\xa1D\x03B\x00\x04'
            b'\xc2\x12ezl\x8f\xec4N\xe1~\xbc`\ra\x16\xbfR&\x1f5\x0b\xc9'
            b'=/\xa5\x91$\x8e6\x8e\x00P\xf0%(L\x95\xfc\x9c|]\xb8\xd1\xdf'
            b'K\xdd\xee\xd5&\xdc\xae\xe6-V\xb5\xabc`\xdb\x00x\x91\xe5'
        )

        ec_public_key = ECPublicKey.from_bytes(
            b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03'
            b'\x01\x07\x03B\x00\x04f\x1d\xfc\xed\xcf7X\x82O\x9c\xf8\x14'
            b'k\x19\xc6U?m\xa7n\xe9vMC\xb8\xc6\x1a\x14\xa57\xee\x82\xc4'
            b'\xdb\xe9(\xa9\x8b\x93\x07\xff\xeb\xa6\xa1\xc3M\xb4\x8cZ'
            b'\xc0I,\x8a\xffh0\xda\xe7\x10G}\xb7\xd6\x18'
        )

        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        with AESKey.derive_from_key_exchange(public_key=ec_public_key,
                                             private_key=ec_private_key,
                                             hkdf_info=hkdf_info,
                                             key_size=128,
                                             salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 128)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\x8930\xe5\x87\xf9\x137\xc7\xb3\x81<\xb0$S_')

    def test_derive_from_key_exchange_with_192_bit(self) -> None:
        """Testing AESKey.derive_from_key_exchange with derived 192-bit key
        """
        ec_private_key = ECPrivateKey.from_bytes(
            b'0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06'
            b'\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 (U\x19'
            b'\xeaQ\x8e\xff\xf9e\xdc\xe3\xee@\x8c\x88\xea\x87\xff8\xb4'
            b'\xf2\xe5U\xd6W\xc5\xb5&\x9b\xa1\x07\x97\xa1D\x03B\x00\x04'
            b'\xc2\x12ezl\x8f\xec4N\xe1~\xbc`\ra\x16\xbfR&\x1f5\x0b\xc9'
            b'=/\xa5\x91$\x8e6\x8e\x00P\xf0%(L\x95\xfc\x9c|]\xb8\xd1\xdf'
            b'K\xdd\xee\xd5&\xdc\xae\xe6-V\xb5\xabc`\xdb\x00x\x91\xe5'
        )

        ec_public_key = ECPublicKey.from_bytes(
            b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03'
            b'\x01\x07\x03B\x00\x04f\x1d\xfc\xed\xcf7X\x82O\x9c\xf8\x14'
            b'k\x19\xc6U?m\xa7n\xe9vMC\xb8\xc6\x1a\x14\xa57\xee\x82\xc4'
            b'\xdb\xe9(\xa9\x8b\x93\x07\xff\xeb\xa6\xa1\xc3M\xb4\x8cZ'
            b'\xc0I,\x8a\xffh0\xda\xe7\x10G}\xb7\xd6\x18'
        )

        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        with AESKey.derive_from_key_exchange(public_key=ec_public_key,
                                             private_key=ec_private_key,
                                             hkdf_info=hkdf_info,
                                             key_size=192,
                                             salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 192)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\x8930\xe5\x87\xf9\x137\xc7\xb3\x81<\xb0$S_\xad\x0e'
                b'\xf6\xc4\xf9\x18\xd78')

    def test_derive_from_key_exchange_with_256_bit(self) -> None:
        """Testing AESKey.derive_from_key_exchange with derived 256-bit key
        """
        ec_private_key = ECPrivateKey.from_bytes(
            b'0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06'
            b'\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 (U\x19'
            b'\xeaQ\x8e\xff\xf9e\xdc\xe3\xee@\x8c\x88\xea\x87\xff8\xb4'
            b'\xf2\xe5U\xd6W\xc5\xb5&\x9b\xa1\x07\x97\xa1D\x03B\x00\x04'
            b'\xc2\x12ezl\x8f\xec4N\xe1~\xbc`\ra\x16\xbfR&\x1f5\x0b\xc9'
            b'=/\xa5\x91$\x8e6\x8e\x00P\xf0%(L\x95\xfc\x9c|]\xb8\xd1\xdf'
            b'K\xdd\xee\xd5&\xdc\xae\xe6-V\xb5\xabc`\xdb\x00x\x91\xe5'
        )

        ec_public_key = ECPublicKey.from_bytes(
            b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03'
            b'\x01\x07\x03B\x00\x04f\x1d\xfc\xed\xcf7X\x82O\x9c\xf8\x14'
            b'k\x19\xc6U?m\xa7n\xe9vMC\xb8\xc6\x1a\x14\xa57\xee\x82\xc4'
            b'\xdb\xe9(\xa9\x8b\x93\x07\xff\xeb\xa6\xa1\xc3M\xb4\x8cZ'
            b'\xc0I,\x8a\xffh0\xda\xe7\x10G}\xb7\xd6\x18'
        )

        salt = Salt(b'12345678123456781234567812345678')
        hkdf_info = b'my-hkdf-info'

        with AESKey.derive_from_key_exchange(public_key=ec_public_key,
                                             private_key=ec_private_key,
                                             hkdf_info=hkdf_info,
                                             key_size=256,
                                             salt=salt) as derived_key:
            self.assertEqual(derived_key.key_size, 256)
            self.assertIsNone(derived_key.key_id)
            self.assertEqual(
                derived_key.to_bytes(),
                b'\x8930\xe5\x87\xf9\x137\xc7\xb3\x81<\xb0$S_\xad\x0e\xf6'
                b'\xc4\xf9\x18\xd78\x86\x905\xb1\x0b\xf6\xc9:')

    def test_derive_from_key_exchange_with_invalid_size(self) -> None:
        """Testing AESKey.derive_from_key_exchange with invalid key size"""
        ec_private_key = ECPrivateKey.from_bytes(
            b'0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06'
            b'\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 (U\x19'
            b'\xeaQ\x8e\xff\xf9e\xdc\xe3\xee@\x8c\x88\xea\x87\xff8\xb4'
            b'\xf2\xe5U\xd6W\xc5\xb5&\x9b\xa1\x07\x97\xa1D\x03B\x00\x04'
            b'\xc2\x12ezl\x8f\xec4N\xe1~\xbc`\ra\x16\xbfR&\x1f5\x0b\xc9'
            b'=/\xa5\x91$\x8e6\x8e\x00P\xf0%(L\x95\xfc\x9c|]\xb8\xd1\xdf'
            b'K\xdd\xee\xd5&\xdc\xae\xe6-V\xb5\xabc`\xdb\x00x\x91\xe5'
        )

        ec_public_key = ECPublicKey.from_bytes(
            b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03'
            b'\x01\x07\x03B\x00\x04f\x1d\xfc\xed\xcf7X\x82O\x9c\xf8\x14'
            b'k\x19\xc6U?m\xa7n\xe9vMC\xb8\xc6\x1a\x14\xa57\xee\x82\xc4'
            b'\xdb\xe9(\xa9\x8b\x93\x07\xff\xeb\xa6\xa1\xc3M\xb4\x8cZ'
            b'\xc0I,\x8a\xffh0\xda\xe7\x10G}\xb7\xd6\x18'
        )

        hkdf_info = b'my-hkdf-info'
        salt = Salt(b'12345678123456781234567812345678')
        message = 'Unsupported AES key size: 64'

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            AESKey.derive_from_key_exchange(public_key=ec_public_key,
                                            private_key=ec_private_key,
                                            hkdf_info=hkdf_info,
                                            key_size=64,
                                            salt=salt)

    def test_from_bytes_with_128_bit(self) -> None:
        """Testing AESKey.from_bytes with 128-bit key"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            self.assertEqual(aes_key.key_size, 128)
            self.assertIsNone(aes_key.key_id)

    def test_from_bytes_with_192_bit(self) -> None:
        """Testing AESKey.from_bytes with 128-bit key"""
        key_bytes = (
            b'\x158\x83\xb9\xb8#|\x88\xb7\x0c\xee\xd7\xact8\x08\xfb'
            b'\xcc\xce%\x1c\xa3hD'
        )

        with AESKey.from_bytes(key_bytes) as aes_key:
            self.assertEqual(aes_key.key_size, 192)
            self.assertIsNone(aes_key.key_id)

    def test_from_bytes_with_256_bit(self) -> None:
        """Testing AESKey.from_bytes with 256-bit key"""
        key_bytes = (
            b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc'
            b'\xe8\xae*\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
        )

        with AESKey.from_bytes(key_bytes) as aes_key:
            self.assertEqual(aes_key.key_size, 256)
            self.assertIsNone(aes_key.key_id)

    def test_from_bytes_with_kid(self) -> None:
        """Testing AESKey.from_bytes with key_id"""
        key_bytes = (
            b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc'
            b'\xe8\xae*\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
        )

        with AESKey.from_bytes(key_bytes,
                               key_id='my-key') as aes_key:
            self.assertEqual(aes_key.key_size, 256)
            self.assertEqual(aes_key.key_id, 'my-key')

    def test_from_bytes_with_invalid_size(self) -> None:
        """Testing AESKey.from_bytes with invalid size"""
        message = 'Unsupported AES key bytes length: 8'

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            AESKey.from_bytes(b'XXXXXXXX')

    def test_generate_key_with_128(self) -> None:
        """Testing AESKey.generate_key with 128-bit key"""
        with AESKey.generate(key_size=128) as aes_key:
            self.assertEqual(aes_key.key_size, 128)

    def test_generate_key_with_192(self) -> None:
        """Testing AESKey.generate_key with 128-bit key"""
        with AESKey.generate(key_size=192) as aes_key:
            self.assertEqual(aes_key.key_size, 192)

    def test_generate_key_with_256(self) -> None:
        """Testing AESKey.generate_key with 128-bit key"""
        with AESKey.generate(key_size=256) as aes_key:
            self.assertEqual(aes_key.key_size, 256)

    def test_generate_key_with_invalid_size(self) -> None:
        """Testing AESKey.generate_key with invalid key size"""
        message = 'Unsupported AES key size: 64'

        with self.assertRaisesRegex(ValueError, re.escape(message)):
            AESKey.generate(key_size=64)  # type: ignore

    def test_supports_encryption_alg_with_cfb8(self) -> None:
        """Testing AESKey.supports_encryption_alg with CFB8 algorithms"""
        self.assertTrue(AESKey.supports_encryption_alg('AES-128-CFB8'))
        self.assertTrue(AESKey.supports_encryption_alg('AES-192-CFB8'))
        self.assertTrue(AESKey.supports_encryption_alg('AES-256-CFB8'))
        self.assertFalse(AESKey.supports_encryption_alg('AES-512-CFB8'))

    def test_supports_encryption_alg_with_gcm(self) -> None:
        """Testing AESKey.supports_encryption_alg with GCM algorithms"""
        self.assertTrue(AESKey.supports_encryption_alg('AES-128-GCM'))
        self.assertTrue(AESKey.supports_encryption_alg('AES-192-GCM'))
        self.assertTrue(AESKey.supports_encryption_alg('AES-256-GCM'))
        self.assertFalse(AESKey.supports_encryption_alg('AES-512-GCM'))

    def test_supports_encryption_alg_with_gcm_siv(self) -> None:
        """Testing AESKey.supports_encryption_alg with GCM-SIV algorithms"""
        self.assertEqual(AESKey.supports_encryption_alg('AES-128-GCM-SIV'),
                         has_gcm_siv)
        self.assertEqual(AESKey.supports_encryption_alg('AES-192-GCM-SIV'),
                         has_gcm_siv)
        self.assertEqual(AESKey.supports_encryption_alg('AES-256-GCM-SIV'),
                         has_gcm_siv)
        self.assertFalse(AESKey.supports_encryption_alg('AES-512-GCM-SIV'))

    def test_supports_encryption_alg_with_unknown_mode(self) -> None:
        """Testing AESKey.supports_encryption_alg with unknown modes"""
        self.assertFalse(AESKey.supports_encryption_alg('AES-128-FOO'))
        self.assertFalse(AESKey.supports_encryption_alg('AES-192-FOO'))
        self.assertFalse(AESKey.supports_encryption_alg('AES-256-FOO'))

    def test_supports_keywrap_alg_with_kw(self) -> None:
        """Testing AESKey.supports_keywrap_alg with KW algorithms"""
        self.assertTrue(AESKey.supports_keywrap_alg('AES-128-KW'))
        self.assertTrue(AESKey.supports_keywrap_alg('AES-192-KW'))
        self.assertTrue(AESKey.supports_keywrap_alg('AES-256-KW'))
        self.assertFalse(AESKey.supports_keywrap_alg('AES-512-KW'))

    def test_supports_keywrap_alg_with_kwp(self) -> None:
        """Testing AESKey.supports_keywrap_alg with KWP algorithms"""
        self.assertTrue(AESKey.supports_keywrap_alg('AES-128-KWP'))
        self.assertTrue(AESKey.supports_keywrap_alg('AES-192-KWP'))
        self.assertTrue(AESKey.supports_keywrap_alg('AES-256-KWP'))
        self.assertFalse(AESKey.supports_keywrap_alg('AES-512-KWP'))

    def test_supports_keywrap_alg_with_unknown_mode(self) -> None:
        """Testing AESKey.supports_keywrap_alg with unknown modes"""
        self.assertFalse(AESKey.supports_keywrap_alg('AES-128-FOO'))
        self.assertFalse(AESKey.supports_keywrap_alg('AES-192-FOO'))
        self.assertFalse(AESKey.supports_keywrap_alg('AES-256-FOO'))


class AESKeyTests(TestCase):
    """Unit tests for AESKey methods.

    Version Added:
        1.0
    """

    def test_decrypt_after_invalidate(self) -> None:
        """Testing AESKey.decrypt after invalidation"""
        with AESKey.generate(key_size=256) as aes_key:
            pass

        self.assertFalse(aes_key.is_valid())

        message = (
            'This AESKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            aes_key.decrypt(
                aad=b'my-aad',
                alg='AES-256-GCM',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xd8\xa6\xad\xb25F.m\xfb\x96'
                    b'\xaf8\\I\x90\xdaY\xddqV\xa2\xa9Dw\x12\xa3\xbfc\xe0'
                    b'\xea\xc8\x95i\n'
                ),
            )

    def test_decrypt_with_truncated_ciphertext(self) -> None:
        """Testing AESKey.decrypt with truncated ciphertext"""
        key_bytes = (
            b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc'
            b'\xe8\xae*\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
        )

        with (AESKey.from_bytes(key_bytes) as aes_key,
              self.assertRaises(DecryptionError)):
            aes_key.decrypt(
                aad=b'my-aad',
                alg='AES-256-GCM',
                ciphertext=b'\00',
            )

    def test_decrypt_with_bad_ciphertext(self) -> None:
        """Testing AESKey.decrypt with bad ciphertext"""
        key_bytes = (
            b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc'
            b'\xe8\xae*\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
        )

        with (AESKey.from_bytes(key_bytes) as aes_key,
              self.assertRaises(DecryptionError)):
            aes_key.decrypt(
                aad=b'my-aad',
                alg='AES-256-GCM',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xd8\xa6\xad\xb25F.m\xfb\x96'
                    b'\xaf8\\I\x90\xdaY\xddqV\xa2\xa9Dw\x12\xa3\xbfc\xe0'
                    b'\xea\xc8\x95i\n'
                ),
            )

    def test_decrypt_with_bad_aad(self) -> None:
        """Testing AESKey.decrypt with bad AAD"""
        key_bytes = (
            b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc'
            b'\xe8\xae*\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
        )

        with (AESKey.from_bytes(key_bytes) as aes_key,
              self.assertRaises(DecryptionError)):
            aes_key.decrypt(
                aad=b'xxx',
                alg='AES-256-GCM',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xb4\x9b3\xce\xcc\xe9w\x97\x01'
                    b'\xf0\x87\x93f\xb3\xee\xa9\xc9\xfb\x1f\x19\xa2:r.%\x1a'
                    b'\xfd\xf7\x80\xa1\x98a\xe7>'
                ),
            )

    def test_encrypt_after_invalidate(self) -> None:
        """Testing AESKey.encrypt after invalidation"""
        with AESKey.generate(key_size=256) as aes_key:
            pass

        self.assertFalse(aes_key.is_valid())

        message = (
            'This AESKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-256-GCM',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

    def test_encrypt_with_unsupported_algorithm(self) -> None:
        """Testing AESKey.encrypt with unsupported algorithm"""
        message = "The algorithm 'AES-256-CFB4' was not supported by this key."

        with (AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key,
              self.assertRaisesRegex(UnsupportedAlgorithmError,
                                     re.escape(message))):
            aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-256-CFB4',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

    def test_encrypt_with_unsupported_key_size(self) -> None:
        """Testing AESKey.encrypt with unsupported algorithm due to key size
        difference
        """
        message = "The algorithm 'AES-256-GCM' was not supported by this key."

        with (AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key,
              self.assertRaisesRegex(UnsupportedAlgorithmError,
                                     re.escape(message))):
            aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-256-GCM',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

    def test_fingerprint_sha256(self) -> None:
        """Testing AESKey.fingerprint_sha256"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            self.assertEqual(
                aes_key.fingerprint_sha256,
                b'\xe4\xf1\xeb\xdaf\x85N\xee.\xe3\xb7\xf0#\xc7hy\x1bb'
                b'\x13\xdc\xea\x91\xe6\xdbA+]\x04\xd8\xd86q')

            self.assertEqual(
                aes_key._fingerprint_sha256,
                b'\xe4\xf1\xeb\xdaf\x85N\xee.\xe3\xb7\xf0#\xc7hy\x1bb'
                b'\x13\xdc\xea\x91\xe6\xdbA+]\x04\xd8\xd86q')

    def test_fingerprint_sha256_after_invalidate(self) -> None:
        """Testing AESKey.fingerprint_sha256 after invalidation"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            aes_key.fingerprint_sha256

        message = (
            'This AESKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            aes_key.fingerprint_sha256

        self.assertIsNone(aes_key._fingerprint_sha256)

    def test_to_bytes(self) -> None:
        """Testing AESKey.to_bytes"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            self.assertEqual(aes_key.to_bytes(), AES_128_KEY_BYTES)

    def test_to_bytes_after_invalidate(self) -> None:
        """Testing AESKey.to_bytes after invalidation"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            pass

        message = (
            'This AESKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            aes_key.to_bytes()

    def test_unwrap_key_after_invalidate(self) -> None:
        """Testing AESKey.unwrap_key after invalidation"""
        with AESKey.generate(key_size=256) as aes_key:
            pass

        self.assertFalse(aes_key.is_valid())

        message = (
            'This AESKey object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b'\x00\x00\x12i\xc1@\xf8\xe8q\xc3Q(3\x05\xba\x9cI\x88'
                    b'\x00\x00|\x127\xc6(\x85h\xa4\x99\xf8\xdb&'
                ),
                alg='AES-128-KW',
                key_cls=AESKey,
            )

    def test_unwrap_key_with_errors(self) -> None:
        """Testing AESKey.unwrap_key with unsupported algorithm"""
        with (AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key,
              self.assertRaises(KeyUnwrapError)):
            aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b'\x00\x00\x12i\xc1@\xf8\xe8q\xc3Q(3\x05\xba\x9cI\x88'
                    b'\x00\x00|\x127\xc6(\x85h\xa4\x99\xf8\xdb&'
                ),
                alg='AES-128-KW',
                key_cls=AESKey,
            )

    def test_unwrap_key_with_unsupported_algorithm(self) -> None:
        """Testing AESKey.unwrap_key with unsupported algorithm"""
        message = "The algorithm 'AES-128-GCM' was not supported by this key."

        with (AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key,
              self.assertRaisesRegex(UnsupportedAlgorithmError,
                                     re.escape(message))):
            aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b'\x07\xe9\x12i\xc1@\xf8\xe8q\xc3Q(3\x05\xba\x9cI\x88'
                    b'\x8e\xd9|\x127\xc6(\x85h\xa4\x99\xf8\xdb&'
                ),
                alg='AES-128-GCM',
                key_cls=AESKey,
            )

    def test_unwrap_key_with_unsupported_key_size(self) -> None:
        """Testing AESKey.unwrap_key with unsupported algorithm due to
        key size difference
        """
        message = "The algorithm 'AES-256-KW' was not supported by this key."

        with (AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key,
              self.assertRaisesRegex(UnsupportedAlgorithmError,
                                     re.escape(message))):
            aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b'\x07\xe9\x12i\xc1@\xf8\xe8q\xc3Q(3\x05\xba\x9cI\x88'
                    b'\x8e\xd9|\x127\xc6(\x85h\xa4\x99\xf8\xdb&'
                ),
                alg='AES-256-KW',
                key_cls=AESKey,
            )

    def test_wrap_key_after_invalidate(self) -> None:
        """Testing AESKey.wrap_key after invalidation"""
        with AESKey.generate(key_size=256) as aes_key:
            pass

        self.assertFalse(aes_key.is_valid())

        message = (
            'This AESKey object has been invalidated and can no '
            'longer be used.'
        )

        with (AESKey.from_bytes(AES_192_KEY_BYTES) as dek,
              self.assertRaisesRegex(InvalidatedError, re.escape(message))):
            aes_key.wrap_key(
                dek,
                alg='AES-256-KWP',
            )

    def test_wrap_key_with_unsupported_key_size(self) -> None:
        """Testing AESKey.wrap_key with unsupported algorithm"""
        message = "The algorithm 'AES-256-KW' was not supported by this key."

        with (AESKey.from_bytes(AES_192_KEY_BYTES) as dek,
              AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key,
              self.assertRaisesRegex(UnsupportedAlgorithmError,
                                     re.escape(message))):
            aes_key.wrap_key(
                dek,
                alg='AES-256-KW',
            )

    def test_wrap_key_with_unsupported_algorithm(self) -> None:
        """Testing AESKey.wrap_key with unsupported algorithm due to key size
        difference
        """
        message = "The algorithm 'AES-256-GCM' was not supported by this key."

        with (AESKey.from_bytes(AES_192_KEY_BYTES) as dek,
              AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key,
              self.assertRaisesRegex(UnsupportedAlgorithmError,
                                     re.escape(message))):
            aes_key.wrap_key(
                dek,
                alg='AES-256-GCM',
            )


class AESKeyCFB8Tests(TestCase):
    """Unit tests for AESKey CFB8 encryption/decryption methods.

    Version Added:
        1.0
    """

    def test_decrypt_with_aes_cfb8_128(self) -> None:
        """Testing AESKey.decrypt with AES-128-CFB8"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                alg='AES-128-CFB8',
                ciphertext=(
                    b'1\xc9\xc2\xde\xb1\xa7R\xa5\xbcJAk\xaf\xee\x91\xf3\x00'
                    b'\xc2\xbe\x0f>\xd6\xb4B\xecSNW\x03\x9b\x0f\xf2\x92\xad'
                )
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_cfb8_192(self) -> None:
        """Testing AESKey.decrypt with AES-192-CFB8"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                alg='AES-192-CFB8',
                ciphertext=(
                    b'1\xc9\xc2\xde\xb1\xa7R\xa5\xbcJAk\xaf\xee\x91\xf3'
                    b'\x10\x97W.\xc2")8$\x0f\xaezV({\xf9\xdb\xe5'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_cfb8_256(self) -> None:
        """Testing AESKey.decrypt with AES-256-CFB8"""
        key_bytes = (
            b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc'
            b'\xe8\xae*\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
        )

        with AESKey.from_bytes(key_bytes) as aes_key:
            plaintext = aes_key.decrypt(
                alg='AES-256-CFB8',
                ciphertext=(
                    b'1\xc9\xc2\xde\xb1\xa7R\xa5\xbcJAk\xaf\xee\x91\xf3\x10'
                    b'\x08a\x95\r,\x90+\xcf\x052E\x184\x99\x15B\xfc'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_encrypt_with_aes_cfb8_128(self) -> None:
        """Testing AESKey.encrypt with AES-128-CFB8"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                alg='AES-128-CFB8',
                nonce=CFB8_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-128-CFB8')
        self.assertEqual(encrypted_data.nonce, CFB8_NONCE)
        self.assertEqual(encrypted_data.tag, b'')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\x00\xc2\xbe\x0f>\xd6\xb4B\xecSNW\x03\x9b\x0f\xf2\x92\xad')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'1\xc9\xc2\xde\xb1\xa7R\xa5\xbcJAk\xaf\xee\x91\xf3\x00\xc2'
            b'\xbe\x0f>\xd6\xb4B\xecSNW\x03\x9b\x0f\xf2\x92\xad')

    def test_encrypt_with_aes_cfb8_192(self) -> None:
        """Testing AESKey.encrypt with AES-192-CFB8"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                alg='AES-192-CFB8',
                nonce=CFB8_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-192-CFB8')
        self.assertEqual(encrypted_data.nonce, CFB8_NONCE)
        self.assertEqual(encrypted_data.tag, b'')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\x10\x97W.\xc2")8$\x0f\xaezV({\xf9\xdb\xe5')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'1\xc9\xc2\xde\xb1\xa7R\xa5\xbcJAk\xaf\xee\x91\xf3\x10\x97W.'
            b'\xc2")8$\x0f\xaezV({\xf9\xdb\xe5')

    def test_encrypt_with_aes_cfb8_256(self) -> None:
        """Testing AESKey.encrypt with AES-256-CFB8"""
        key_bytes = (
            b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc'
            b'\xe8\xae*\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
        )
        with AESKey.from_bytes(key_bytes) as aes_key:
            encrypted_data = aes_key.encrypt(
                alg='AES-256-CFB8',
                nonce=CFB8_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-256-CFB8')
        self.assertEqual(encrypted_data.nonce, CFB8_NONCE)
        self.assertEqual(encrypted_data.tag, b'')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\x10\x08a\x95\r,\x90+\xcf\x052E\x184\x99\x15B\xfc')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'1\xc9\xc2\xde\xb1\xa7R\xa5\xbcJAk\xaf\xee\x91\xf3\x10\x08a'
            b'\x95\r,\x90+\xcf\x052E\x184\x99\x15B\xfc')

    def test_encrypt_with_aes_cfb8_aad(self) -> None:
        """Testing AESKey.encrypt with AES-CFB8 and AAD"""
        key_bytes = (
            b'\x95|\xa3\xd2\x1f\xeaL\xae\xf2\x01\xc8\xaeL\xb0\xcb\xfc'
            b'\xe8\xae*\xb1bC\x0c\xa5]\xaf\xac\xf5\x0b\xabo\xc7'
        )

        message = 'aad is not supported for AES mode CFB8.'

        with (AESKey.from_bytes(key_bytes) as aes_key,
              self.assertRaisesRegex(ValueError, re.escape(message))):
            aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-256-CFB8',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )


class AESKeyGCMTests(TestCase):
    """Unit tests for AESKey GCM encryption/decryption methods.

    Version Added:
        1.0
    """

    def test_decrypt_with_aes_128_gcm(self) -> None:
        """Testing AESKey.decrypt with AES-128-GCM"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                alg='AES-128-GCM',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xd8\xa6\xad\xb25F.m\xfb\x96'
                    b'\xaf8\\I\x90\xdaY\xdd\x19[bA\x9b\x98\xc9\xf0\x13k'
                    b'\xc0.\x8b>\xb6 '
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_128_gcm_aad(self) -> None:
        """Testing AESKey.decrypt with AES-128-GCM and AAD"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                aad=b'my-aad',
                alg='AES-128-GCM',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xd8\xa6\xad\xb25F.m\xfb\x96'
                    b'\xaf8\\I\x90\xdaY\xddqV\xa2\xa9Dw\x12\xa3\xbfc\xe0'
                    b'\xea\xc8\x95i\n'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_192_gcm(self) -> None:
        """Testing AESKey.decrypt with AES-192-GCM"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                alg='AES-192-GCM',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xf5\x18\xce9H&%\xc2\x96\xcd'
                    b'\x04\x1c\x90,\x13q\x15>\x9ci\xbeI\xc4\x18\x8e\xdb!'
                    b'\x8e\xec\xc92\x13\xe7 '
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_192_gcm_aad(self) -> None:
        """Testing AESKey.decrypt with AES-192-GCM and AAD"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                aad=b'my-aad',
                alg='AES-192-GCM',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xf5\x18\xce9H&%\xc2\x96\xcd\x04'
                    b'\x1c\x90,\x13q\x15>\x807\xc0q\x00\xa2\x88\x87\x8bp\xc5'
                    b'\xaa\xff\xe4\x04\x9d'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_256_gcm(self) -> None:
        """Testing AESKey.decrypt with AES-256-GCM"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                alg='AES-256-GCM',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xb4\x9b3\xce\xcc\xe9w\x97\x01'
                    b'\xf0\x87\x93f\xb3\xee\xa9\xc9\xfb\x1f\x19\xa2:r.%\x1a'
                    b'\xfd\xf7\x80\xa1\x98a\xe7>'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_256_gcm_aad(self) -> None:
        """Testing AESKey.decrypt with AES-256-GCM and AAD"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                aad=b'my-aad',
                alg='AES-256-GCM',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xb4\x9b3\xce\xcc\xe9w\x97\x01'
                    b'\xf0\x87\x93f\xb3\xee\xa9\xc9\xfb\x12\x80\x1d2\x90\x15'
                    b'\xed\xad\x0f\x1b\x86\xa01\xf7}q'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_encrypt_with_default_alg(self) -> None:
        """Testing AESKey.encrypt with default algorithm"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                plaintext=b'Please encrypt me.',
                nonce=GCM_NONCE,
            )

        self.assertEqual(encrypted_data.alg, 'AES-256-GCM')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\x1f\x19\xa2:r.%\x1a\xfd\xf7\x80\xa1\x98a\xe7>')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\xb4\x9b3\xce\xcc\xe9w\x97\x01\xf0\x87\x93f\xb3\xee\xa9\xc9\xfb')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\xb4\x9b3\xce\xcc\xe9w\x97\x01\xf0'
            b'\x87\x93f\xb3\xee\xa9\xc9\xfb\x1f\x19\xa2:r.%\x1a\xfd\xf7'
            b'\x80\xa1\x98a\xe7>')

    def test_encrypt_with_default_alg_aad(self) -> None:
        """Testing AESKey.encrypt with default algorithm and AAD"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                plaintext=b'Please encrypt me.',
                aad=b'my-aad',
                nonce=GCM_NONCE,
            )

        self.assertEqual(encrypted_data.alg, 'AES-256-GCM')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\x12\x80\x1d2\x90\x15\xed\xad\x0f\x1b\x86\xa01\xf7}q')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\xb4\x9b3\xce\xcc\xe9w\x97\x01\xf0\x87\x93f\xb3\xee\xa9\xc9\xfb')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\xb4\x9b3\xce\xcc\xe9w\x97\x01\xf0'
            b'\x87\x93f\xb3\xee\xa9\xc9\xfb\x12\x80\x1d2\x90\x15\xed\xad'
            b'\x0f\x1b\x86\xa01\xf7}q')

    def test_encrypt_with_aes_128_gcm(self) -> None:
        """Testing AESKey.encrypt with AES-128-GCM"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                alg='AES-128-GCM',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-128-GCM')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\x19[bA\x9b\x98\xc9\xf0\x13k\xc0.\x8b>\xb6 ')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\xd8\xa6\xad\xb25F.m\xfb\x96\xaf8\\I\x90\xdaY\xdd')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\xd8\xa6\xad\xb25F.m\xfb\x96\xaf8\\I'
            b'\x90\xdaY\xdd\x19[bA\x9b\x98\xc9\xf0\x13k\xc0.\x8b>\xb6 ')

    def test_encrypt_with_aes_128_gcm_aad(self) -> None:
        """Testing AESKey.encrypt with AES-128-GCM and AAD"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-128-GCM',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-128-GCM')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'qV\xa2\xa9Dw\x12\xa3\xbfc\xe0\xea\xc8\x95i\n')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\xd8\xa6\xad\xb25F.m\xfb\x96\xaf8\\I\x90\xdaY\xdd')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\xd8\xa6\xad\xb25F.m\xfb\x96\xaf8\\I'
            b'\x90\xdaY\xddqV\xa2\xa9Dw\x12\xa3\xbfc\xe0\xea\xc8\x95i\n')

    def test_encrypt_with_aes_192_gcm(self) -> None:
        """Testing AESKey.encrypt with AES-192-GCM"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                alg='AES-192-GCM',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-192-GCM')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\x9ci\xbeI\xc4\x18\x8e\xdb!\x8e\xec\xc92\x13\xe7 ')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\xf5\x18\xce9H&%\xc2\x96\xcd\x04\x1c\x90,\x13q\x15>')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\xf5\x18\xce9H&%\xc2\x96\xcd\x04\x1c'
            b'\x90,\x13q\x15>\x9ci\xbeI\xc4\x18\x8e\xdb!\x8e\xec\xc92\x13'
            b'\xe7 ')

    def test_encrypt_with_aes_192_gcm_aad(self) -> None:
        """Testing AESKey.encrypt with AES-192-GCM and AAD"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-192-GCM',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-192-GCM')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\x807\xc0q\x00\xa2\x88\x87\x8bp\xc5\xaa\xff\xe4\x04\x9d')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\xf5\x18\xce9H&%\xc2\x96\xcd\x04\x1c\x90,\x13q\x15>')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\xf5\x18\xce9H&%\xc2\x96\xcd\x04'
            b'\x1c\x90,\x13q\x15>\x807\xc0q\x00\xa2\x88\x87\x8bp\xc5'
            b'\xaa\xff\xe4\x04\x9d')

    def test_encrypt_with_aes_256_gcm(self) -> None:
        """Testing AESKey.encrypt with AES-256-GCM"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                alg='AES-256-GCM',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-256-GCM')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\x1f\x19\xa2:r.%\x1a\xfd\xf7\x80\xa1\x98a\xe7>')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\xb4\x9b3\xce\xcc\xe9w\x97\x01\xf0\x87\x93f\xb3\xee\xa9\xc9\xfb')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\xb4\x9b3\xce\xcc\xe9w\x97\x01\xf0'
            b'\x87\x93f\xb3\xee\xa9\xc9\xfb\x1f\x19\xa2:r.%\x1a\xfd\xf7'
            b'\x80\xa1\x98a\xe7>')

    def test_encrypt_with_aes_256_gcm_aad(self) -> None:
        """Testing AESKey.encrypt with AES-256-GCM and AAD"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-256-GCM',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-256-GCM')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\x12\x80\x1d2\x90\x15\xed\xad\x0f\x1b\x86\xa01\xf7}q')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\xb4\x9b3\xce\xcc\xe9w\x97\x01\xf0\x87\x93f\xb3\xee\xa9\xc9\xfb')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\xb4\x9b3\xce\xcc\xe9w\x97\x01\xf0'
            b'\x87\x93f\xb3\xee\xa9\xc9\xfb\x12\x80\x1d2\x90\x15\xed\xad'
            b'\x0f\x1b\x86\xa01\xf7}q')


@skipUnless(has_gcm_siv,
            'GCM-SIV is not available on this build of cryptography.')
class AESKeyGCMSIVTests(TestCase):
    """Unit tests for AESKey GCM-SIV encryption/decryption methods.

    Version Added:
        1.0
    """

    def test_decrypt_with_aes_128_gcm_siv(self) -> None:
        """Testing AESKey.decrypt with AES-128-GCM-SIV"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                alg='AES-128-GCM-SIV',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\xe6\x1f6bv\xb6\r1\xf1m\x80'
                    b'\xf3\xa1\xe6\t\x14-\x85\xef6\xdf\x04\xa0b\xe0\x87'
                    b'C"81I\x90\x1a\x81'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_128_gcm_siv_aad(self) -> None:
        """Testing AESKey.decrypt with AES-128-GCM-SIV and AAD"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                aad=b'my-aad',
                alg='AES-128-GCM-SIV',
                ciphertext=(
                    b"\n-*\xa9\xe8nB\r6n\xb4h\xba\xa5&'\x90\xb9_@\xc1!"
                    b"\xbcu\x01\xe7$V\xc1\xb6\xa1\xe1\xc2}Z<}\xd3\x8eC"
                    b"\xa0.\xe5j\xbb\x92"
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_192_gcm_siv(self) -> None:
        """Testing AESKey.decrypt with AES-192-GCM-SIV"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                alg='AES-192-GCM-SIV',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h\x10\x8cD\xc5+a\x96}\xdd\xd8'
                    b'\xde\xc4\x99\x93D\x0c\xf1\xe6\xf3J@\x1f\xaf\xc3\xf3'
                    b'\xfb\xe4w\xbe\xdf\xb1\x8760'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_192_gcm_siv_aad(self) -> None:
        """Testing AESKey.decrypt with AES-192-GCM-SIV and AAD"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                aad=b'my-aad',
                alg='AES-192-GCM-SIV',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4ho*\xd3\x93\xa0\xb5a\xafW\xbf'
                    b'\xcdG\x17\x94\xe7\xaf\xa0\xd3\x05\xeaF\xc2\xa2[\xadA'
                    b'\xce4\x82\xb3q2N\xf2'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_256_gcm_siv(self) -> None:
        """Testing AESKey.decrypt with AES-256-GCM-SIV"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                alg='AES-256-GCM-SIV',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h/\xb6<\xfe\xa2\x8c\xd5\x81\xe91@'
                    b'\xe6\xbc\xf7L;\xda\x9f\x8c*\x91\xcd\t\xd5\xa7\xdfB\xf2'
                    b'\xf3Y\xea5\x04w'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_decrypt_with_aes_256_gcm_siv_aad(self) -> None:
        """Testing AESKey.decrypt with AES-256-GCM-SIV and AAD"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            plaintext = aes_key.decrypt(
                aad=b'my-aad',
                alg='AES-256-GCM-SIV',
                ciphertext=(
                    b'\n-*\xa9\xe8nB\r6n\xb4h(\xf6;\x98\xd6Je\xd0~\xb1\x19'
                    b'\x19\x10[\xb9Z\xae\xd8\xd7\x83j\xf4\xad\xdc\x03\x83'
                    b'\xb7\xc5P\xb3\x96\x80|\xaa'
                ),
            )

        self.assertEqual(plaintext, b'Please encrypt me.')

    def test_encrypt_with_aes_128_gcm_siv(self) -> None:
        """Testing AESKey.encrypt with AES-128-GCM-SIV"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                alg='AES-128-GCM-SIV',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-128-GCM-SIV')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\xef6\xdf\x04\xa0b\xe0\x87C"81I\x90\x1a\x81')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\xe6\x1f6bv\xb6\r1\xf1m\x80\xf3\xa1\xe6\t\x14-\x85')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\xe6\x1f6bv\xb6\r1\xf1m\x80\xf3\xa1'
            b'\xe6\t\x14-\x85\xef6\xdf\x04\xa0b\xe0\x87C"81I\x90\x1a\x81')

    def test_encrypt_with_aes_128_gcm_siv_aad(self) -> None:
        """Testing AESKey.encrypt with AES-128-GCM-SIV and AAD"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-128-GCM-SIV',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-128-GCM-SIV')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\xa1\xe1\xc2}Z<}\xd3\x8eC\xa0.\xe5j\xbb\x92')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b"\xba\xa5&'\x90\xb9_@\xc1!\xbcu\x01\xe7$V\xc1\xb6")
        self.assertEqual(
            encrypted_data.ciphertext,
            b"\n-*\xa9\xe8nB\r6n\xb4h\xba\xa5&'\x90\xb9_@\xc1!\xbcu\x01"
            b"\xe7$V\xc1\xb6\xa1\xe1\xc2}Z<}\xd3\x8eC\xa0.\xe5j\xbb\x92")

    def test_encrypt_with_aes_192_gcm_siv(self) -> None:
        """Testing AESKey.encrypt with AES-192-GCM-SIV"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                alg='AES-192-GCM-SIV',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-192-GCM-SIV')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\xf3J@\x1f\xaf\xc3\xf3\xfb\xe4w\xbe\xdf\xb1\x8760')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'\x10\x8cD\xc5+a\x96}\xdd\xd8\xde\xc4\x99\x93D\x0c\xf1\xe6')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h\x10\x8cD\xc5+a\x96}\xdd\xd8\xde\xc4'
            b'\x99\x93D\x0c\xf1\xe6\xf3J@\x1f\xaf\xc3\xf3\xfb\xe4w\xbe\xdf'
            b'\xb1\x8760')

    def test_encrypt_with_aes_192_gcm_siv_aad(self) -> None:
        """Testing AESKey.encrypt with AES-192-GCM-SIV and AAD"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-192-GCM-SIV',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-192-GCM-SIV')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\x05\xeaF\xc2\xa2[\xadA\xce4\x82\xb3q2N\xf2')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'o*\xd3\x93\xa0\xb5a\xafW\xbf\xcdG\x17\x94\xe7\xaf\xa0\xd3')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4ho*\xd3\x93\xa0\xb5a\xafW\xbf\xcdG'
            b'\x17\x94\xe7\xaf\xa0\xd3\x05\xeaF\xc2\xa2[\xadA\xce4\x82'
            b'\xb3q2N\xf2')

    def test_encrypt_with_aes_256_gcm_siv(self) -> None:
        """Testing AESKey.encrypt with AES-256-GCM-SIV"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                alg='AES-256-GCM-SIV',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-256-GCM-SIV')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\x8c*\x91\xcd\t\xd5\xa7\xdfB\xf2\xf3Y\xea5\x04w')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'/\xb6<\xfe\xa2\x8c\xd5\x81\xe91@\xe6\xbc\xf7L;\xda\x9f')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h/\xb6<\xfe\xa2\x8c\xd5\x81\xe91@'
            b'\xe6\xbc\xf7L;\xda\x9f\x8c*\x91\xcd\t\xd5\xa7\xdfB\xf2'
            b'\xf3Y\xea5\x04w')

    def test_encrypt_with_aes_256_gcm_siv_aad(self) -> None:
        """Testing AESKey.encrypt with AES-256-GCM-SIV and AAD"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            encrypted_data = aes_key.encrypt(
                aad=b'my-aad',
                alg='AES-256-GCM-SIV',
                nonce=GCM_NONCE,
                plaintext=b'Please encrypt me.',
            )

        self.assertEqual(encrypted_data.alg, 'AES-256-GCM-SIV')
        self.assertEqual(encrypted_data.nonce, GCM_NONCE)
        self.assertEqual(
            encrypted_data.tag,
            b'\xd7\x83j\xf4\xad\xdc\x03\x83\xb7\xc5P\xb3\x96\x80|\xaa')
        self.assertEqual(
            encrypted_data.raw_ciphertext,
            b'(\xf6;\x98\xd6Je\xd0~\xb1\x19\x19\x10[\xb9Z\xae\xd8')
        self.assertEqual(
            encrypted_data.ciphertext,
            b'\n-*\xa9\xe8nB\r6n\xb4h(\xf6;\x98\xd6Je\xd0~\xb1\x19\x19\x10'
            b'[\xb9Z\xae\xd8\xd7\x83j\xf4\xad\xdc\x03\x83\xb7\xc5P\xb3\x96'
            b'\x80|\xaa')


class AESKeyKWTests(TestCase):
    """Unit tests for AESKey KW keywrap methods.

    Version Added:
        1.0
    """

    def test_unwrap_key_with_aes_128_kw(self) -> None:
        """Testing AESKey.unwrap_key with AES-128-KW"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            dek = aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b'\x07\xe9\x12i\xc1@\xf8\xe8q\xc3Q(3\x05\xba\x9cI\x88'
                    b'\x8e\xd9|\x127\xc6(\x85h\xa4\x99\xf8\xdb&'
                ),
                alg='AES-128-KW',
                key_cls=AESKey,
            )

        self.assertIsInstance(dek, AESKey)
        self.assertEqual(dek.to_bytes(), AES_192_KEY_BYTES)

    def test_unwrap_key_with_aes_192_kw(self) -> None:
        """Testing AESKey.unwrap_key with AES-192-KW"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            dek = aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b'JD\xc5S\xda\t\xc5\xe1fG\xe7\xd8G\x0c\xcfCH\x00\xc16O'
                    b'\xd3@\xdd\x1a\xbb\xc9\xa1\xb1\x9a?\x87\x0b\xa4\xf6r'
                    b'\xcb\xa5o\xe9'
                ),
                alg='AES-192-KW',
                key_cls=AESKey,
            )

        self.assertIsInstance(dek, AESKey)
        self.assertEqual(dek.to_bytes(), AES_256_KEY_BYTES)

    def test_unwrap_key_with_aes_256_kw(self) -> None:
        """Testing AESKey.unwrap_key with AES-256-KW"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            dek = aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b'\xe9mo=\xad\xa7\xf1\x03r\xfe\xcf\xaa<\x16\x06i\xbd'
                    b'\x82\xbb\r\xe2%\xe1\xbd\xa8\x97\xb9U-^\xa5\x1f'
                ),
                alg='AES-256-KW',
                key_cls=AESKey,
            )

        self.assertIsInstance(dek, AESKey)
        self.assertEqual(dek.to_bytes(), AES_192_KEY_BYTES)

    def test_wrap_key_with_aes_128_kw(self) -> None:
        """Testing AESKey.wrap_key with AES-128-KW"""
        with (AESKey.from_bytes(AES_192_KEY_BYTES) as dek,
              AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key):
            wrapped_key_data = aes_key.wrap_key(
                dek,
                alg='AES-128-KW',
            )

        self.assertEqual(wrapped_key_data.alg, 'AES-128-KW')
        self.assertEqual(
            wrapped_key_data.edek,
            b'\x07\xe9\x12i\xc1@\xf8\xe8q\xc3Q(3\x05\xba\x9cI\x88\x8e\xd9'
            b'|\x127\xc6(\x85h\xa4\x99\xf8\xdb&')

    def test_wrap_key_with_aes_192_kw(self) -> None:
        """Testing AESKey.wrap_key with AES-192-KW"""
        with (AESKey.from_bytes(AES_256_KEY_BYTES) as dek,
              AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key):
            wrapped_key_data = aes_key.wrap_key(
                dek,
                alg='AES-192-KW',
            )

        self.assertEqual(wrapped_key_data.alg, 'AES-192-KW')
        self.assertEqual(
            wrapped_key_data.edek,
            b'JD\xc5S\xda\t\xc5\xe1fG\xe7\xd8G\x0c\xcfCH\x00\xc16O\xd3@'
            b'\xdd\x1a\xbb\xc9\xa1\xb1\x9a?\x87\x0b\xa4\xf6r\xcb\xa5o\xe9')

    def test_wrap_key_with_aes_256_kw(self) -> None:
        """Testing AESKey.wrap_key with AES-256-KW"""
        with (AESKey.from_bytes(AES_192_KEY_BYTES) as dek,
              AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key):
            wrapped_key_data = aes_key.wrap_key(
                dek,
                alg='AES-256-KW',
            )

        self.assertEqual(wrapped_key_data.alg, 'AES-256-KW')
        self.assertEqual(
            wrapped_key_data.edek,
            b'\xe9mo=\xad\xa7\xf1\x03r\xfe\xcf\xaa<\x16\x06i\xbd\x82\xbb'
            b'\r\xe2%\xe1\xbd\xa8\x97\xb9U-^\xa5\x1f')


class AESKeyKWPTests(TestCase):
    """Unit tests for AESKey KWP keywrap methods.

    Version Added:
        1.0
    """

    def test_unwrap_key_with_aes_128_kw(self) -> None:
        """Testing AESKey.unwrap_key with AES-128-KWP"""
        with AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key:
            dek = aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b"\xae9\x0ey\x8f'\xc9\xc4Ls\t\x91\xa7}\xa2#\xae\x97\xb3"
                    b"\xea\xa6MH\xac'\xd1\x92\xc6\x92\x80\x16J"
                ),
                alg='AES-128-KWP',
                key_cls=AESKey,
            )

        self.assertIsInstance(dek, AESKey)
        self.assertEqual(dek.to_bytes(), AES_192_KEY_BYTES)

    def test_unwrap_key_with_aes_192_kw(self) -> None:
        """Testing AESKey.unwrap_key with AES-192-KWP"""
        with AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key:
            dek = aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b"\xcfm\xae\xad\xf2\xb2\nf\xb0\xed8\xe0'\x88g;_\xec"
                    b"\xa3\x1bP\x1aV\xd9?\x94\xb0K\xbd\x99\x9dNu\xb9M"
                    b"\x85_\x9e\xb4h"
                ),
                alg='AES-192-KWP',
                key_cls=AESKey,
            )

        self.assertIsInstance(dek, AESKey)
        self.assertEqual(dek.to_bytes(), AES_256_KEY_BYTES)

    def test_unwrap_key_with_aes_256_kw(self) -> None:
        """Testing AESKey.unwrap_key with AES-256-KWP"""
        with AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key:
            dek = aes_key.unwrap_key(
                wrapped_key_bytes=(
                    b'\xe1\x89\x9d\xcd\n\x88\xdfbVA\xa1.\x9a\xc0\x19\xcd\x0e'
                    b'\x13\x9cPw\xc7\xa7\xcd\xd6\xaai\x95;\x9eX\xda'
                ),
                alg='AES-256-KWP',
                key_cls=AESKey,
            )

        self.assertIsInstance(dek, AESKey)
        self.assertEqual(dek.to_bytes(), AES_192_KEY_BYTES)

    def test_wrap_key_with_aes_128_kw(self) -> None:
        """Testing AESKey.wrap_key with AES-128-KWP"""
        with (AESKey.from_bytes(AES_192_KEY_BYTES) as dek,
              AESKey.from_bytes(AES_128_KEY_BYTES) as aes_key):
            wrapped_key_data = aes_key.wrap_key(
                dek,
                alg='AES-128-KWP',
            )

        self.assertEqual(wrapped_key_data.alg, 'AES-128-KWP')
        self.assertEqual(
            wrapped_key_data.edek,
            b"\xae9\x0ey\x8f'\xc9\xc4Ls\t\x91\xa7}\xa2#\xae\x97\xb3"
            b"\xea\xa6MH\xac'\xd1\x92\xc6\x92\x80\x16J")

    def test_wrap_key_with_aes_192_kw(self) -> None:
        """Testing AESKey.wrap_key with AES-192-KWP"""
        with (AESKey.from_bytes(AES_256_KEY_BYTES) as dek,
              AESKey.from_bytes(AES_192_KEY_BYTES) as aes_key):
            wrapped_key_data = aes_key.wrap_key(
                dek,
                alg='AES-192-KWP',
            )

        self.assertEqual(wrapped_key_data.alg, 'AES-192-KWP')
        self.assertEqual(
            wrapped_key_data.edek,
            b"\xcfm\xae\xad\xf2\xb2\nf\xb0\xed8\xe0'\x88g;_\xec\xa3"
            b"\x1bP\x1aV\xd9?\x94\xb0K\xbd\x99\x9dNu\xb9M\x85_\x9e\xb4h")

    def test_wrap_key_with_aes_256_kw(self) -> None:
        """Testing AESKey.wrap_key with AES-256-KWP"""
        with (AESKey.from_bytes(AES_192_KEY_BYTES) as dek,
              AESKey.from_bytes(AES_256_KEY_BYTES) as aes_key):
            wrapped_key_data = aes_key.wrap_key(
                dek,
                alg='AES-256-KWP',
            )

        self.assertEqual(wrapped_key_data.alg, 'AES-256-KWP')
        self.assertEqual(
            wrapped_key_data.edek,
            b'\xe1\x89\x9d\xcd\n\x88\xdfbVA\xa1.\x9a\xc0\x19\xcd\x0e'
            b'\x13\x9cPw\xc7\xa7\xcd\xd6\xaai\x95;\x9eX\xda')
