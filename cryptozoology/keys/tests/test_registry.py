"""Unit tests for cryptozoology.keys.registry.KeyTypeRegistry.

Version Added:
    1.0
"""

from __future__ import annotations

from unittest import TestCase

from cryptozoology.keys.aes import AESKey
from cryptozoology.keys.base import BaseKey
from cryptozoology.keys.ec import ECPrivateKey
from cryptozoology.keys.registry import KeyTypeRegistry


class KeyTypeRegistryTests(TestCase):
    """Unit tests for KeyTypeRegistry.

    Version Added:
        1.0
    """

    def test_get_key_with_found(self) -> None:
        """Testing KeyTypeRegistry.get_key_type with found"""
        registry = KeyTypeRegistry()

        self.assertIs(registry.get_key_type('aes'), AESKey)
        self.assertIs(registry.get_key_type('ec'), ECPrivateKey)

    def test_get_key_with_not_found(self) -> None:
        """Testing KeyTypeRegistry.get_key_type with not found"""
        registry = KeyTypeRegistry()

        self.assertIsNone(registry.get_key_type('xxx'))

    def test_get_for_encryption_alg_with_found(self) -> None:
        """Testing KeyTypeRegistry.get_for_encryption_alg with found"""
        registry = KeyTypeRegistry()
        registry.populate()

        self.assertEqual(registry._enc_key_cache_map, {})

        self.assertIs(registry.get_for_encryption_alg('AES-256-GCM'), AESKey)
        self.assertIs(registry.get_for_encryption_alg('AES-128-CFB8'), AESKey)

        self.assertEqual(
            registry._enc_key_cache_map,
            {
                'AES-256-GCM': AESKey,
                'AES-128-CFB8': AESKey,
            })

    def test_get_for_encryption_alg_with_not_found(self) -> None:
        """Testing KeyTypeRegistry.get_for_encryption_alg with not found"""
        registry = KeyTypeRegistry()

        self.assertIsNone(registry.get_for_encryption_alg('AES-512-GCM'))
        self.assertIsNone(registry.get_for_encryption_alg('AES-256-CFB4'))

    def test_get_for_encryption_alg_uses_cache(self) -> None:
        """Testing KeyTypeRegistry.get_for_encryption_alg uses cached result"""
        registry = KeyTypeRegistry()
        registry.populate()

        registry._enc_key_cache_map['AES-007-ABC'] = AESKey

        self.assertIs(registry.get_for_encryption_alg('AES-007-ABC'), AESKey)

    def test_get_for_encryption_alg_with_cache_overflow(self) -> None:
        """Testing KeyTypeRegistry.get_for_encryption_alg with overflowing
        the cache
        """
        registry = KeyTypeRegistry()
        registry._max_cache_size = 2
        registry.populate()

        self.assertEqual(registry._enc_key_cache_map, {})

        self.assertIs(registry.get_for_encryption_alg('AES-256-GCM'), AESKey)
        self.assertIs(registry.get_for_encryption_alg('AES-128-CFB8'), AESKey)

        self.assertEqual(
            registry._enc_key_cache_map,
            {
                'AES-256-GCM': AESKey,
                'AES-128-CFB8': AESKey,
            })

        # Make AES-256-GCM the most-recently-used.
        self.assertIs(registry.get_for_encryption_alg('AES-256-GCM'), AESKey)

        self.assertEqual(
            registry._enc_key_cache_map,
            {
                'AES-128-CFB8': AESKey,
                'AES-256-GCM': AESKey,
            })

        # Fetch one more, overflowing the cache.
        self.assertIsNone(registry.get_for_encryption_alg('AES-123-XYZ'))

        self.assertEqual(
            registry._enc_key_cache_map,
            {
                'AES-256-GCM': AESKey,
                'AES-123-XYZ': None,
            })

    def test_get_for_keywrap_alg_with_found(self) -> None:
        """Testing KeyTypeRegistry.get_for_keywrap_alg with found"""
        registry = KeyTypeRegistry()
        registry.populate()

        self.assertEqual(registry._keywrap_key_cache_map, {})

        self.assertIs(registry.get_for_keywrap_alg('AES-256-KW'), AESKey)
        self.assertIs(registry.get_for_keywrap_alg('AES-128-KWP'), AESKey)

        self.assertEqual(
            registry._keywrap_key_cache_map,
            {
                'AES-128-KWP': AESKey,
                'AES-256-KW': AESKey,
            })

    def test_get_for_keywrap_alg_with_not_found(self) -> None:
        """Testing KeyTypeRegistry.get_for_keywrap_alg with not found"""
        registry = KeyTypeRegistry()

        self.assertIsNone(registry.get_for_keywrap_alg('AES-256-GCM'))
        self.assertIsNone(registry.get_for_keywrap_alg('AES-512-KW'))

    def test_get_for_keywrap_alg_uses_cache(self) -> None:
        """Testing KeyTypeRegistry.get_for_keywrap_alg uses cached result"""
        registry = KeyTypeRegistry()
        registry.populate()

        registry._keywrap_key_cache_map['AES-007-ABC'] = AESKey

        self.assertIs(registry.get_for_keywrap_alg('AES-007-ABC'), AESKey)

    def test_get_for_keywrap_alg_with_cache_overflow(self) -> None:
        """Testing KeyTypeRegistry.get_for_keywrap_alg with overflowing
        the cache
        """
        registry = KeyTypeRegistry()
        registry._max_cache_size = 2
        registry.populate()

        self.assertEqual(registry._keywrap_key_cache_map, {})

        self.assertIs(registry.get_for_keywrap_alg('AES-256-KW'), AESKey)
        self.assertIs(registry.get_for_keywrap_alg('AES-128-KWP'), AESKey)

        self.assertEqual(
            registry._keywrap_key_cache_map,
            {
                'AES-128-KWP': AESKey,
                'AES-256-KW': AESKey,
            })

        # Make AES-256-KW the most-recently-used.
        self.assertIs(registry.get_for_keywrap_alg('AES-256-KW'), AESKey)

        self.assertEqual(
            registry._keywrap_key_cache_map,
            {
                'AES-256-KW': AESKey,
                'AES-128-KWP': AESKey,
            })

        # Fetch one more, overflowing the cache.
        self.assertIsNone(registry.get_for_keywrap_alg('AES-123-XYZ'))

        self.assertEqual(
            registry._keywrap_key_cache_map,
            {
                'AES-256-KW': AESKey,
                'AES-123-XYZ': None,
            })

    def test_registration_invalidates_caches(self) -> None:
        """Testing KeyTypeRegistry.register invalidates algorithm caches"""
        class MyKeyType(BaseKey):
            key_type_id = 'abc123'

        registry = KeyTypeRegistry()
        registry.populate()

        registry._enc_key_cache_map['AES-007-ABC'] = AESKey
        registry._keywrap_key_cache_map['AES-007-DEF'] = AESKey

        registry.register(MyKeyType)

        self.assertEqual(registry._enc_key_cache_map, {})
        self.assertEqual(registry._keywrap_key_cache_map, {})

    def test_unregistration_invalidates_caches(self) -> None:
        """Testing KeyTypeRegistry.unregister invalidates algorithm caches"""
        registry = KeyTypeRegistry()
        registry.populate()

        registry._enc_key_cache_map['AES-007-ABC'] = AESKey
        registry._keywrap_key_cache_map['AES-007-DEF'] = AESKey

        registry.unregister(AESKey)

        self.assertEqual(registry._enc_key_cache_map, {})
        self.assertEqual(registry._keywrap_key_cache_map, {})

    def test_reset_invalidates_caches(self) -> None:
        """Testing KeyTypeRegistry.reset invalidates algorithm caches"""
        registry = KeyTypeRegistry()
        registry.populate()

        registry._enc_key_cache_map['AES-007-ABC'] = AESKey
        registry._keywrap_key_cache_map['AES-007-DEF'] = AESKey

        registry.reset()

        self.assertEqual(registry._enc_key_cache_map, {})
        self.assertEqual(registry._keywrap_key_cache_map, {})
