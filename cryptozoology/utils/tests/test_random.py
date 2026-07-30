"""Unit tests for cryptozoology.utils.random.

Version Added:
    1.0
"""

from __future__ import annotations

from unittest import TestCase

from cryptozoology.utils.random import (AES_NONCE_SIZE,
                                        AES_SALT_SIZE,
                                        generate_aes_nonce,
                                        generate_aes_salt,
                                        generate_nonce,
                                        generate_salt)


class TestGenerateAESNonce(TestCase):
    """Unit tests for generate_aes_nonce.

    Version Added:
        1.0
    """

    def test_size(self) -> None:
        """Testing generate_aes_nonce result size"""
        assert len(generate_aes_nonce()) == AES_NONCE_SIZE


class TestGenerateAESSalt(TestCase):
    """Unit tests for generate_nonce.

    Version Added:
        1.0
    """

    def test_size(self) -> None:
        """Testing generate_aes_salt result size"""
        assert len(generate_aes_salt()) == AES_SALT_SIZE


class GenerateNonceTests(TestCase):
    """Unit tests for generate_nonce.

    Version Added:
        1.0
    """

    def test_size(self) -> None:
        """Testing generate_nonce result size"""
        assert len(generate_nonce(16)) == 16

    def test_uniqueness(self) -> None:
        """Testing generate_nonce randomness"""
        assert generate_nonce(16) != generate_nonce(16)


class TestGenerateSalt(TestCase):
    """Unit tests for generate_salt.

    Version Added:
        1.0
    """

    def test_size(self) -> None:
        """Testing generate_salt result size"""
        assert len(generate_salt(16)) == 16

    def test_uniqueness(self) -> None:
        """Testing generate_salt randomness"""
        assert generate_salt(16) != generate_salt(16)
