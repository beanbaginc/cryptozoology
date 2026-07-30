"""Unit tests for cryptozoology.utils.invalidation.SensitiveBytes.

Version Added:
    1.0
"""

from __future__ import annotations

from unittest import TestCase

from cryptozoology.utils.invalidation import SensitiveBytes


class SensitiveBytesTests(TestCase):
    """Unit tests for SensitiveBytes.

    Version Added:
        1.0
    """

    def test_context(self) -> None:
        """Testing SensitiveBytes as context manager"""
        with SensitiveBytes(b'foo') as obj:
            self.assertTrue(obj.is_valid())
            self.assertEqual(obj, b'foo')

        self.assertFalse(obj.is_valid())
        self.assertEqual(obj, b'')
