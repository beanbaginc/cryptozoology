"""Tests for cryptozoology.utils.encoding.

Version Added:
    1.0
"""

from __future__ import annotations

import re
from unittest import TestCase

from cryptozoology.utils.encoding import (b64u_decode,
                                          b64u_encode,
                                          build_length_prefixed_bytes)


class B64UDecodeTests(TestCase):
    """Unit tests for b64u_decode.

    Version Added:
        1.0
    """

    def test_with_string(self) -> None:
        """Testing b64u_decode"""
        self.assertEqual(b64u_decode('AQID'),
                         b'\x01\x02\x03')

    def test_with_omitted_padding(self) -> None:
        """Testing b64u_encode with omitted padding"""
        self.assertEqual(b64u_decode('AQ'),
                         b'\x01')

    def test_with_urlsafe_values(self) -> None:
        """Testing b64u_decode with - and _"""
        self.assertEqual(b64u_decode('-_-_'),
                         b'\xfb\xff\xbf')

    def test_with_empty_string(self) -> None:
        """Testing b64u_decode with empty string"""
        self.assertEqual(b64u_decode(''), b'')

    def test_with_invalid_type(self) -> None:
        """Testing b64u_decode with invalid type"""
        message = "b64u_decode takes str, not <class 'bytes'>."

        with self.assertRaisesRegex(TypeError, re.escape(message)):
            b64u_decode(b'foo')  # type: ignore


class B64UEncodeTests(TestCase):
    """Unit tests for b64u_encode.

    Version Added:
        1.0
    """

    def test_with_bytes(self) -> None:
        """Testing b64u_encode with bytes string"""
        self.assertEqual(b64u_encode(b'\x01\x02\x03'),
                         'AQID')

    def test_with_bytearray(self) -> None:
        """Testing b64u_encode with bytearray"""
        self.assertEqual(b64u_encode(bytearray([1, 2, 3])),
                         'AQID')

    def test_with_memoryview(self) -> None:
        """Testing b64u_encode with memoryview"""
        b = b'--\x01\x02\x03--'
        memview = memoryview(b)
        memview_segment = memview[2:-2]

        self.assertIsInstance(memview_segment, memoryview)

        self.assertEqual(b64u_encode(memview), 'LS0BAgMtLQ')
        self.assertEqual(b64u_encode(memview_segment), 'AQID')

    def test_omits_padding(self) -> None:
        """Testing b64u_encode omits "=" padding"""
        self.assertEqual(b64u_encode(b'\x01'),
                         'AQ')

    def test_with_urlsafe_values(self) -> None:
        """Testing b64u_encode uses - and _ instead of / and +"""
        self.assertEqual(b64u_encode(b'\xfb\xff\xbf'),
                         '-_-_')

    def test_with_empty_string(self) -> None:
        """Testing b64u_encode with empty string"""
        self.assertEqual(b64u_encode(b''), '')

    def test_with_invalid_type(self) -> None:
        """Testing b64u_encode with invalid type"""
        message = "b64u_encode takes bytes, not <class 'str'>."

        with self.assertRaisesRegex(TypeError, re.escape(message)):
            b64u_encode('foo')  # type: ignore


class TestBuildLengthPrefixedBytes(TestCase):
    """Testing build_length_prefixed_bytes.

    Version Added:
        1.0
    """

    def test_with_string(self) -> None:
        """Testing build_length_prefixed_bytes"""
        self.assertEqual(build_length_prefixed_bytes(b'hello world'),
                         b'\x00\x00\x00\x0bhello world')

    def test_with_empty_string(self) -> None:
        """Testing build_length_prefixed_bytes with empty string"""
        self.assertEqual(build_length_prefixed_bytes(b''),
                         b'\x00\x00\x00\x00')
