"""Tests for cryptozoology.keys.base."""

from __future__ import annotations

import hashlib

import pytest

from cryptozoology.errors import InvalidatedError
from cryptozoology.keys.base import BaseKey


class _DummyKey(BaseKey):
    """A minimal concrete BaseKey used to test shared base behavior."""

    def __init__(self, data: (bytes | None), **kwargs: object) -> None:
        super().__init__(**kwargs)

        self._data = data

    def is_valid(self) -> bool:
        return self._data is not None

    def get_fingerprint_bytes(self) -> bytes:
        self.assert_valid()

        assert self._data is not None

        return self._data

    def invalidate(self) -> None:
        self._data = None


class TestBaseKey:
    def test_key_id_defaults_to_none(self) -> None:
        assert _DummyKey(b'data').key_id is None

    def test_key_id_stored(self) -> None:
        assert _DummyKey(b'data', key_id='my-kid').key_id == 'my-kid'

    def test_is_valid(self) -> None:
        key = _DummyKey(b'data')

        assert key.is_valid()

        key.invalidate()

        assert not key.is_valid()

    def test_assert_valid_raises_when_invalidated(self) -> None:
        key = _DummyKey(b'data')
        key.invalidate()

        with pytest.raises(InvalidatedError):
            key.assert_valid()

    def test_fingerprint_sha256(self) -> None:
        key = _DummyKey(b'some-key-material')

        assert (
            key.fingerprint_sha256 ==
            hashlib.sha256(b'some-key-material').digest()
        )

    def test_fingerprint_sha256_is_cached(self) -> None:
        key = _DummyKey(b'some-key-material')

        fingerprint1 = key.fingerprint_sha256
        key._data = b'different-key-material'
        fingerprint2 = key.fingerprint_sha256

        assert fingerprint1 == fingerprint2
