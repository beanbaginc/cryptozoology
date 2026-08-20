"""Unit tests for cryptozoology.utils.invalidation.InvalidatableMixin.

Version Added:
    1.0
"""

from __future__ import annotations

import re
from unittest import TestCase

from cryptozoology.errors import InvalidatedError
from cryptozoology.utils.invalidation import InvalidatableMixin


class _MyObject(InvalidatableMixin):
    def __init__(
        self,
        tracking: set[str],
    ) -> None:
        super().__init__()

        self.tracking = tracking

    def is_valid(self) -> bool:
        return 'invalidated' not in self.tracking

    def invalidate(self) -> None:
        self.tracking.add('invalidated')


class InvalidatableMixinTests(TestCase):
    """Unit tests for InvalidatableMixin.

    Version Added:
        1.0
    """

    def test_out_of_scope(self) -> None:
        """Testing InvalidatableMixin with object out of scope"""
        tracking: set[str] = set()

        obj = _MyObject(tracking)
        self.assertNotIn('invalidated', tracking)
        self.assertTrue(obj.is_valid())

        obj = None
        self.assertIn('invalidated', tracking)

    def test_assert_valid_with_valid(self) -> None:
        """Testing InvalidatableMixin.assert_valid when valid"""
        obj = _MyObject(set())

        # This should not raise an exception.
        obj.assert_valid()

        self.assertTrue(obj.is_valid())

    def test_assert_valid_with_invalid(self) -> None:
        """Testing InvalidatableMixin.assert_valid when invalid"""
        obj = _MyObject(set())
        obj.invalidate()

        message = (
            'This _MyObject object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            obj.assert_valid()

    def test_context(self) -> None:
        """Testing InvalidatableMixin as context manager"""
        tracking: set[str] = set()

        with _MyObject(tracking) as obj:
            self.assertNotIn('invalidated', tracking)
            self.assertTrue(obj.is_valid())

        self.assertIn('invalidated', tracking)
        self.assertFalse(obj.is_valid())

    def test_context_after_invalidation(self) -> None:
        """Testing InvalidatableMixin as context manager after invalidation"""
        with _MyObject(set()) as obj:
            pass

        message = (
            'This _MyObject object has been invalidated and can no '
            'longer be used.'
        )

        with self.assertRaisesRegex(InvalidatedError, re.escape(message)):
            with obj:
                pass

    def test_context_with_exception(self) -> None:
        """Testing InvalidatableMixin as context manager with an exception
        raised
        """
        tracking: set[str] = set()
        obj = None

        with self.assertRaises(ValueError):
            with _MyObject(tracking) as obj:
                self.assertNotIn('invalidated', tracking)
                self.assertTrue(obj.is_valid())

                raise ValueError()

        assert obj is not None
        self.assertIn('invalidated', tracking)
        self.assertFalse(obj.is_valid())
