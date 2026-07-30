"""Unit tests for cryptozoology.utils.invalidation.InvalidatableMixin.

Version Added:
    1.0
"""

from __future__ import annotations

from unittest import TestCase

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

    def test_context(self) -> None:
        """Testing InvalidatableMixin as context manager"""
        tracking: set[str] = set()

        with _MyObject(tracking) as obj:
            self.assertNotIn('invalidated', tracking)
            self.assertTrue(obj.is_valid())

        self.assertIn('invalidated', tracking)
        self.assertFalse(obj.is_valid())

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
