"""Object invalidation management.

Version Added:
    1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptozoology.errors import InvalidatedError

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Self


class InvalidatableMixin:
    """A mixin class that makes an object invalidatable.

    This will invalidate the object when it's garbage collected, or when
    used as a context manager and the context exits.

    The subclass is responsible for determining what happens during
    invalidation.

    Version Added:
        1.0
    """

    def __del__(self) -> None:
        """Handle deletion of the object's instance.

        This will perform an invalidation to clear state.
        """
        self.invalidate()

    def __enter__(self) -> Self:
        """Enter the object's context.

        Once exited, the object will be invalidated.

        Returns:
            InvalidatableMixin:
            This instance, as the context value.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The object is no longer valid.
        """
        self.assert_valid()

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit the object's context.

        This will invalidate the context.

        Args:
            exc_type (type):
                The exception type, if an exception was raised.

            exc_value (BaseException):
                The exception value, if an exception was raised.

            traceback (types.TracebackType):
                The traceback, if an exception was raised.
        """
        self.invalidate()

    def assert_valid(self) -> None:
        """Assert that the object is still valid.

        This should be called internally before performing operations using
        state that might become invalidated.

        Raises:
            cryptozoology.errors.InvalidatedError:
                The object is no longer valid.
        """
        if not self.is_valid():
            name = type(self).__name__

            raise InvalidatedError(
                f'This {name} object has been invalidated and can no '
                f'longer be used.'
            )

    def is_valid(self) -> bool:
        """Return whether this object is still valid.

        This must be implemented by subclasses.

        Returns:
            bool:
            ``True`` if the object is valid. ``False`` if it is invalid.
        """
        raise NotImplementedError

    def invalidate(self) -> None:
        """Invalidate the object.

        Subclasses must override this. They must take care to not assume
        all instance attributes are present or complete, as this may be
        called as a result of an exception during construction or
        partially-cleaned up state during destruction.

        It may also be called more than once.
        """
        raise NotImplementedError


class SensitiveBytes(InvalidatableMixin, bytearray):
    """A byte array that clears once invalidated.

    This can be used as a context manager, clearing the resulting array
    once the context closes in order to ensure sensitive data isn't
    sitting around in memory.

    Version Added:
        1.0
    """

    def is_valid(self) -> bool:
        """Return whether the bytes are still valid.

        Returns:
            bool:
            ``True`` if valid, or ``False`` if cleared.
        """
        return bool(self)

    def invalidate(self) -> None:
        """Invalidate the bytes.

        This will clear the bytes from memory.
        """
        self.clear()
