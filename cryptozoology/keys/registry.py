"""A registry of available key types.

Version Added:
    1.0
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from registries import Registry

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from cryptozoology.keys.base import BaseKey


class KeyTypeRegistry(Registry[type['BaseKey']]):
    """A registry managing types of encryption or signing keys.

    Version Added:
        1.0
    """

    lookup_attrs = ('key_type_id',)

    ######################
    # Instance variables #
    ######################

    #: A cache of encryption algorithms to key type results.
    _enc_key_cache_map: OrderedDict[str, type[BaseKey] | None]

    #: A cache of keywrap algorithms to key type results.
    _keywrap_key_cache_map: OrderedDict[str, type[BaseKey] | None]

    #: The maximum size of any of the lookup caches.
    _max_cache_size: int

    def __init__(self) -> None:
        """Initialize the registry."""
        super().__init__()

        self._max_cache_size = 128
        self._reset_caches()

    def get_key_type(
        self,
        key_type_id: str,
    ) -> type[BaseKey] | None:
        """Return a key type with the given ID.

        Args:
            key_type_id (str):
                The ID of the type of key.

        Returns:
            type:
            The key class, or ``None`` if not found.
        """
        return self.get_or_none(key_type_id=key_type_id)

    def get_for_encryption_alg(
        self,
        alg: str,
    ) -> type[BaseKey] | None:
        """Return the key type supporting an encryption algorithm.

        Args:
            alg (str):
                The algorithm to check for.

        Returns:
            type:
            The key handling this encryption algorithm, or ``None`` if not
            found.
        """
        self.populate()

        with self._lock:
            return self._get_or_add_cached(
                key=alg,
                cache=self._enc_key_cache_map,
                is_item_match=(
                    lambda key_cls:
                    key_cls.supports_encryption_alg(alg)
                ),
            )

    def get_for_keywrap_alg(
        self,
        alg: str,
    ) -> type[BaseKey] | None:
        """Return the key type supporting a keywrap algorithm.

        Args:
            alg (str):
                The algorithm to check for.

        Returns:
            type:
            The key handling this keywrap algorithm, or ``None`` if not found.
        """
        self.populate()

        with self._lock:
            return self._get_or_add_cached(
                key=alg,
                cache=self._keywrap_key_cache_map,
                is_item_match=(
                    lambda key_cls:
                    key_cls.supports_keywrap_alg(alg)
                ),
            )

    def get_defaults(self) -> Iterable[type[BaseKey]]:
        """Return the default key classes in Cryptozoology.

        Yields:
            type:
            Each default key class.
        """
        from cryptozoology.keys.aes import AESKey
        from cryptozoology.keys.ec import ECPrivateKey

        yield AESKey
        yield ECPrivateKey

    def on_item_registered(self, *args) -> None:
        """Handle extra steps after registering an item.

        This clears the algorithm caches whenever an item is registered.

        Args:
            *args (tuple, unused):
                Unused arguments passed to the handler.
        """
        self._reset_caches()

    def on_item_unregistered(self, *args) -> None:
        """Handle extra steps after unregistering an item.

        This clears the algorithm caches whenever an item is unregistered.

        Args:
            *args (tuple, unused):
                Unused arguments passed to the handler.
        """
        self._reset_caches()

    def _get_or_add_cached(
        self,
        *,
        key: str,
        cache: OrderedDict[str, type[BaseKey] | None],
        is_item_match: Callable[[type[BaseKey]], bool],
    ) -> type[BaseKey] | None:
        """Return an item from a cache, adding from the registry if missing.

        If the item is not present in the cache, this will iterate through
        all items in the registry and allow the caller to return whether the
        item is a match. The result (either a matched item or ``None``) will
        be added to the cache.

        If the cache grows beyond a maximum size (:py:attr:`_max_cache_size`),
        the least-recently-used item in the cache will be removed.

        This must be run in a lock.

        Args:
            key (str):
                The cache key used as the lookup value.

            cache (collections.OrderedDict):
                The ordered dictionary used as a cache.

            is_item_match (callable):
                The callback to call for each item to determine a match.

        Returns:
            type:
            The resulting key class, or ``None`` if one was not found.
        """
        key_cls: type[BaseKey] | None

        try:
            key_cls = cache[key]

            # The item was found, so move it to the end of the cache
            # (as the most-recently-used).
            cache.move_to_end(key)
        except KeyError:
            # Loop through all items in the cache, determining if any of
            # them is a match.
            for key_cls in self:
                if is_item_match(key_cls):
                    break
            else:
                # The item was not found.
                key_cls = None

            # Store the result back in the cache.
            cache[key] = key_cls

            if len(cache) > self._max_cache_size:
                # The cache has grown beyond the maximum size. Shrink
                # it.
                cache.popitem(last=False)

        return key_cls

    def _reset_caches(self) -> None:
        """Reset the algorithm lookup caches."""
        # Fully replace these instances. This is fast and will guarantee new
        # operations are working on fresh caches, irrespective of locks.
        self._enc_key_cache_map = OrderedDict()
        self._keywrap_key_cache_map = OrderedDict()


#: A registry for managing key types.
#:
#: Version Added:
#:     1.0
key_type_registry = KeyTypeRegistry()
