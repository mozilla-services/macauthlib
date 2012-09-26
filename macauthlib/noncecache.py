# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Class for managing a cache of nonces.

"""

import time
import heapq
import threading
import collections


DEFAULT_NONCE_TTL = 30  # thirty seconds
DEFAULT_ID_TTL = 3600   # one hour


class KeyExistsError(KeyError):
    """Error raised when trying to add a key that already exists."""

    def __init__(self, key, value):
        msg = "Key %r already exists" % (key,)
        super(KeyExistsError, self).__init__(msg)
        self.key = key
        self.value = value


class NonceCache(object):
    """Object for managing a cache of used nonce values.

    This class allow easy timestamp-based management of client-generated
    nonces according to the rules of RFC-TODO:

        * Maintain a measure of clock skew for each MAC id.
        * Reject nonces with a timestamp outside the configured range.
        * Reject nonces that have already been seen.

    It supports an optional max_size argument to limit the number of items
    stored per id and the total number of ids.  If given then items may be
    removed from the cache even if they have not expired, possibly opening
    the server up to replay attacks.
    """

    def __init__(self, nonce_ttl=None, id_ttl=None, max_size=None):
        if nonce_ttl is None:
            nonce_ttl = DEFAULT_NONCE_TTL
        if id_ttl is None:
            id_ttl = DEFAULT_ID_TTL
        self.nonce_ttl = nonce_ttl
        self.id_ttl = id_ttl
        self.max_size = max_size
        self._cache_lock = threading.Lock()
        self._ids = Cache(id_ttl, max_size, self._cache_lock)

    def __len__(self):
        return sum(len(self._ids.get(key)[1]) for key in self._ids)

    def check_nonce(self, id, timestamp, nonce):
        """Check if the given timestamp+nonce is fresh for the given id.

        This method checks that the given timestamp+nonce has not previously
        been seen for the given id.  It returns True if the nonce is fresh
        and False if not.

        Fresh nonces are added to the cache, so that subsequent checks of the
        same nonce will return False.
        """
        # Get the clock skew to use for calculations.
        # If no skew is cached, calculate it.
        try:
            (skew, nonces) = self._ids.get(id)
        except KeyError:
            server_time = time.time()
            skew = server_time - timestamp
            nonces = Cache(self.nonce_ttl, self.max_size, self._cache_lock)
            # Insertion could race if multiple requests come in for an id.
            try:
                self._ids.set(id, (skew, nonces))
            except KeyExistsError, exc:     # pragma nocover
                (skew, nonces) = exc.value  # pragma nocover
        # If the adjusted timestamp is too old or too new, then
        # we can reject it without even looking at the nonce.
        # XXX TODO: we really need a monotonic clock here.
        # If the system time gets adjusted then we could be in trouble.
        timestamp = timestamp + skew
        if abs(timestamp - time.time()) >= self.nonce_ttl:
            return False
        # Otherwise, we need to look in the per-id nonce cache.
        if nonce in nonces:
            return False
        # The nonce is fresh, add it into the cache.
        nonces.set(nonce, True, timestamp)
        return True


CacheItem = collections.namedtuple("CacheItem", "value timestamp")


class Cache(object):
    """A simple in-memory cache with automatic timestamp-based purging.

    This class provides a very simple in-memory cache.  Along with a dict
    for fast lookup of cached values, it maintains a queue of values and their
    timestamps so that they can be purged in order as they expire.
    """

    def __init__(self, ttl, max_size=None, purge_lock=None):
        assert not max_size or max_size > 0
        self.items = {}
        self.ttl = ttl
        self.max_size = max_size
        self.purge_lock = purge_lock or threading.Lock()
        self.purge_queue = []

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        now = time.time()
        for key, item in self.items.iteritems():
            if item.timestamp + self.ttl >= now:
                yield key

    def __contains__(self, key):
        try:
            item = self.items[key]
        except KeyError:
            return False
        if item.timestamp + self.ttl < time.time():
            return False
        return True

    def get(self, key):
        item = self.items[key]
        if item.timestamp + self.ttl < time.time():
            raise KeyError(key)
        return item.value

    def set(self, key, value, timestamp=None):
        now = time.time()
        if timestamp is None:
            timestamp = now
        purge_deadline = now - self.ttl
        item = CacheItem(value, timestamp)
        with self.purge_lock:
            # Refuse to set duplicate keys in the cache, unless it has expired.
            old_item = self.items.get(key)
            if old_item is not None and old_item.timestamp >= purge_deadline:
                raise KeyExistsError(key, old_item.value)
            # This try-except catches the case where we purge
            # all items from the queue, producing an IndexError.
            try:
                # Ensure we stay below max_size, if defined.
                if self.max_size:
                    while len(self.items) >= self.max_size:
                        self._purge_item()
                # Purge a few expired items to make room.
                # Don't purge *all* of them, so we don't pause for too long.
                for _ in xrange(5):
                    (old_timestamp, old_key) = self.purge_queue[0]
                    if old_timestamp >= purge_deadline:
                        break
                    self._purge_item()
            except IndexError:
                pass
            # Add the new item into both queue and map.
            self.items[key] = item
            heapq.heappush(self.purge_queue, (timestamp, key))

    def _purge_item(self):
        """Purge the topmost item in the queue."""
        # We have to take a little care here, because the entry in self.items
        # might have overwritten the entry which appears at head of queue.
        # Check that timestamps match before purging.
        (timestamp, key) = heapq.heappop(self.purge_queue)
        item = self.items.pop(key, None)
        if item is not None and item.timestamp != timestamp:
            self.items[key] = item  # pragma nocover
