# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Class for managing a cache of nonces.

"""

import time
import heapq
import threading


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

    def __init__(self, nonce_timeout=None, id_timeout=None, max_size=None):
        if nonce_timeout is None:
            nonce_timeout = 60
        if id_timeout is None:
            id_timeout = nonce_timeout
        self.nonce_timeout = nonce_timeout
        self.id_timeout = id_timeout
        self.max_size = max_size
        self._cache_lock = threading.Lock()
        self._ids = Cache(id_timeout, max_size, self._cache_lock)

    def __len__(self):
        return sum(len(self._ids.get(key)[1]) for key in self._ids)

    def is_fresh(self, id, timestamp, nonce):
        """Check if the given timestamp+nonce is fresh for the given id."""
        # Get the clock skew to use for calculations.
        # If we've never seen this id before, it must be fresh.
        try:
            (skew, nonces) = self._ids.get(id)
        except KeyError:
            return True
        # If the adjusted timestamps is too old or too new, then
        # we can reject it without even looking at the nonce.
        timestamp = timestamp + skew
        if abs(timestamp - time.time()) >= self.nonce_timeout:
            return False
        # Otherwise, we need to look in the per-id nonce cache.
        return nonce not in nonces

    def add_nonce(self, id, timestamp, nonce):
        """Add the given nonce to the cache."""
        # If this is the first nonce for that id, calculate
        # the clock skew and initialise the cache of used nonces.
        # This could race if multiple requests come in for the
        # same id, but we consider it an acceptable risk.
        try:
            (skew, nonces) = self._ids.get(id)
        except KeyError:
            server_time = time.time()
            skew = server_time - timestamp
            nonces = Cache(self.nonce_timeout, self.max_size, self._cache_lock)
            self._ids.set(id, (skew, nonces))
        # Store the nonce according to the adjusted time.
        timestamp = timestamp + skew
        nonces.set(nonce, True, timestamp)


class Cache(object):
    """A simple in-memory cache with automatic timestamp-based purging.

    This class provides a very simple in-memory cache.  Along with a dict
    for fast lookup of cached items, it maintains a queue of items and their
    timestamps so that they can be purged in order as they expire.
    """

    def __init__(self, timeout, max_size=None, purge_lock=None):
        assert not max_size or max_size > 0
        self.items = {}
        self.timeout = timeout
        self.max_size = max_size
        self.purge_lock = purge_lock or threading.Lock()
        self.purge_queue = []

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        now = time.time()
        for key, (timestamp, value) in self.items.iteritems():
            if timestamp + self.timeout >= now:
                yield key

    def __contains__(self, key):
        try:
            timestamp, _ = self.items[key]
        except KeyError:
            return False
        if timestamp + self.timeout < time.time():
            return False
        return True

    def get(self, key):
        timestamp, value = self.items[key]
        if timestamp + self.timeout < time.time():
            raise KeyError(key)
        return value

    def set(self, key, value, timestamp=None):
        now = time.time()
        if timestamp is None:
            timestamp = now
        with self.purge_lock:
            # This try-except catches the case where we purge
            # all items from the queue, producing an IndexError.
            try:
                # Ensure we stay below max_size, if defined.
                if self.max_size:
                    while len(self.items) >= self.max_size:
                        (_, old_key) = heapq.heappop(self.purge_queue)
                        del self.items[old_key]
                # Purge a few expired items to make room.
                # Don't purge *all* of them, so we don't pause for too long.
                purge_deadline = now - self.timeout
                for _ in xrange(5):
                    (old_timestamp, old_key) = self.purge_queue[0]
                    if old_timestamp >= purge_deadline:
                        break
                    heapq.heappop(self.purge_queue)
                    del self.items[old_key]
            except IndexError:
                pass
            # Add the new item into both queue and map.
            self.items[key] = (timestamp, value)
            heapq.heappush(self.purge_queue, (timestamp, key))
