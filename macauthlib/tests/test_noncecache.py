# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
import time

from macauthlib.noncecache import NonceCache, Cache, KeyExistsError


class TestNonceCache(unittest.TestCase):

    def test_default_ttl_values(self):
        nc = NonceCache()
        self.assertEquals(nc.nonce_ttl,  30)
        self.assertEquals(nc.id_ttl,  60 * 60)

    def test_operation(self):
        timeout = 0.1
        nc = NonceCache(nonce_ttl=timeout, id_ttl=1)
        # Initially nothing is cached, so all nonces as fresh.
        self.assertEquals(nc.nonce_ttl, 0.1)
        self.assertEquals(len(nc), 0)
        self.assertTrue(nc.is_fresh("id", time.time(), "abc"))
        # After adding a nonce, it should contain just that item.
        nc.add_nonce("id", time.time(), "abc")
        self.assertEquals(len(nc), 1)
        self.assertFalse(nc.is_fresh("id", time.time(), "abc"))
        self.assertTrue(nc.is_fresh("id", time.time(), "xyz"))
        # After the timeout passes, the nonce should be expired.
        time.sleep(timeout)
        self.assertTrue(nc.is_fresh("id", time.time(), "abc"))
        # Writing to the cache purges expired nonces but keeps valid ones.
        nc.add_nonce("id", time.time(), "abc")
        time.sleep(timeout / 2)
        nc.add_nonce("id", time.time(), "def")
        self.assertFalse(nc.is_fresh("id", time.time(), "abc"))
        self.assertFalse(nc.is_fresh("id", time.time(), "def"))
        self.assertTrue(nc.is_fresh("id", time.time(), "xyz"))
        time.sleep(timeout / 2)
        nc.add_nonce("id", time.time(), "xyz")
        self.assertTrue(nc.is_fresh("id", time.time(), "abc"))
        self.assertFalse(nc.is_fresh("id", time.time(), "def"))
        self.assertFalse(nc.is_fresh("id", time.time(), "xyz"))
        self.assertEquals(len(nc), 2)

    def test_that_cache_items_are_ungettable_once_expired(self):
        timeout = 0.1
        cache = Cache(timeout)
        cache.set("hello", "world")
        self.assertEquals(cache.get("hello"), "world")
        time.sleep(timeout / 2)
        self.assertEquals(cache.get("hello"), "world")
        time.sleep(timeout / 2)
        self.assertRaises(KeyError, cache.get, "hello")

    def test_that_cache_respects_max_size(self):
        timeout = 0.1
        cache = Cache(timeout, max_size=2)
        cache.set("hello", "world")
        self.assertEquals(len(cache), 1)
        cache.set("how", "are")
        self.assertEquals(len(cache), 2)
        cache.set("you", "today?")
        self.assertEquals(len(cache), 2)
        self.assertEquals(cache.get("you"), "today?")
        self.assertEquals(cache.get("how"), "are")
        self.assertRaises(KeyError, cache.get, "hello")

    def test_that_you_cant_set_duplicate_cache_keys(self):
        timeout = 0.1
        cache = Cache(timeout)
        cache.set("hello", "world")
        try:
            cache.set("hello", "spamityspam")
        except KeyExistsError, e:
            self.assertEquals(e.key, "hello")
            self.assertEquals(e.value, "world")
        else:
            assert False, "KeyExistsError was not raised"  # pragma: nocover
