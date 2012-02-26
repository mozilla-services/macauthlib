# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
import time

from macauthlib.noncecache import NonceCache, Cache


class TestNonces(unittest.TestCase):

    def test_default_timeout_is_one_minute(self):
        nm = NonceCache()
        self.assertEquals(nm.nonce_timeout,  60)
        self.assertEquals(nm.id_timeout,  60)

    def test_operation(self):
        timeout = 0.1
        nm = NonceCache(nonce_timeout=timeout, id_timeout=1)
        # Initially nothing is cached, so all nonces as fresh.
        self.assertEquals(nm.nonce_timeout, 0.1)
        self.assertEquals(len(nm), 0)
        self.assertTrue(nm.is_fresh("id", time.time(), "abc"))
        # After adding a nonce, it should contain just that item.
        nm.add_nonce("id", time.time(), "abc")
        self.assertEquals(len(nm), 1)
        self.assertFalse(nm.is_fresh("id", time.time(), "abc"))
        self.assertTrue(nm.is_fresh("id", time.time(), "xyz"))
        # After the timeout passes, the nonce should be expired.
        time.sleep(timeout)
        self.assertTrue(nm.is_fresh("id", time.time(), "abc"))
        # Writing to the cache purges expired nonces but keeps valid ones.
        nm.add_nonce("id", time.time(), "abc")
        time.sleep(timeout / 2)
        nm.add_nonce("id", time.time(), "def")
        self.assertFalse(nm.is_fresh("id", time.time(), "abc"))
        self.assertFalse(nm.is_fresh("id", time.time(), "def"))
        self.assertTrue(nm.is_fresh("id", time.time(), "xyz"))
        time.sleep(timeout / 2)
        nm.add_nonce("id", time.time(), "xyz")
        self.assertTrue(nm.is_fresh("id", time.time(), "abc"))
        self.assertFalse(nm.is_fresh("id", time.time(), "def"))
        self.assertFalse(nm.is_fresh("id", time.time(), "xyz"))
        self.assertEquals(len(nm), 2)

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
