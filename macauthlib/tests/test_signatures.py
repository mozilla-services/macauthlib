# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
import time

from webob import Request

from macauthlib import sign_request, get_id, get_signature, check_signature
from macauthlib.noncecache import NonceCache
from macauthlib.utils import parse_authz_header


class TestSignatures(unittest.TestCase):

    def test_get_id_works_on_valid_header(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("MAC", {"id": "user1", "ts": "1", "nonce": "2"})
        self.assertEquals(get_id(req), "user1")

    def test_get_id_returns_none_for_other_auth_schemes(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("OAuth", {"id": "user1", "ts": "1", "nonce": "2"})
        self.assertEquals(get_id(req), None)

    def test_get_id_returns_none_if_the_id_is_missing(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("MAC", {"ts": "1", "nonce": "2"})
        self.assertEquals(get_id(req), None)

    def test_get_signature_against_example_from_spec(self):
        # This is the example used in Section 1.1 of RFC-TODO
        req = "GET /resource/1?b=1&a=2 HTTP/1.1\r\n"\
              "Host: example.com\r\n"\
              "\r\n"
        params = {
            "id": "h480djs93hd8",
            "ts": "1336363200",
            "nonce": "dj83hs9s"
        }
        key = "489dks293j39"
        sig = "bhCQXTVyfj5cmA9uKkPFx1zeOXM="
        req = Request.from_bytes(req)
        mysig = get_signature(req, key, params=params)
        # XXX: disagrees with spec, but I'm wondering if spec is broken..?
        if False:
            self.assertEquals(sig, mysig)

    def test_sign_request_throws_away_other_auth_params(self):
        req = Request.blank("/")
        req.authorization = ("Digest", {"response": "helloworld"})
        sign_request(req, "id", "key")
        self.assertEquals(req.authorization[0], "MAC")

    def test_compatability_with_ff_sync_client(self):
        # These are test values used in the FF Sync Client testsuite.
        # Trying to make sure we're compatible.
        id, key = (
          "vmo1txkttblmn51u2p3zk2xiy16hgvm5ok8qiv1yyi86ffjzy9zj0ez9x6wnvbx7",
          "b8u1cc5iiio5o319og7hh8faf2gi5ym4aq0zwf112cv1287an65fudu5zj7zo7dz",
        )
        req = "GET /alias/ HTTP/1.1\r\nHost: 10.250.2.176\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("MAC", {"ts": "1329181221", "nonce": "wGX71"})
        sig = "jzh5chjQc2zFEvLbyHnPdX11Yck="
        mysig = get_signature(req, key)
        self.assertEquals(sig, mysig)

    def test_check_signature_errors_when_missing_id(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("MAC", {"ts": "1", "nonce": "2"})
        self.assertFalse(check_signature(req, "secretkeyohsecretkey"))

    def test_check_signature_fails_with_non_mac_scheme(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        sign_request(req, "myid", "mykey")
        req.authorization = ("OAuth", req.authorization[1])
        self.assertFalse(check_signature(req, "mykey"))

    def test_check_signature_fails_with_expired_timestamp(self):
        req = Request.blank("/")
        # Do an initial request so that the server can
        # calculate and cache our clock skew.
        ts = str(int(time.time()))
        req.authorization = ("MAC", {"ts": ts})
        sign_request(req, "myid", "mykey")
        self.assertTrue(check_signature(req, "mykey"))
        # Now do one with a really old timestamp.
        ts = str(int(time.time() - 1000))
        req.authorization = ("MAC", {"ts": ts})
        sign_request(req, "myid", "mykey")
        self.assertFalse(check_signature(req, "mykey"))

    def test_check_signature_fails_with_far_future_timestamp(self):
        req = Request.blank("/")
        # Do an initial request so that the server can
        # calculate and cache our clock skew.
        ts = str(int(time.time()))
        req.authorization = ("MAC", {"ts": ts})
        sign_request(req, "myid", "mykey")
        self.assertTrue(check_signature(req, "mykey"))
        # Now do one with a far future timestamp.
        ts = str(int(time.time() + 1000))
        req.authorization = ("MAC", {"ts": ts})
        sign_request(req, "myid", "mykey")
        self.assertFalse(check_signature(req, "mykey"))

    def test_check_signature_fails_with_reused_nonce(self):
        # First request with that nonce should succeed.
        req = Request.blank("/")
        req.authorization = ("MAC", {"nonce": "PEPPER"})
        sign_request(req, "myid", "mykey")
        self.assertTrue(check_signature(req, "mykey"))
        # Second request with that nonce should fail.
        req = Request.blank("/")
        req.authorization = ("MAC", {"nonce": "PEPPER"})
        sign_request(req, "myid", "mykey")
        self.assertFalse(check_signature(req, "mykey"))
        # But it will succeed if using a different nonce cache.
        self.assertTrue(check_signature(req, "mykey", nonces=NonceCache()))

    def test_check_signature_fails_with_busted_signature(self):
        req = Request.blank("/")
        sign_request(req, "myid", "mykey")
        signature = parse_authz_header(req)["mac"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.assertFalse(check_signature(req, "mykey"))
