# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

from webob import Request

from macauthlib.utils import (strings_differ,
                              parse_authz_header,
                              get_normalized_request_string)


class TestUtils(unittest.TestCase):

    def test_strings_differ(self):
        # We can't really test the timing-invariance, but
        # we can test that we actually compute equality!
        self.assertTrue(strings_differ("", "a"))
        self.assertTrue(strings_differ("b", "a"))
        self.assertTrue(strings_differ("cc", "a"))
        self.assertTrue(strings_differ("cc", "aa"))
        self.assertFalse(strings_differ("", ""))
        self.assertFalse(strings_differ("D", "D"))
        self.assertFalse(strings_differ("EEE", "EEE"))

    def test_parse_authz_header(self):
        def req(authz):
            """Make a fake request with the given authz header."""
            class request:
                environ = {"HTTP_AUTHORIZATION": authz}
            return request

        # Test parsing of a single unquoted parameter.
        params = parse_authz_header(req('Digest realm=hello'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['realm'], 'hello')

        # Test parsing of multiple parameters with mixed quotes.
        params = parse_authz_header(req('Digest test=one, again="two"'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['test'], 'one')
        self.assertEquals(params['again'], 'two')

        # Test parsing of an escaped quote and empty string.
        params = parse_authz_header(req('Digest test="\\"",again=""'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['test'], '"')
        self.assertEquals(params['again'], '')

        # Test parsing of embedded commas, escaped and non-escaped.
        params = parse_authz_header(req('Digest one="1\\,2", two="3,4"'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['one'], '1,2')
        self.assertEquals(params['two'], '3,4')

        # Test parsing on various malformed inputs
        self.assertRaises(ValueError, parse_authz_header, req(None))
        self.assertRaises(ValueError, parse_authz_header, req(""))
        self.assertRaises(ValueError, parse_authz_header, req(" "))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken raw-token'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="unclosed-quote'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm=unopened-quote"'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="unescaped"quote"'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="escaped-end-quote\\"'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="duplicated",,what=comma'))

        # Test all those again, but returning a default value
        self.assertEquals(None, parse_authz_header(req(None), None))
        self.assertEquals(None, parse_authz_header(req(""), None))
        self.assertEquals(None, parse_authz_header(req(" "), None))
        self.assertEquals(None,
                          parse_authz_header(req('Broken raw-token'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="unclosed-quote'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm=unopened-quote"'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="unescaped"quote"'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="escaped-end-quote\\"'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="duplicated",,what=comma'), None))

    def test_normalized_request_string_against_example_from_spec(self):
        # This is the example used in Section 3.2.1 of RFC-TODO
        req = "POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q"\
              " HTTP/1.1\r\n"\
              "Host: example.com\r\n"\
              "\r\n"\
              "Hello World!"
        params = {
            "ts": "264095",
            "nonce": "7d8f3e4a",
            "ext": "a,b,c",
        }
        sigstr = "264095\n"\
                 "7d8f3e4a\n"\
                 "POST\n"\
                 "/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q\n"\
                 "example.com\n"\
                 "80\n"\
                 "a,b,c\n"
        # IanB, *thank you* for Request.from_bytes!
        req = Request.from_bytes(req)
        mysigstr = get_normalized_request_string(req, params)
        self.assertEquals(sigstr, mysigstr)

    def test_normalized_request_string_with_custom_port(self):
        req = "GET / HTTP/1.1\r\nHost: example.com:88\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("MAC", {"ts": "1", "nonce": "2"})
        sigstr = "1\n2\nGET\n/\nexample.com\n88\n\n"
        mysigstr = get_normalized_request_string(req)
        self.assertEquals(sigstr, mysigstr)

    def test_normalized_request_string_with_https_scheme(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("MAC", {"ts": "1", "nonce": "2"})
        req.scheme = "https"
        sigstr = "1\n2\nGET\n/\nexample.com\n443\n\n"
        mysigstr = get_normalized_request_string(req)
        self.assertEquals(sigstr, mysigstr)

    def test_normalized_request_string_errors_when_no_default_port(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = Request.from_bytes(req)
        req.authorization = ("MAC", {"ts": "1", "nonce": "2"})
        req.scheme = "httptypo"
        self.assertRaises(ValueError, get_normalized_request_string, req)
