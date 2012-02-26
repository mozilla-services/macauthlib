===============================================================
macauthlib:  library for implementing MAC Access Authentication
===============================================================

This is a low-level library for implementing MAC Access Authentication, a
simple HTTP request-signing scheme described in:

    http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01

To access resources using MAC Access Authentication, the client must have
obtained a set of MAC credentials including an id and secret key.  They use
these credentials to make signed requests to the server.

When accessing a protected resource, the server will generate a 401 challenge
response with the scheme "MAC" as follows::

    > GET /protected_resource HTTP/1.1
    > Host: example.com

    < HTTP/1.1 401 Unauthorized
    < WWW-Authenticate: MAC

The client will use their MAC credentials to build a request signature and
include it in the Authorization header like so::

    > GET /protected_resource HTTP/1.1
    > Host: example.com
    > Authorization: MAC id="h480djs93hd8",
    >                    ts="1336363200",
    >                    nonce="dj83hs9s",
    >                    mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="

    < HTTP/1.1 200 OK
    < Content-Type: text/plain
    <
    < For your eyes only:  secret data!


This library provices the low-level functions necessary to implement such
an authentication scheme.  For MAC Auth clients, it provides the following
function:

    * sign_request(req, id, key, hashmod=sha1):  sign a request using
                                                 MAC Access Auth.

For MAC Auth servers, it provides the following functions:

    * get_id(req):  get the claimed MAC Auth id
                    from the request.

    * check_signature(req, key, hashmod=sha1):  check that the request was
                                                signed with the given key.

