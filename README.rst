===============================================================
macauthlib:  library for implementing MAC Access Authentication
===============================================================

This is a low-level library for implementing MAC Access Authentication, a
simple HTTP request-signing scheme described in:

    http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01

To access resources using MAC Access Authentication, the client must have
obtained a set of MAC credentials including an id and a secret key.  They use
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

    * get_id(req):  get the claimed MAC Auth id from the request.

    * check_signature(req, key, hashmod=sha1):  check that the request was
      signed with the given key.

The request objects passed to these functions can be any of a variety of
common object types:

    * a WSGI environment dict
    * a webob.Request object
    * a requests.Request object
    * a string or file-like object of request data

A typical use for a client program might be to install the sign_request
function as an authentication hook when using the requests library, like this::

    import requests
    import functools
    import macauthlib

    # Hook up sign_request() to be called on every request.
    def auth_hook(req):
        macauthlib.sign_request(req, id="<AUTH-ID>", key="<AUTH-KEY>")
        return req
    session = requests.session(hooks={"pre_request": auth_hook})

    # Then use the session as normal, and the auth is applied transparently.
    session.get("http://www.secret-data.com/get-my-data")


A typical use for a server program might be to verify requests using a WSGI
middleware component, like this::

    class MACAuthMiddleware(object):

        # ...setup code goes here...

        def __call__(self, environ, start_response):

            # Find the identity claimed by the request.
            id = macauthlib.get_id(environ)

            # Look up their secret key.
            key = self.SECRET_KEYS[id]

            # If the signature is invalid, error out.
            if not macauthlib.check_signature(environ, key):
                start_response("401 Unauthorized",
                               [("WWW-Authenticate", "MAC")])
                return [""]

            # Otherwise continue to the main application.
            return self.application(environ, start_response)
