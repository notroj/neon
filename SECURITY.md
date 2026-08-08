# HTTP Client Security

> Generated from `doc/security.xml`; do not edit directly.

neon is intended to be secure against a specific threat model: use of a
malicious HTTP server. Under this threat model, a range of attacks are possible
against a client when the user (or application) can be tricked into accessing
an HTTP server which is controlled by an attacker. This section documents
various types of possible attack and describes what mitigation is used in neon.

## CPU or memory consumption attacks

neon uses fixed resource limits to prevent the following attacks:

- memory/CPU consumption attack using an unbounded number of response header
fields

- memory consumption attack using an unbounded length of individual response
header lines (or continuation headers)

- memory consumption attack against the `PROPFIND` code using an unbounded
number of properties (`propstat` elements) per resource

- memory consumption attack against the `PROPFIND` code using an unbounded
`CDATA` element in a "flat property" value

Memory consumption attacks against applications based on neon by use of
unbounded response length are also possible, but must be mitigated at
application level. Memory consumption in neon while reading response bodies is
fixed and is not proportional to the response length.

Test cases for all the above attacks are present in the neon test suite.

## SSL/TLS connection security

When using a connection secured by SSL/TLS, it is necessary for clients to
verify that the X.509 certificate presented by the server matches the server's
expected identity. The algorithm required for this purpose is described in [RFC
9110](https://www.rfc-editor.org/rfc/rfc9110) and [RFC
6125](https://www.rfc-editor.org/rfc/rfc6125), and is implemented by neon in
the following manner:

1. the `host` argument passed to `ne_session_create()` is the expected identity
of the server

2. if the `host` argument is an IP literal (e.g. `"198.51.100.42"` or
`"[2001:db8::42]"`), it is compared *only* to any `iPAddress` subjectAltName
values present

3. otherwise, the `host` parameter is treated as a DNS hostname, and is
compared with any `dNSName` subjectAltName values if present; if none match the
hostname is compared with the most specific `commonName` attribute in the
Subject name.

In the case where a server certificate is presented that does not match the
expected identity (or is otherwise not trusted), neon will fail the request by
default. This behaviour can be overridden by the use of a callback installed
using `ne_ssl_set_verify()`, which allows the application to present the
certificate details to a user for manual/off-line verification, if possible.

Test cases for the correctness of the implementation of the identity
verification algorithm are present in the neon test suite.

## Control character insertion in error messages

Where error messages (as returned by `ne_get_error()`) contain data supplied by
the server, the untrusted data is sanitised to remove both control characters
and non-ASCII characters. This prevents any attacks where such error messages
are exposed to the user and can potentially distort the presentation of the
interface (for example, through the use of a carriage return character in a
text user interface).

## Attacks against authentication credentials

Authentication credentials can be compromised by a "downgrade attack" by an
active attacker; for example, where a MITM presents a Basic authentication
challenge in place of the server's Digest challenge. neon mitigates these
attacks by allowing the application (and hence, user) to specify that only a
specific set of authentication protocols is permitted.

When using Basic authentication, neon applies the scoping rules from [RFC 7617
Section 2.2](https://www.rfc-editor.org/rfc/rfc7617.html#section-2.2) to limit
reuse of cached credentials within a session.

neon supports the Digest and Negotiate authentication schemes, which both allow
authentication of users without passing credentials in cleartext over the wire.

When using Digest authentication, neon uses hash algorithm implementations from
the configured SSL/TLS toolkit where possible, or falls back to a bundled MD5
implementation where SSL/TLS is not supported. If available, the SSL/TLS
toolkit is also used to generate random `cnonce` values. The `userhash` field
is supported for username privacy (this depends on server-side enablement). The
full range of hash algorithms specified in [RFC 7616 Section
6.1](https://www.rfc-editor.org/rfc/rfc7616.html#section-6.1) is supported if
configured using OpenSSL 1.1.0 or later.

