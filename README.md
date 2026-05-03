
[![Build and test](https://github.com/notroj/neon/actions/workflows/ci.yml/badge.svg)](https://github.com/notroj/neon/actions/workflows/ci.yml)

# neon

_neon_ is an HTTP/1.1 and WebDAV client library, with a C language API.

GitHub: https://github.com/notroj/neon | Web: https://notroj.github.io/neon/

The neon API and ABI are stable and maintain backwards compatibility
since 0.27 through to 1.0.0. From neon 1.0.0 onwards, semantic
versioning will be used. https://semver.org/

Features:

 - High-level interface to HTTP and WebDAV methods.
 - Low-level interface to HTTP request handling, to allow implementing
   new methods easily.
 - Persistent connection support (HTTP/1.1 and HTTP/1.0 aware)
 - Basic and Digest authentication (RFC 7616/7617, including SHA-2, userhash)
 - Kerberos (Negotiate) and SSPI/NTLM authentication (Unix and Windows)
 - HTTP and SOCKS (v4/5) proxy support (including authentication)
 - SSL/TLS support using OpenSSL or GnuTLS (client certs via files or PKCS#11)
 - Generic WebDAV 207 XML response handling mechanism
 - XML parsing using expat or libxml2
 - Easy generation of error messages from 207 error responses
 - Basic HTTP/1.1 methods: GET, PUT, HEAD, OPTIONS, conditional PUT
 - WebDAV resource manipulation: MOVE, COPY, DELETE, MKCOL.
 - WebDAV metadata support: set and remove properties (PROPPATCH), query
   any set of properties (PROPFIND).
 - WebDAV locking and ACL (RFC 3744) support
 - Autoconf macros supplied for easily embedding neon directly inside 
   an application source tree.

Provides lower-level interfaces to directly implement new HTTP
methods, and higher-level interfaces so that you don't have to worry
about the lower-level stuff.

The neon library source code is licensed under the GNU Library GPL;
see src/COPYING.LIB for full details.  The manual and test suite are
licensed under the terms of the GNU GPL; see test/COPYING for terms.
The autoconf macros in the "macros" directory are under a less
restrictive license, see each file for details.

## Building neon

Grab the latest neon release tarball from https://notroj.github.io/neon/ and build 
as follows:

```bash
./configure --with-ssl=openssl --prefix=/path/to/install
make
make check
```

Third-party libraries are required for certain features:

- _expat_ or _libxml2_ for XML parsing and WebDAV support (https://github.com/libexpat/libexpat or https://github.com/gnome/libxml2)
- _OpenSSL_ or _GnuTLS_ for SSL/TLS support (https://openssl-library.org/ or https://gnutls.org/)
- _Libntlm_ for NTLM authentication support (https://gitlab.com/gsasl/libntlm)
- _GSSAPI_ libraries from a Kerberos distribution for Negotiate authentication
- _zlib_ for compressed response support (https://github.com/madler/zlib)
- _libproxy_ for system proxy support (see https://github.com/libproxy/libproxy)

~~~
neon is Copyright (C) 1999-2026 Joe Orton
Portions are:
Copyright (C) Aleix Conchillo Flaque
Copyright (C) Arfrever Frehtes Taifersar Arahesis
Copyright (C) Arun Garg
Copyright (C) Free Software Foundation, Inc.
Copyright (C) Henrik Holst
Copyright (C) Jiang Lei
Copyright (C) Karl Ove Hufthammer.
Copyright (C) Michael Sobolev
Copyright (C) Nobuyuki Tsuchimura
Copyright (C) Sylvain Glaize
Copyright (C) Temuri Doghonadze
Copyright (C) Thomas Schultz
Copyright (C) Vladimir Berezniker
Copyright (C) Yves Martin
~~~
