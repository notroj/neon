/* 
   utils tests
   Copyright (C) 2001-2006, Joe Orton <joe@manyfish.co.uk>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include "config.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "ne_utils.h"
#include "ne_md5.h"
#include "ne_alloc.h"
#include "ne_dates.h"
#include "ne_string.h"

#include "tests.h"

static const struct {
    const char *status;
    int major, minor, code;
    const char *rp;
} accept_sl[] = {
    /* These are really valid. */
    { "HTTP/1.1 200 OK", 1, 1, 200, "OK" },
    { "HTTP/9.9 599 OK", 9, 9, 599, "OK" },
    { "HTTP/1.0 123 OK-is-OK1234", 1, 0, 123, "OK-is-OK1234" },
    { "HTTP/1.1 100 Alpha\tBeta", 1, 1, 100, "Alpha Beta" }, /* should be cleaned. */
    { "HTTP/1.1 100 Alpha  Beta", 1, 1, 100, "Alpha  Beta" },
    { "HTTP/1.1 100 fØØbÆr", 1, 1, 100, "f    b  r" }, /* UTF-8 should be cleaned */

    /* these aren't really valid but we should be able to parse them. */
    { NULL }
};

static const char *const bad_sl[] = {
    "",
    "HTTP/1.1 1000 OK",
    "HTTP/1.1 1000",
    "HTTP/-1.1 100 OK",
    "HTTP/1.1 -100 OK",
    "HTTP/ 200 OK",
    "HTTP/",
    "HTTP/1.1A 100 OK",
    "HTTP/1.",
    "HTTP/1.1 1",
    "Fish/1.1 100 OK",
    "HTTP/1.1 10",
    "HTTP",
    "H\0TP/1.1 100 OK",

    /* Previously allowed, now disallowed. */
    "HTTP/1.1   200   OK",
    "HTTP/1.1   200 \t  OK",
    "   HTTP/1.1 200 OK",
    "Norman is a dog HTTP/1.1 200 OK",
    "HTTP/1.1000 100 OK",
    "HTTP/1000.1000 100 OK",
    "HTTP/00001.1 100 OK",
    "HTTP/1.00001 100 OK",
    "HTTP/99.99 100 OK",
    "HTTP/1.1 600 OK",

    NULL
};  

static int status_lines(void)
{
    ne_status s;
    int n;

    for (n = 0; accept_sl[n].status != NULL; n++) {
	ONV(ne_parse_statusline(accept_sl[n].status, &s),
	    ("valid #%d: parsing '%s' failed", n, accept_sl[n].status));
	ONV(accept_sl[n].major != s.major_version, ("valid #%d: major", n));
	ONV(accept_sl[n].minor != s.minor_version, ("valid #%d: minor", n));
	ONV(accept_sl[n].code != s.code, ("valid #%d: code %d not %d", n, s.code, accept_sl[n].code));
	ONV(strcmp(accept_sl[n].rp, s.reason_phrase), 
	    ("valid #%d: reason phrase [%s] not [%s]", n, s.reason_phrase, accept_sl[n].rp));
        ne_free(s.reason_phrase);
        memset(&s, 0, sizeof s);
    }
    
    for (n = 0; bad_sl[n] != NULL; n++) {
	ONV(ne_parse_statusline(bad_sl[n], &s) == 0, 
	    ("invalid #%d parsed OK - [%s]", n, bad_sl[n]));
    }

    return OK;
}

/* Write MD5 of 'len' bytes of 'str' to 'digest' */
static const unsigned char *digest_md5(const char *data, size_t len,
                                 unsigned int digest[4])
{
    struct ne_md5_ctx *ctx;

#define CHUNK 100
    ctx = ne_md5_create_ctx();
    if (!ctx) {
        return (unsigned char *)"NO-MD5-SUPPORT";
    }        
    /* exercise the buffering interface */
    while (len > CHUNK) {
        ne_md5_process_bytes(data, CHUNK, ctx);
        len -= CHUNK;
        data += CHUNK;
    }
    ne_md5_process_bytes(data, len, ctx);
    ne_md5_finish_ctx(ctx, digest);
    ne_md5_destroy_ctx(ctx);

    return (unsigned char *)digest;
}

static int md5(void)
{
    unsigned int buf[4], buf2[4] = {0};
    char ascii[33] = {0};
    char zzzs[500];

    ne_md5_to_ascii(digest_md5("", 0, buf), ascii);
    ONN("MD5(null)", strcmp(ascii, "d41d8cd98f00b204e9800998ecf8427e"));
    
    ne_md5_to_ascii(digest_md5("foobar", 7, buf), ascii);
    ONN("MD5(foobar)", strcmp(ascii, "b4258860eea29e875e2ee4019763b2bb"));

    /* $ perl -e 'printf "z"x500' | md5sum
     * 8b9323bd72250ea7f1b2b3fb5046391a  - */
    memset(zzzs, 'z', sizeof zzzs);
    ne_md5_to_ascii(digest_md5(zzzs, sizeof zzzs, buf), ascii);
    ONN("MD5(\"z\"x512)", strcmp(ascii, "8b9323bd72250ea7f1b2b3fb5046391a"));

    ne_ascii_to_md5(ascii, (unsigned char *)buf2);
    ON(memcmp(buf, buf2, 16));
    
    return OK;
}

static int md5_alignment(void)
{
    char *bb = ne_malloc(66);
    struct ne_md5_ctx *ctx;

    /* regression test for a bug in md5.c in <0.15.0 on SPARC, where
     * the process_bytes function would SIGBUS if the buffer argument
     * isn't 32-bit aligned. Won't trigger on x86 though. */
    ctx = ne_md5_create_ctx();
    ONN("could not create MD5 context", ctx == NULL);
    ne_md5_process_bytes(bb + 1, 65, ctx);
    ne_md5_destroy_ctx(ctx);
    ne_free(bb);

    return OK;
}

#define INIT_MD5 "0123456789abcdeffedcba9876543210"

static int md5_read(void)
{
    union {
        unsigned int int32[4];
        unsigned char buf[16];
    } u;
    struct ne_md5_ctx *ctx = ne_md5_create_ctx();
    void *rv;
    char hex[33];

    rv = ne_md5_read_ctx(ctx, u.buf);
    if (rv == NULL) {
        ne_md5_destroy_ctx(ctx);
        return SKIP;
    }
    ONN("bogus return value", rv != u.buf);

    ne_md5_to_ascii(u.buf, hex);

    ONV(strcmp(INIT_MD5, hex) != 0,
        ("read context was %s not %s", hex, INIT_MD5));

    ne_md5_destroy_ctx(ctx);

    return OK;
}

static const struct {
    const char *str;
    time_t time;
    enum { d_rfc1123, d_iso8601, d_rfc1036, d_asctime } type;
} good_dates[] = {
    { "Fri, 08 Jun 2001 22:59:46 GMT", 992041186, d_rfc1123 },
    { "Friday, 08-Jun-01 22:59:46 GMT", 992041186, d_rfc1036 },
    { "Wednesday, 06-Jun-01 22:59:46 GMT", 991868386, d_rfc1036 },
    { "Wed Jun 06 22:59:46 2001", 991868386, d_asctime },
    /* some different types of ISO8601 dates. */
    { "2001-06-08T22:59:46Z", 992041186, d_iso8601 },
    { "2001-06-08T22:59:46.9Z", 992041186, d_iso8601 },
    { "2001-06-08T26:00:46+03:01", 992041186, d_iso8601 },
    { "2001-06-08T20:58:46-02:01", 992041186, d_iso8601 },
    { NULL }
};

static int parse_dates(void)
{
    int n;

    for (n = 0; good_dates[n].str != NULL; n++) {
	time_t res;
	const char *str = good_dates[n].str;

	switch (good_dates[n].type) {
	case d_rfc1036: res = ne_rfc1036_parse(str); break;
	case d_iso8601: res = ne_iso8601_parse(str); break;
	case d_rfc1123: res = ne_rfc1123_parse(str); break;
	case d_asctime: res = ne_asctime_parse(str); break;
	default: res = -1; break;
	}
	
	ONV(res == -1, ("date %d parse", n));
	
#define FT "%" NE_FMT_TIME_T
	ONV(res != good_dates[n].time, (
	    "date %d incorrect (" FT " not " FT ")", n,
	    res, good_dates[n].time));
    }

    return OK;
}

#define BAD_DATE(format, result) \
    ONN(format " date parse must fail", result != -1)

/* Test for bad dates; trigger segfaults in ne_rfc1036_parse() in
 * <=0.24.5. */
static int bad_dates(void)
{
    static const char *dates[] = {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "Friday, 08-Jun-01",
    };
    size_t n;
    
    for (n = 0; n < sizeof(dates)/sizeof(dates[0]); n++) {
        BAD_DATE("rfc1036", ne_rfc1036_parse(dates[n]));
        BAD_DATE("iso8601", ne_iso8601_parse(dates[n]));
        BAD_DATE("rfc1123", ne_rfc1123_parse(dates[n]));
        BAD_DATE("asctime", ne_asctime_parse(dates[n]));
    }

#if SIZEOF_TIME_T == 8 && defined(INT64_MAX)
    {
        char *rv = ne_rfc1123_date(INT64_MAX);

        ONV(rv != NULL,
            ("RFC1123 date conversion surprisingly worked for INT64_MAX: %s",
             rv));
    }
#endif

    return OK;
}

#define GOOD(n,m,msg) ONV(ne_version_match(n,m), \
("match of " msg " failed (%d.%d)", n, m))
#define BAD(n,m,msg) ONV(ne_version_match(n,m) == 0, \
("match of " msg " succeeded (%d.%d)", n, m))

static int versioning(void)
{
    GOOD(NE_VERSION_MAJOR, NE_VERSION_MINOR, "current version");
    BAD(NE_VERSION_MAJOR + 1, 0, "later major");
    BAD(NE_VERSION_MAJOR, NE_VERSION_MINOR + 1, "later minor");

#if NE_VERSION_MAJOR > 1
    BAD(NE_VERSION_MAJOR - 1, 0, "earlier major");
#if NE_VERSION_MINOR > 0
    GOOD(NE_VERSION_MAJOR, NE_VERSION_MINOR - 1, "earlier minor");
#endif /* NE_VERSION_MINOR > 0 */

#else /* where NE_VERSION_MAJOR < 2; note that 0.28 thru 1.0 maintain
       * backwards compatibility to 0.27 */
    BAD(0, 26, "minor version before 0.27");
    GOOD(0, 27, "current version back-compat to 0.27");
    GOOD(0, 28, "current version back-compat to 0.28");
    GOOD(0, 29, "current version back-compat to 0.29");
    GOOD(0, 30, "current version back-compat to 0.30");
#endif

    return OK;
}

#undef GOOD
#undef BAD

/* basic ne_version_string() sanity tests */
static int version_string(void)
{
    char buf[1024];
    
    ne_snprintf(buf, sizeof buf, "%s", ne_version_string());
    
    NE_DEBUG(NE_DBG_HTTP, "Version string: %s\n", buf);

    ONN("version string too long", strlen(buf) > 200);
    ONN("version string contained newline", strchr(buf, '\n') != NULL);

    return OK;    
}

static int support(void)
{
#ifdef NE_HAVE_SSL
    ONN("SSL support not advertised", !ne_has_support(NE_FEATURE_SSL));
#else
    ONN("SSL support advertised", ne_has_support(NE_FEATURE_SSL));
#endif
#ifdef NE_HAVE_ZLIB
    ONN("zlib support not advertised", !ne_has_support(NE_FEATURE_ZLIB));
#else
    ONN("zlib support advertised", ne_has_support(NE_FEATURE_ZLIB));
#endif
#ifdef NE_HAVE_IPV6
    ONN("IPv6 support not advertised", !ne_has_support(NE_FEATURE_IPV6));
#else
    ONN("IPv6 support advertised", ne_has_support(NE_FEATURE_IPV6));
#endif
#ifdef NE_HAVE_LFS
    ONN("LFS support not advertised", !ne_has_support(NE_FEATURE_LFS));
#else
    ONN("LFS support advertised", ne_has_support(NE_FEATURE_LFS));
#endif
#ifdef NE_HAVE_TS_SSL
    ONN("Thread-safe SSL support not advertised", 
        !ne_has_support(NE_FEATURE_TS_SSL));
#else
    ONN("Thread-safe SSL support advertised", 
        ne_has_support(NE_FEATURE_TS_SSL));
#endif
#ifdef NE_HAVE_I18N
    ONN("i18n support not advertised", 
        !ne_has_support(NE_FEATURE_I18N));
#else
    ONN("i18n SSL support advertised", 
        ne_has_support(NE_FEATURE_I18N));
#endif
#ifdef NE_HAVE_GSSAPI
    ONN("GSSAPI support not advertised", 
        !ne_has_support(NE_FEATURE_GSSAPI));
#else
    ONN("GSSAPI support advertised", 
        ne_has_support(NE_FEATURE_GSSAPI));
#endif
#ifdef NE_HAVE_LIBPXY
    ONN("libproxy support not advertised", 
        !ne_has_support(NE_FEATURE_LIBPXY));
#else
    ONN("libproxy support advertised", 
        ne_has_support(NE_FEATURE_LIBPXY));
#endif
    return OK;
}

ne_test tests[] = {
    T(status_lines),
    T(md5),
    T(md5_alignment),
    T(md5_read),
    T(parse_dates),
    T(bad_dates),
    T(versioning),
    T(version_string),
    T(support),
    T(NULL)
};
