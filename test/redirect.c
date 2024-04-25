/* 
   Tests for 3xx redirect interface (ne_redirect.h)
   Copyright (C) 2002-2003, Joe Orton <joe@manyfish.co.uk>

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

#include <sys/types.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ne_redirect.h"

#include "tests.h"
#include "child.h"
#include "utils.h"

struct redir_args {
    int code;
    const char *location;
};

static int serve_redir(ne_socket *sock, void *ud)
{
    struct redir_args *args = ud;
    char buf[BUFSIZ];

    CALL(discard_request(sock));

    ne_snprintf(buf, BUFSIZ, 
		"HTTP/1.0 %d Get Ye Away\r\n"
		"Content-Length: 0\r\n"
		"Location: %s\r\n\n",
		args->code, args->location);

    SEND_STRING(sock, buf);

    return OK;
}

/* Run a request to 'path' and retrieve the redirect destination to
 * *redir. */
static int process_redir(ne_session *sess, const char *path,
                         const ne_uri **redir)
{
    int ret = any_request(sess, path);
    ONV(ret != NE_REDIRECT,
        ("request got %d (%s) rather than NE_REDIRECT",
         ret, ne_get_error(sess)));
    *redir = ne_redirect_location(sess);
    return OK;
}

static int check_redir(struct redir_args *args, const char *target,
                       const char *expect)
{
    ne_session *sess;
    const ne_uri *loc;
    char *unp;
    char *full_expect = NULL;
    
    CALL(make_session(&sess, serve_redir, args));
    ne_redirect_register(sess);
    
    if (expect[0] == '/') {
        ne_uri uri = {0};
        ne_fill_server_uri(sess, &uri);
        uri.path = (char *)expect;
        full_expect = ne_uri_unparse(&uri);
        expect = full_expect;
        uri.path = NULL;
        ne_uri_free(&uri);
    }

    CALL(process_redir(sess, target, &loc));
    ONN("redirect location was NULL", loc == NULL);

    unp = ne_uri_unparse(loc);
    ONV(strcmp(unp, expect), ("redirected to `%s' not `%s'", unp, expect));
    ne_free(unp);

    if (full_expect) ne_free(full_expect);

    return destroy_and_wait(sess);
}

#define DEST "http://foo.com/blah/blah/bar"
#define PATH "/redir/me"

static int redirects(void)
{
    const struct {
        const char *target;
        int code;
        const char *location;
        const char *expected;
    } ts[] = {
        {PATH, 301, DEST, DEST},
        {PATH, 302, DEST, DEST},
        {PATH, 303, DEST, DEST},
        {PATH, 307, DEST, DEST},
        /* Test for various URI-reference cases. */
        {PATH, 302, "/foo/bar/blah", "/foo/bar/blah"},
        {"/foo/bar", 302, "norman", "/foo/norman"},
        {"/foo/bar/", 302, "wishbone", "/foo/bar/wishbone"},

#if 0
        /* all 3xx should really get NE_REDIRECT. */
        {PATH, 399, DEST, DEST},
         /* not yet working, needs to resolve URI-reference properly. */
        {"/blah", 307, "//example.com:8080/fish#food", "http://example.com:8080/fish#food"},
        {"/blah", 307, "#food", "/blah#food"},
#endif
    };
    unsigned n;
    
    for (n = 0; n < sizeof(ts)/sizeof(ts[0]); n++) {
        struct redir_args args = { ts[n].code, ts[n].location };
        CALL(check_redir(&args, ts[n].target, ts[n].expected));
    }

    return OK;
}

#define RESP1 "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n"
#define RESP2 "HTTP/1.0 302 Get Ye Away\r\n" "Location: /blah\r\n" "\r\n"

/* ensure that ne_redirect_location returns NULL when no redirect has
 * been encountered, or redirect hooks aren't registered. */
static int no_redirect(void)
{
    ne_session *sess;
    const ne_uri *loc;
    struct double_serve_args resp;

    resp.first.data = RESP1;
    resp.first.len = strlen(RESP1);
    resp.second.data = RESP2;
    resp.second.len = strlen(RESP2);

    CALL(session_server(&sess, double_serve_sstring, &resp));
    ONN("redirect non-NULL before register", ne_redirect_location(sess));
    ne_redirect_register(sess);
    ONN("initial redirect non-NULL", ne_redirect_location(sess));

    ONREQ(any_request(sess, "/noredir"));

    ONN("redirect non-NULL after non-redir req", ne_redirect_location(sess));

    CALL(process_redir(sess, "/foo", &loc));

    return destroy_and_wait(sess);
}

ne_test tests[] = {
    T(lookup_localhost),
    T(redirects),
    T(no_redirect),
    T(NULL) 
};

