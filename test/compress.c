/* 
   tests for compressed response handling.
   Copyright (C) 2001-2003, Joe Orton <joe@manyfish.co.uk>

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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <fcntl.h>

#include "ne_compress.h"

#include "tests.h"
#include "child.h"
#include "utils.h"

static int failed;

static char *newsfn = "../NEWS";

struct body {
    const char *str;
    size_t len;
};

static int init(void)
{
    if (test_argc > 1) {
	newsfn = ne_concat(test_argv[1], "/../NEWS", NULL);
    }
    return lookup_localhost();
}

static void reader(void *ud, const char *block, size_t len)
{
    struct body *b = ud;
 
    if (failed || len > b->len || memcmp(b->str, block, len) != 0) {
	failed = 1;
    } else {
	b->str += len;
	b->len -= len;
    }
}

static int file2buf(int fd, ne_buffer *buf)
{
    char buffer[BUFSIZ];
    ssize_t n;
    
    while ((n = read(fd, buffer, BUFSIZ)) > 0) {
	ne_buffer_append(buf, buffer, n);
    }
    
    return 0;
}

static int do_fetch(const char *realfn, const char *gzipfn,
		    int chunked, int expect_fail)
{
    ne_session *sess;
    ne_request *req;
    int fd;
    ne_buffer *buf = ne_buffer_create();
    struct serve_file_args sfargs;
    ne_decompress *dc;
    struct body body;
    
    fd = open(realfn, O_RDONLY);
    ONN("failed to open file", fd < 0);
    file2buf(fd, buf);
    (void) close(fd);

    body.str = buf->data;
    body.len = buf->used - 1;
    
    failed = 0;

    if (gzipfn) {
	sfargs.fname = gzipfn;
	sfargs.headers = "Content-Encoding: gzip\r\n";
    } else {
	sfargs.fname = realfn;
	sfargs.headers = NULL;
    }
    sfargs.chunks = chunked;
    
    CALL(make_session(&sess, serve_file, &sfargs));
    
    req = ne_request_create(sess, "GET", "/");
    dc = ne_decompress_reader(req, ne_accept_2xx, reader, &body);

    ONREQ(ne_request_dispatch(req));

    ONN("file not served", ne_get_status(req)->code != 200);

    ONN("decompress succeeded", expect_fail && !ne_decompress_destroy(dc));
    ONV(!expect_fail && ne_decompress_destroy(dc),
        ("decompress failed: %s", ne_get_error(sess)));

    ne_request_destroy(req);
    ne_session_destroy(sess);
    ne_buffer_destroy(buf);
    
    CALL(await_server());

    ONN("inflated response compare", failed);
    if (!expect_fail)
	ONN("inflated response truncated", body.len != 0);

    return OK;
}

static int fetch(const char *realfn, const char *gzipfn, int chunked)
{
    return do_fetch(realfn, gzipfn, chunked, 0);
}

/* Test the no-compression case. */
static int not_compressed(void)
{
    return fetch(newsfn, NULL, 0);
}

static int simple(void)
{
    return fetch(newsfn, "file1.gz", 0);
}

/* file1.gz has an embedded filename. */
static int withname(void)
{
    return fetch(newsfn, "file2.gz", 0);
}

/* deliver various different sizes of chunks: tests the various
 * decoding cases. */
static int chunked_1b_wn(void)
{
    return fetch(newsfn, "file2.gz", 1);
}

static int chunked_1b(void)
{
    return fetch(newsfn, "file1.gz", 1);
}

static int chunked_12b(void)
{
    return fetch(newsfn, "file2.gz", 12);
}

static int chunked_20b(void)
{
    return fetch(newsfn, "file2.gz", 20);
}

static int chunked_10b(void)
{
    return fetch(newsfn, "file1.gz", 10);
}

static int chunked_10b_wn(void)
{
    return fetch(newsfn, "file2.gz", 10);
}

static int fail_trailing(void)
{
    return do_fetch(newsfn, "trailing.gz", 0, 1);
}

static int fail_truncate(void)
{
    return do_fetch(newsfn, "truncated.gz", 0, 1);
}

static int fail_bad_csum(void)
{
    return do_fetch(newsfn, "badcsum.gz", 0, 1);
}

ne_test tests[] = {
    T_LEAKY(init),
    T(not_compressed),
    T(simple),
    T(withname),
    T(fail_trailing),
    T(fail_bad_csum),
    T(fail_truncate),
    T(chunked_1b), 
    T(chunked_1b_wn),
    T(chunked_12b), 
    T(chunked_20b),
    T(chunked_10b),
    T(chunked_10b_wn),
    T(NULL)
};
