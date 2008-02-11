/* 
   HTTP request handling tests
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

#include <sys/types.h>

#include <time.h> /* for time() */

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ne_request.h"
#include "ne_socket.h"

#include "tests.h"
#include "child.h"
#include "utils.h"

static char buffer[BUFSIZ];

static ne_session *def_sess;
static ne_request *def_req;

static int prepare_request(server_fn fn, void *ud)
{
    static char uri[100];

    def_sess = ne_session_create("http", "localhost", 7777);

    sprintf(uri, "/test%d", test_num);

    def_req = ne_request_create(def_sess, "GET", uri);

    CALL(spawn_server(7777, fn, ud));

    return OK;
}

static int finish_request(void)
{
    ne_request_destroy(def_req);
    ne_session_destroy(def_sess);
    return await_server();
}

#define RESP200 "HTTP/1.1 200 OK\r\n" "Server: neon-test-server\r\n"
#define TE_CHUNKED "Transfer-Encoding: chunked\r\n"

/* takes response body chunks and appends them to a buffer. */
static void collector(void *ud, const char *data, size_t len)
{
    ne_buffer *buf = ud;
    ne_buffer_append(buf, data, len);
}

typedef ne_request *(*construct_request)(ne_session *sess, void *userdata);

/* construct a get request, callback for run_request. */
static ne_request *construct_get(ne_session *sess, void *userdata)
{
    ne_request *r = ne_request_create(sess, "GET", "/");
    ne_buffer *buf = userdata;

    ne_add_response_body_reader(r, ne_accept_2xx, collector, buf);

    return r;
}

/* run a request created by callback 'cb' in session 'sess'. */
static int run_request(ne_session *sess, int status,
		       construct_request cb, void *userdata)
{
    ne_request *req = cb(sess, userdata);

    ON(req == NULL);
    
    ONREQ(ne_request_dispatch(req));
 
    ONV(ne_get_status(req)->code != status,
	("response status-code was %d not %d",
	 ne_get_status(req)->code, status));

    ne_request_destroy(req);

    return OK;
}

/* Runs a server function 'fn', expecting to get a header 'name' with value
 * 'value' in the response. */
static int expect_header_value(const char *name, const char *value,
			       server_fn fn, void *userdata)
{
    ne_session *sess;
    ne_request *req;
    char *gotval = NULL;

    CALL(make_session(&sess, fn, userdata));

    req = ne_request_create(sess, "FOO", "/bar");
    ne_add_response_header_handler(req, name, ne_duplicate_header, &gotval);
    ONREQ(ne_request_dispatch(req));
    CALL(await_server());
    
    ONN("no header value set", gotval == NULL);
    ONV(strcmp(gotval, value),
	("header value mis-match: got [%s] not [%s]", gotval, value));
    
    ne_request_destroy(req);
    ne_session_destroy(sess);
    ne_free(gotval);

    return OK;
}

/* runs a server function 'fn', expecting response body to be equal to
 * 'expect' */
static int expect_response(const char *expect, server_fn fn, void *userdata)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);
    ne_buffer *buf = ne_buffer_create();

    ON(sess == NULL || buf == NULL);
    ON(spawn_server(7777, fn, userdata));

    CALL(run_request(sess, 200, construct_get, buf));

    ON(await_server());

    ONN("response body match", strcmp(buf->data, expect));

    ne_session_destroy(sess);
    ne_buffer_destroy(buf);
    
    return OK;
}

#define EMPTY_RESP RESP200 "Content-Length: 0\r\n\r\n"

/* Process a request with given method and response, expecting to get
 * a zero-length response body.  A second request is sent down the
 * connection (to ensure that the response isn't silently eaten), so
 * 'resp' must be an HTTP/1.1 response with no 'Connection: close'
 * header. */
static int expect_no_body(const char *method, const char *resp)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);
    ne_request *req = ne_request_create(sess, method, "/first");
    ssize_t ret;
    char *r = ne_malloc(strlen(resp) + sizeof(EMPTY_RESP));
    
    strcpy(r, resp);
    strcat(r, EMPTY_RESP);
    ON(spawn_server(7777, single_serve_string, r));
    ne_free(r);

    ONN("failed to begin request", ne_begin_request(req));
    ret = ne_read_response_block(req, buffer, BUFSIZ);
    ONV(ret != 0, ("got response block of size %" NE_FMT_SSIZE_T, ret));
    ONN("failed to end request", ne_end_request(req));

    /* process following request; makes sure that nothing extra has
     * been eaten by the first request. */
    ONV(any_request(sess, "/second"),
	("second request on connection failed: %s",ne_get_error(sess)));

    ON(await_server());

    ne_request_destroy(req);
    ne_session_destroy(sess);
    return OK;
}

static int reason_phrase(void)
{
    ne_session *sess;

    CALL(make_session(&sess, single_serve_string, RESP200
		      "Connection: close\r\n\r\n"));
    CALL(any_request(sess, "/foo"));
    CALL(await_server());
    
    ONV(strcmp(ne_get_error(sess), "200 OK"),
	("reason phrase mismatch: got `%s' not `200 OK'",
	 ne_get_error(sess)));

    ne_session_destroy(sess);
    return OK;    
}

static int single_get_eof(void)
{
    return expect_response("a", single_serve_string, 
			   RESP200
			   "Connection: close\r\n"
			   "\r\n"
			   "a");
}

static int single_get_clength(void)
{
    return expect_response("a", single_serve_string,
			   RESP200
			   "Content-Length: 1\r\n"
			   "\r\n"
			   "a"
			   "bbbbbbbbasdasd");
}

static int single_get_chunked(void) 
{
    return expect_response("a", single_serve_string,
			   RESP200 TE_CHUNKED
			   "\r\n"
			   "1\r\n"
			   "a\r\n"
			   "0\r\n" "\r\n"
			   "g;lkjalskdjalksjd");
}

static int no_body_304(void)
{
    return expect_no_body("GET", "HTTP/1.1 304 Not Mfodified\r\n"
			  "Content-Length: 5\r\n\r\n");
}

static int no_body_204(void)
{
    return expect_no_body("GET", "HTTP/1.1 204 Not Modified\r\n"
			  "Content-Length: 5\r\n\r\n");
}

static int no_body_205(void)
{
    return expect_no_body("GET", "HTTP/1.1 205 Reset Content\r\n"
			  "Content-Length: 5\r\n\r\n");
}

static int no_body_HEAD(void)
{
    return expect_no_body("HEAD", "HTTP/1.1 200 OK\r\n"
			  "Content-Length: 5\r\n\r\n");
}

static int no_body_empty_clength(void)
{
    return expect_no_body("GET", "HTTP/1.1 200 OK\r\n"
			  "Content-Length:\r\n\r\n");
}

static int no_body_bad_clength(void)
{
    return expect_no_body("GET", "HTTP/1.1 200 OK\r\n"
			  "Content-Length: foobar\r\n\r\n");
}

static int no_headers(void)
{
    return expect_response("abcde", single_serve_string,
			   "HTTP/1.1 200 OK\r\n\r\n"
			   "abcde");
}

#define CHUNK(len, data) #len "\r\n" data "\r\n"

#define ABCDE_CHUNKS CHUNK(1, "a") CHUNK(1, "b") \
 CHUNK(1, "c") CHUNK(1, "d") \
 CHUNK(1, "e") CHUNK(0, "")

static int chunks(void)
{
    /* lots of little chunks. */
    return expect_response("abcde", single_serve_string,
			   RESP200 TE_CHUNKED
			   "\r\n"
			   ABCDE_CHUNKS);
}

static int te_header(void)
{
    return expect_response("abcde", single_serve_string,
			   RESP200 "Transfer-Encoding: CHUNKED\r\n"
			   "\r\n" ABCDE_CHUNKS);
}

/* test that the presence of *any* t-e header implies a chunked
 * response. */
static int any_te_header(void)
{
    return expect_response("abcde", single_serve_string, RESP200
                           "Transfer-Encoding: punked\r\n" "\r\n"
                           ABCDE_CHUNKS);
}

static int chunk_numeric(void)
{    
    /* leading zero's */
    return expect_response("0123456789abcdef", single_serve_string,
			   RESP200 TE_CHUNKED
			   "\r\n"
			   "000000010\r\n" "0123456789abcdef\r\n"
			   "000000000\r\n" "\r\n");
}

static int chunk_extensions(void)
{
    /* chunk-extensions. */
    return expect_response("0123456789abcdef", single_serve_string,
			   RESP200 TE_CHUNKED
			   "\r\n"
			   "000000010; foo=bar; norm=fish\r\n" 
			   "0123456789abcdef\r\n"
			   "000000000\r\n" "\r\n");
}

static int chunk_trailers(void)
{
    /* trailers. */
    return expect_response("abcde", single_serve_string,
			   RESP200 TE_CHUNKED
			   "\r\n"
			   "00000005; foo=bar; norm=fish\r\n" 
			   "abcde\r\n"
			   "000000000\r\n" 
			   "X-Hello: world\r\n"
			   "X-Another: header\r\n"
			   "\r\n");
}

static int chunk_oversize(void)
{
#define BIG (20000)
    char *body = ne_malloc(BIG + 1);
    static const char rnd[] = "abcdefghijklm";
    int n;
    ne_buffer *buf = ne_buffer_create();
    
    for (n = 0; n < BIG; n++) {
	body[n] = rnd[n % (sizeof(rnd) - 1)];
    }
    body[n] = '\0';
#undef BIG

    ne_buffer_concat(buf, RESP200 TE_CHUNKED "\r\n" 
		     "4E20\r\n", body, "\r\n",
		     "0\r\n\r\n", NULL);

    CALL(expect_response(body, single_serve_string, buf->data));
    
    ne_buffer_destroy(buf);
    ne_free(body);

    return OK;
}

static int te_over_clength(void)
{   
    /* T-E dominates over C-L. */
    return expect_response("abcde", single_serve_string,
			   RESP200 TE_CHUNKED
			   "Content-Length: 300\r\n" 
			   "\r\n"
			   ABCDE_CHUNKS);
}

/* te_over_clength with the headers the other way round; check for
 * ordering problems. */
static int te_over_clength2(void)
{   
    return expect_response("abcde", single_serve_string,
			   RESP200 "Content-Length: 300\r\n" 
			   TE_CHUNKED
			   "\r\n"
			   ABCDE_CHUNKS);
}

/* obscure case which is possibly a valid request by 2616, but should
 * be handled correctly in any case.  neon <0.22.0 tries to 
 * eat the response body, which is probably incorrect. */
static int no_body_chunks(void)
{
    return expect_no_body("HEAD", "HTTP/1.1 204 Not Modified\r\n"
			  TE_CHUNKED "\r\n");
}

static int serve_twice(ne_socket *sock, void *userdata)
{
    const char *resp = userdata;
    
    CALL(discard_request(sock));
    SEND_STRING(sock, resp);

    CALL(discard_request(sock));
    SEND_STRING(sock, resp);

    return OK;
}

/* Test persistent connection handling: serve 'response' twice on a
 * single TCP connection, expecting to get a response body equal to
 * 'body' both times. */
static int test_persist(const char *response, const char *body)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);
    ne_buffer *buf = ne_buffer_create();

    ON(sess == NULL || buf == NULL);
    ON(spawn_server(7777, serve_twice, (char *)response));
    
    CALL(run_request(sess, 200, construct_get, buf));
    
    ONV(strcmp(buf->data, body),
	("response #1 mismatch: [%s] not [%s]", buf->data, body));

    /* Run it again. */
    ne_buffer_clear(buf);
    CALL(run_request(sess, 200, construct_get, buf));

    ON(await_server());

    ONV(strcmp(buf->data, body),
	("response #2 mismatch: [%s] not [%s]", buf->data, body));

    ne_session_destroy(sess);
    ne_buffer_destroy(buf);

    return OK;
}

static int persist_http11(void)
{
    return test_persist(RESP200 "Content-Length: 5\r\n\r\n" "abcde",
			"abcde");
}

static int persist_chunked(void)
{
    return test_persist(RESP200 TE_CHUNKED "\r\n" ABCDE_CHUNKS,
			"abcde");
}

static int persist_http10(void)
{
    return test_persist("HTTP/1.0 200 OK\r\n"
			"Connection: keep-alive\r\n"
			"Content-Length: 5\r\n\r\n" "abcde",
			"abcde");
}

/* Server function for fail_early_eof */
static int serve_eof(ne_socket *sock, void *ud)
{
    const char *resp = ud;

    /* dummy request/response. */
    CALL(discard_request(sock));
    CALL(SEND_STRING(sock, RESP200 "Content-Length: 0\r\n\r\n"));
    /* real request/response. */
    CALL(discard_request(sock));
    CALL(SEND_STRING(sock, resp));

    return OK;
}

/* Utility function: 'resp' is a truncated response; such that an EOF
 * arrives early during response processing; but NOT as a valid
 * premature EOF due to a persistent connection timeout.  It is an
 * error if the request is then retried, and the test fails. */
static int fail_early_eof(const char *resp)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);

    CALL(spawn_server_repeat(7777, serve_eof, (char *)resp, 3));

    ONREQ(any_request(sess, "/foo"));
    ONN("request retried after early EOF",
	any_request(sess, "/foobar") == NE_OK);
    
    CALL(reap_server());
    ne_session_destroy(sess);
    return OK;
}

/* This failed with neon <0.22. */
static int fail_eof_continued(void)
{
    return fail_early_eof("HTTP/1.1 100 OK\r\n\r\n");
}

static int fail_eof_headers(void)
{
    return fail_early_eof("HTTP/1.1 200 OK\r\nJimbob\r\n");
}

static int fail_eof_chunk(void)
{
    return fail_early_eof(RESP200 TE_CHUNKED "\r\n" "1\r\n" "a");
}

static int fail_eof_badclen(void)
{
    return fail_early_eof(RESP200 "Content-Length: 10\r\n\r\n" "abcde");
}

/* Persistent connection timeout where a FIN is sent to terminate the
 * connection, which is caught by a 0 return from the read() when the
 * second request reads the status-line. */
static int ptimeout_eof(void)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);

    CALL(spawn_server_repeat(7777, single_serve_string, 
			     RESP200 "Content-Length: 0\r\n" "\r\n", 4));
    
    CALL(any_2xx_request(sess, "/first"));
    CALL(any_2xx_request(sess, "/second"));
    
    ONN("server died prematurely?", dead_server());
    reap_server();

    ne_session_destroy(sess);
    return OK;
}

/* Persistent connection timeout where a FIN is sent to terminate the
 * connection, but the request fails in the write() call which sends
 * the body. */
static int ptimeout_eof2(void)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);

    CALL(spawn_server_repeat(7777, single_serve_string, 
			     RESP200 "Content-Length: 0\r\n" "\r\n", 4));
    
    CALL(any_2xx_request(sess, "/first"));
    minisleep();
    CALL(any_2xx_request_body(sess, "/second"));
    
    ONN("server died prematurely?", dead_server());
    reap_server();

    ne_session_destroy(sess);
    return OK;
}

/* TODO: add a ptimeout_reset too, if an RST can be reliably generated
 * mid-connection. */

/* Emulates a persistent connection timeout on the server. This tests
 * the timeout occuring after between 1 and 10 requests down the
 * connection. */
static int persist_timeout(void)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);
    ne_buffer *buf = ne_buffer_create();
    int n;
    struct many_serve_args args;

    ON(sess == NULL || buf == NULL);

    args.str = RESP200 "Content-Length: 5\r\n\r\n" "abcde";
    
    for (args.count = 1; args.count < 10; args.count++) {

	ON(spawn_server(7777, many_serve_string, &args));

	for (n = 0; n < args.count; n++) {
	    
	    ONV(run_request(sess, 200, construct_get, buf),
		("%d of %d, request failed: %s", n, args.count,
		 ne_get_error(sess)));
	    
	    ONV(strcmp(buf->data, "abcde"),
		("%d of %d, response body mismatch", n, args.count));

	    /* Ready for next time. */
	    ne_buffer_clear(buf);
	}

	ON(await_server());

    }

    ne_session_destroy(sess);
    ne_buffer_destroy(buf);

    return OK;
}   

/* Test that an HTTP/1.0 server is not presumed to support persistent
 * connections by default. */
static int no_persist_http10(void)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);

    CALL(spawn_server_repeat(7777, single_serve_string,
			     "HTTP/1.0 200 OK\r\n"
			     "Content-Length: 5\r\n\r\n"
			     "abcde"
			     "Hello, world - what a nice day!\r\n",
			     4));

    /* if the connection is treated as persistent, the status-line for
     * the second request will be "Hello, world...", which will
     * fail. */

    ONREQ(any_request(sess, "/foobar"));
    ONREQ(any_request(sess, "/foobar"));

    ONN("server died prematurely?", dead_server());
    CALL(reap_server());
    ne_session_destroy(sess);
    return OK;
}

static int ignore_bad_headers(void)
{
    return expect_response("abcde", single_serve_string,
			   RESP200 
			   "Stupid Header\r\n"
			   "ReallyStupidHeader\r\n"
			   "Content-Length: 5\r\n"
			   "\r\n"
			   "abcde");
}

static int fold_headers(void)
{
    return expect_response("abcde", single_serve_string,
			   RESP200 "Content-Length: \r\n   5\r\n"
			   "\r\n"
			   "abcde");
}

static int fold_many_headers(void)
{
    return expect_response("abcde", single_serve_string,
			   RESP200 "Content-Length: \r\n \r\n \r\n \r\n  5\r\n"
			   "\r\n"
			   "abcde");
}

#define NO_BODY "Content-Length: 0\r\n\r\n"

static int empty_header(void)
{
    return expect_header_value("ranDom-HEader", "",
			       single_serve_string,
			       RESP200 "RANDom-HeADEr:\r\n"
			       NO_BODY);
}

static int ignore_header_case(void)
{
    return expect_header_value("ranDom-HEader", "noddy",
			       single_serve_string,
			       RESP200 "RANDom-HeADEr: noddy\r\n"
			       NO_BODY);
}

static int ignore_header_ws(void)
{
    return expect_header_value("ranDom-HEader", "fishy",
			       single_serve_string,
			       RESP200 "RANDom-HeADEr:    fishy\r\n"
			       NO_BODY);
}

static int ignore_header_ws2(void)
{
    return expect_header_value("ranDom-HEader", "fishy",
			       single_serve_string,
			       RESP200 "RANDom-HeADEr \t :    fishy\r\n"
			       NO_BODY);
}

static int ignore_header_ws3(void)
{
    return expect_header_value("ranDom-HEader", "fishy",
			       single_serve_string,
			       RESP200 "RANDom-HeADEr: fishy  \r\n"
			       NO_BODY);
}

static int ignore_header_tabs(void)
{
    return expect_header_value("ranDom-HEader", "geezer",
			       single_serve_string,
			       RESP200 "RANDom-HeADEr: \t \tgeezer\r\n"
			       NO_BODY);
}

static int trailing_header(void)
{
    return expect_header_value("gONe", "fishing",
			       single_serve_string,
			       RESP200 TE_CHUNKED
			       "\r\n0\r\n"
			       "Hello: world\r\n"
			       "GONE: fishing\r\n"
			       "\r\n");
}

static int continued_header(void)
{
    return expect_header_value("hello", "w o r l d", single_serve_string,
			       RESP200 "Hello:  \n\tw\r\n\to r l\r\n\td  \r\n"
			       NO_BODY);
}

static void mh_header(void *ctx, const char *value)
{
    int *state = ctx;
    static const char *hdrs[] = { "jim", "jab", "jar" };

    if (*state < 0 || *state > 2) {
	/* already failed. */
	return;
    }

    if (strcmp(value, hdrs[*state]))
	*state = -*state;
    else
	(*state)++;
}

/* check headers callbacks are working correctly. */
static int multi_header(void)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);
    ne_request *req;
    int state = 0;

    ON(sess == NULL);
    ON(spawn_server(7777, single_serve_string, 
		    RESP200 
		    "X-Header: jim\r\n" 
		    "x-header: jab\r\n"
		    "x-Header: jar\r\n"
		    "Content-Length: 0\r\n\r\n"));

    req = ne_request_create(sess, "GET", "/");
    ON(req == NULL);

    ne_add_response_header_handler(req, "x-header", mh_header, &state);

    ONREQ(ne_request_dispatch(req));

    ON(await_server());

    ON(state != 3);

    ne_request_destroy(req);
    ne_session_destroy(sess);

    return OK;
}

struct s1xx_args {
    int count;
    int hdrs;
};

static int serve_1xx(ne_socket *sock, void *ud)
{
    struct s1xx_args *args = ud;
    CALL(discard_request(sock));
    
    do {
	if (args->hdrs) {
	    SEND_STRING(sock, "HTTP/1.1 100 Continue\r\n"
			"Random: header\r\n"
			"Another: header\r\n\r\n");
	} else {
	    SEND_STRING(sock, "HTTP/1.1 100 Continue\r\n\r\n");
	}
    } while (--args->count > 0);
    
    SEND_STRING(sock, RESP200 "Content-Length: 0\r\n\r\n");
    
    return OK;
}

#define sess def_sess

static int skip_interim_1xx(void)
{
    struct s1xx_args args = {0, 0};
    ON(prepare_request(serve_1xx, &args));
    ONREQ(ne_request_dispatch(def_req));
    return finish_request();
}

static int skip_many_1xx(void)
{
    struct s1xx_args args = {5, 0};
    ON(prepare_request(serve_1xx, &args));
    ONREQ(ne_request_dispatch(def_req));
    return finish_request();
}

static int skip_1xx_hdrs(void)
{
    struct s1xx_args args = {5, 5};
    ON(prepare_request(serve_1xx, &args));
    ONREQ(ne_request_dispatch(def_req));
    return finish_request();
}

#undef sess

/* server for expect_100_once: eats a dummy request, then serves a
 * 100-continue request, and fails if the request body is sent
 * twice. */
static int serve_100_once(ne_socket *sock, void *ud)
{
    struct s1xx_args args = {2, 0};
    char ch;
    /* dummy first request. */
    CALL(discard_request(sock));
    CALL(SEND_STRING(sock, RESP200 "Content-Length: 0\r\n\r\n"));
    /* now the real 1xx request. */
    CALL(serve_1xx(sock, &args));
    CALL(discard_body(sock));
    ONN("body was served twice", ne_sock_read(sock, &ch, 1) == 1);
    return OK;
}

/* regression test; fails with neon <0.22, where the request body was
 * served *every* time a 1xx response was received, rather than just
 * once. */
static int expect_100_once(void)
{
    ne_session *sess;
    ne_request *req;
    char body[BUFSIZ];

    CALL(make_session(&sess, serve_100_once, NULL));
    ne_set_expect100(sess, 1);

    /* 100-continue is only used if the server is known to claim
     * HTTP/1.1 compliance; make a dummy request on the socket first,
     * to trigger that logic. */
    CALL(any_request(sess, "/foo"));
    
    /* now the real request. */
    req = ne_request_create(sess, "GET", "/foo");
    memset(body, 'A', sizeof(body));
    ne_set_request_body_buffer(req, body, sizeof(body));
    ONN("request failed", ne_request_dispatch(req));
    ne_request_destroy(req);
    ne_session_destroy(sess);
    CALL(await_server());
    return OK;
}

struct body {
    char *body;
    size_t size;
};

static int want_body(ne_socket *sock, void *userdata)
{
    struct body *b = userdata;
    char *buf = ne_malloc(b->size);

    clength = 0;
    CALL(discard_request(sock));
    ONN("request has c-l header", clength == 0);
    
    ONN("request length", clength != (int)b->size);
    
    NE_DEBUG(NE_DBG_HTTP, 
	     "reading body of %" NE_FMT_SIZE_T " bytes...\n", b->size);
    
    ON(ne_sock_fullread(sock, buf, b->size));
    
    ON(SEND_STRING(sock, RESP200 "Content-Length: 0\r\n\r\n"));

    ON(memcmp(buf, b->body, b->size));
    
    ne_free(buf);
    return OK;
}

static ssize_t provide_body(void *userdata, char *buf, size_t buflen)
{
    static const char *pnt;
    static size_t left;
    struct body *b = userdata;

    if (buflen == 0) {
	pnt = b->body;
	left = b->size;
    } else {
	if (left < buflen) buflen = left;
	memcpy(buf, pnt, buflen);
	left -= buflen;
    }
    
    return buflen;
}

static int send_bodies(void)
{
    unsigned int n, m;

    struct body bodies[] = { 
	{ "abcde", 5 }, 
	{ "\0\0\0\0\0\0", 6 },
	{ NULL, 50000 },
	{ NULL }
    };

#define BIG 2
    /* make the body with some cruft. */
    bodies[BIG].body = ne_malloc(bodies[BIG].size);
    for (n = 0; n < bodies[BIG].size; n++) {
	bodies[BIG].body[n] = (char)n%80;
    }

    for (m = 0; m < 2; m++) {
	for (n = 0; bodies[n].body != NULL; n++) {
	    ne_session *sess = ne_session_create("http", "localhost", 7777);
	    ne_request *req;
	    
	    ON(sess == NULL);
	    ON(spawn_server(7777, want_body, &(bodies[n])));

	    req = ne_request_create(sess, "PUT", "/");
	    ON(req == NULL);

	    if (m == 0) {
		ne_set_request_body_buffer(req, bodies[n].body, bodies[n].size);
	    } else {
		ne_set_request_body_provider(req, bodies[n].size, 
					     provide_body, &bodies[n]);
	    }

	    ONREQ(ne_request_dispatch(req));
	    
	    CALL(await_server());
	    
	    ne_request_destroy(req);
	    ne_session_destroy(sess);
	}
    }

    ne_free(bodies[BIG].body);
    return OK;
}

static int serve_infinite_headers(ne_socket *sock, void *userdata)
{
    CALL(discard_request(sock));

    SEND_STRING(sock, RESP200);
    
    for (;;) {
	SEND_STRING(sock, "x-foo: bar\r\n");
    }

    return 0;	
}

/* Utility function: run a request using the given server fn, and the
 * request should fail. If 'error' is non-NULL, it must be a substring
 * of the error string. */
static int fail_request_with_error(int with_body, server_fn fn, void *ud, 
                                   int forever, const char *error)
{
    ne_session *sess = ne_session_create("http", "localhost", 7777);
    ne_request *req;
    int ret;

    ON(sess == NULL);
    
    if (forever) {
	ON(spawn_server_repeat(7777, fn, ud, 100));
    } else {
	ON(spawn_server(7777, fn, ud));
    }
    
    req = ne_request_create(sess, "GET", "/");
    ON(req == NULL);

    if (with_body) {
	static const char *body = "random stuff";
	
	ne_set_request_body_buffer(req, body, strlen(body));
    }

    /* request should fail. */
    ret = ne_request_dispatch(req);
    ONN("request succeeded", ret == NE_OK);

    if (!forever) {
	/* reap the server, don't care what it's doing. */
	reap_server();
    }

    NE_DEBUG(NE_DBG_HTTP, "Response gave error `%s'\n", ne_get_error(sess));
 
    ONV(error && strstr(ne_get_error(sess), error) == NULL,
        ("failed with error `%s', no `%s'", ne_get_error(sess), error));

    if (!forever)
        ONV(any_request(sess, "/fail/to/connect") != NE_CONNECT,
            ("subsequent request re-used connection?"));

    ne_request_destroy(req);
    ne_session_destroy(sess);
   
    return OK;    
}

/* Run a random GET request which is given 'body' as the response; the
 * request must fail, and 'error' must be found in the error
 * string. */
static int invalid_response_gives_error(const char *resp, const char *error)
{
    return fail_request_with_error(0, single_serve_string, (void *)resp, 0, error);
}

/* Utility function: run a request using the given server fn, and the
 * request must fail. */
static int fail_request(int with_body, server_fn fn, void *ud, int forever)
{
    return fail_request_with_error(with_body, fn, ud, forever, NULL);
}

static int unbounded_headers(void)
{
    return fail_request(0, serve_infinite_headers, NULL, 0);
}

static int blank_response(void)
{
    return fail_request(0, single_serve_string, "\r\n", 0);
}

static int serve_non_http(ne_socket *sock, void *ud)
{
    SEND_STRING(sock, "Hello Mum.\n");
    ne_sock_readline(sock, buffer, BUFSIZ);
    return OK;
}

/* Test behaviour when not speaking to an HTTP server. Regression test
 * for infinite loop. */
static int not_http(void)
{
    return fail_request(0, serve_non_http, NULL, 0);
}

static int serve_infinite_folds(ne_socket *sock, void *ud)
{
    SEND_STRING(sock, "HTTP/1.0 200 OK\r\nFoo: bar\r\n");
    for (;;) {
	SEND_STRING(sock, "  hello there.\r\n");
    }
    return OK;
}

static int unbounded_folding(void)
{
    return fail_request(0, serve_infinite_folds, NULL, 0);
}

static int serve_close(ne_socket *sock, void *ud)
{
    /* do nothing; the socket will be closed. */
    return 0;
}

/* Returns non-zero if port is alive. */
static int is_alive(int port)
{
    ne_sock_addr *addr;
    ne_socket *sock = ne_sock_create();
    const ne_inet_addr *ia;
    int connected = 0;

    addr = ne_addr_resolve("localhost", 0);
    for (ia = ne_addr_first(addr); ia && !connected; ia = ne_addr_next(addr))
	connected = ne_sock_connect(sock, ia, 7777) == 0;
    ne_addr_destroy(addr);
    if (sock == NULL)
	return 0;
    else {
	ne_sock_close(sock);
	return 1;
    }
}

/* This is a regression test for neon 0.17.0 and earlier, which goes
 * into an infinite loop if a request with a body is sent to a server
 * which simply closes the connection. */
static int closed_connection(void)
{
    int ret;

    /* This spawns a server process which will run the 'serve_close'
     * response function 200 times, then die. This guarantees that the
     * request eventually fails... */
    CALL(fail_request(1, serve_close, NULL, 1));
    /* if server died -> infinite loop was detected. */
    ret = !is_alive(7777);
    reap_server();
    ONN("server aborted, infinite loop?", ret);
    return OK;
}

static int serve_close2(ne_socket *sock, void *userdata)
{
    int *count = userdata;
    *count += 1;
    if (*count == 1)
	return 0;
    NE_DEBUG(NE_DBG_HTTP, "Re-entered! Buggy client.\n");
    CALL(discard_request(sock));
    CALL(SEND_STRING(sock, RESP200 "Content-Length: 0\r\n\r\n"));
    return 0;
}

/* As closed_connection(); but check that the client doesn't retry
 * after receiving the EOF on the first request down a new
 * connection.  */
static int close_not_retried(void)
{
    int count = 0;
    ne_session *sess = ne_session_create("http", "localhost", 7777);
    CALL(spawn_server_repeat(7777, serve_close2, &count, 3));
    ONN("request was retried after EOF", any_request(sess, "/foo") == NE_OK);
    reap_server();
    ne_session_destroy(sess);
    return OK;
}

static enum {
    prog_error, /* error */
    prog_transfer, /* doing a transfer */
    prog_done /* finished. */
} prog_state = prog_transfer;

static off_t prog_last = -1, prog_total;

/* callback for send_progress. */
static void s_progress(void *userdata, off_t prog, off_t total)
{
    NE_DEBUG(NE_DBG_HTTP, 
	     "progress callback: %" NE_FMT_OFF_T "/%" NE_FMT_OFF_T ".\n",
	     prog, total);

    switch (prog_state) {
    case prog_error:
    case prog_done:
	return;
    case prog_transfer:
	if (total != prog_total) {
	    t_context("total unexpected: %ld not %ld", total, prog_total);
	    prog_state = prog_error;
	}
	else if (prog > total) {
	    t_context("first progress was invalid (%ld/%ld)", prog, total);
	    prog_state = prog_error;
	}
	else if (prog_last != -1 && prog_last > prog) {
	    t_context("progess went backwards: %ld to %ld", prog_last, prog);
	    prog_state = prog_error;
	}
	else if (prog_last == prog) {
	    t_context("no progress made! %ld to %ld", prog_last, prog);
	    prog_state = prog_error;
	}
	else if (prog == total) {
	    prog_state = prog_done;
	}
	break;
    }
	    
    prog_last = prog;
}

static ssize_t provide_progress(void *userdata, char *buf, size_t bufsiz)
{
    int *count = userdata;

    if (*count >= 0 && buf != NULL) {
	buf[0] = 'a';
	*count -= 1;
	return 1;
    } else {
	return 0;
    }
}

static int send_progress(void)
{
    static int count = 200;

    ON(prepare_request(single_serve_string, 
		       RESP200 "Connection: close\r\n\r\n"));

    prog_total = 200;

    ne_set_progress(def_sess, s_progress, NULL);
    ne_set_request_body_provider(def_req, count,
				 provide_progress, &count);

#define sess def_sess
    ONREQ(ne_request_dispatch(def_req));
#undef sess
    
    ON(finish_request());

    CALL(prog_state == prog_error);

    return OK;    
}

static int read_timeout(void)
{
    ne_session *sess;
    ne_request *req;
    time_t start, finish;
    int ret;

    CALL(make_session(&sess, sleepy_server, NULL));
    
    /* timeout after one second. */
    ne_set_read_timeout(sess, 1);
    
    req = ne_request_create(sess, "GET", "/timeout");

    time(&start);
    ret = ne_request_dispatch(req);
    time(&finish);

    reap_server();

    ONN("request succeeded, should have timed out", ret == NE_OK);
    ONV(ret != NE_TIMEOUT,
	("request failed non-timeout error: %s", ne_get_error(sess)));
    ONN("timeout ignored, or very slow machine", finish - start > 3);

    ne_request_destroy(req);
    ne_session_destroy(sess);

    return OK;    
}

/* expect failure code 'code', for request to given hostname and port,
 * without running a server. */
static int fail_noserver(const char *hostname, unsigned int port, int code)
{
     ne_session *sess = ne_session_create("http", hostname, port);
     int ret = any_request(sess, "/foo");
     ne_session_destroy(sess);

     ONV(ret == NE_OK,
	 ("request to server at %s:%u succeded?!", hostname, port));
     ONV(ret != code, ("request failed with %d not %d", ret, code));

     return OK;
}

static int fail_lookup(void)
{
    return fail_noserver("no.such.domain", 7777, NE_LOOKUP);
}

/* neon 0.23.0 to 0.23.3: if a nameserver lookup failed, subsequent
 * requests on the session would crash. */
static int fail_double_lookup(void)
{
     ne_session *sess = ne_session_create("http", "nohost.example.com", 80);
     ONN("request did not give lookup failure",
	 any_request(sess, "/foo") != NE_LOOKUP);
     ONN("second request did not give lookup failure",
	 any_request(sess, "/bar") != NE_LOOKUP);
     ne_session_destroy(sess);
     return OK;
}

static int fail_connect(void)
{
    return fail_noserver("localhost", 7777, NE_CONNECT);
}

/* Test that the origin server hostname is NOT resolved for a proxied
 * request. */
static int proxy_no_resolve(void)
{
     ne_session *sess = ne_session_create("http", "no.such.domain", 80);
     int ret;
     
     ne_session_proxy(sess, "localhost", 7777);
     CALL(spawn_server(7777, single_serve_string,
		       RESP200 "Content-Length: 0\r\n\r\n"));
     
     ret = any_request(sess, "/foo");
     ne_session_destroy(sess);

     ONN("origin server name resolved when proxy used", ret == NE_LOOKUP);

     CALL(await_server());

     return OK;
}

/* If the chunk size is entirely invalid, the request should be
 * aborted.  Fails with neon <0.22; invalid chunk sizes would be
 * silently treated as 'zero'. */
static int fail_chunksize(void)
{
    return fail_request(0, single_serve_string,
			RESP200 TE_CHUNKED "\r\n" "ZZZZZ\r\n\r\n", 0);
}

/* in neon <0.22, if an error occcurred whilst reading the response
 * body, the connection would not be closed (though this test will
 * succeed in neon <0.22 since it the previous test fails). */
static int abort_respbody(void)
{
    ne_session *sess;
    
    CALL(make_session(&sess, single_serve_string,
		      RESP200 TE_CHUNKED "\r\n"
		      "zzz\r\n"
		      RESP200 "Content-Length: 0\r\n\r\n"));
    
    /* connection must be aborted on the first request, since it
     * contains an invalid chunk size. */
    ONN("invalid chunk size was accepted?",
	any_request(sess, "/foo") != NE_ERROR);

    CALL(await_server());
    
    /* second request should fail since server has gone away. */
    ONN("connection was not aborted", any_request(sess, "/foo") == NE_OK);

    ne_session_destroy(sess);
    return OK;
}

static int serve_abort(ne_socket *sock, void *ud)
{
    exit(0);
}

/* Test that after an aborted request on a peristent connection, a
 * failure of the *subsequent* request is not treated as a persistent
 * connection timeout and retried.  */
static int retry_after_abort(void)
{
    ne_session *sess;
    
    /* Serve two responses down a single persistent connection, the
     * second of which is invalid and will cause the request to be
     * aborted. */
    CALL(make_session(&sess, single_serve_string, 
		      RESP200 "Content-Length: 0\r\n\r\n"
		      RESP200 TE_CHUNKED "\r\n"
		      "zzzzz\r\n"));

    CALL(any_request(sess, "/first"));
    ONN("second request should fail", any_request(sess, "/second") == NE_OK);
    CALL(await_server());

    /* spawn a server, abort the server immediately.  If the
     * connection reset is interpreted as a p.conn timeout, a new
     * connection will be attempted, which will fail with
     * NE_CONNECT. */
    CALL(spawn_server(7777, serve_abort, NULL));
    ONN("third request was retried",
	any_request(sess, "/third") == NE_CONNECT);
    reap_server();

    ne_session_destroy(sess);    
    return OK;
}

/* Fail to parse the response status line: check the error message is
 * sane.  Failed during 0.23-dev briefly, and possibly with 0.22.0
 * too. */
static int fail_statusline(void)
{
    ne_session *sess;
    int ret;

    CALL(make_session(&sess, single_serve_string, "Fish.\r\n"));
    
    ret = any_request(sess, "/fail");
    ONV(ret != NE_ERROR, ("request failed with %d not NE_ERROR", ret));
    
    /* FIXME: will break for i18n. */
    ONV(strcmp(ne_get_error(sess), "Could not parse response status line."),
	("session error was `%s'", ne_get_error(sess)));

    ne_session_destroy(sess);
    return OK;    
}

#define LEN (9000)
static int fail_long_header(void)
{
    char resp[LEN + 500] = "HTTP/1.1 200 OK\r\n"
	"Server: fish\r\n";
    size_t len = strlen(resp);
    
    /* add a long header */
    memset(resp + len, 'a', LEN);
    resp[len + LEN] = '\0';
    
    strcat(resp, "\r\n\r\n");

    return invalid_response_gives_error(resp, "Line too long");
}

static int fail_corrupt_chunks(void)
{
    static const struct {
        const char *resp, *error;
    } ts[] = {
        /* not CRLF */
        { RESP200 TE_CHUNKED "\r\n" "5\r\n" "abcdeFISH", 
          "delimiter was invalid" },
        /* short CRLF */
        { RESP200 TE_CHUNKED "\r\n" "5\r\n" "abcde\n",
          "not read chunk delimiter" },
        /* CR-notLF */
        { RESP200 TE_CHUNKED "\r\n" "5\r\n" "abcde\rZZZ",
          "delimiter was invalid" },
        { NULL, NULL }
    };
    int n;

    for (n = 0; ts[n].resp; n++)
        CALL(invalid_response_gives_error(ts[n].resp, ts[n].error));

    return OK;
}

static int versions(void)
{
    ne_session *sess;

    CALL(make_session(&sess, single_serve_string, 
		      "HTTP/1.1 200 OK\r\n"
		      "Content-Length: 0\r\n\r\n"

		      "HTTP/1.0 200 OK\r\n"
		      "Content-Length: 0\r\n\r\n"));
    
    CALL(any_request(sess, "/http11"));
	 
    ONN("did not detect HTTP/1.1 compliance",
	ne_version_pre_http11(sess) != 0);
	 
    CALL(any_request(sess, "/http10"));

    ONN("did not detect lack of HTTP/1.1 compliance",
	ne_version_pre_http11(sess) == 0);

    ne_session_destroy(sess);

    return OK;
}

struct cr_args {
    const char *method, *uri;
    int result;
};

static void hk_createreq(ne_request *req, void *userdata,
			 const char *method, const char *requri)
{
    struct cr_args *args = userdata;
    
    args->result = 1; /* presume failure */
    
    if (strcmp(args->method, method))
	t_context("Hook got method %s not %s", method, args->method);
    else if (strcmp(args->uri, requri))
	t_context("Hook got Req-URI %s not %s", requri, args->uri);
    else
	args->result = 0;
}

static int hook_create_req(void)
{
    ne_session *sess;
    struct cr_args args;

    CALL(make_session(&sess, single_serve_string, EMPTY_RESP EMPTY_RESP));

    ne_hook_create_request(sess, hk_createreq, &args);

    args.method = "GET";
    args.uri = "/foo";
    args.result = -1;

    CALL(any_request(sess, "/foo"));
    
    ONN("first hook never called", args.result == -1);
    if (args.result) return FAIL;

    args.uri = "http://localhost:7777/bar";
    args.result = -1;
    
    /* force use of absoluteURI in request-uri */
    ne_session_proxy(sess, "localhost", 7777);

    CALL(any_request(sess, "/bar"));
    
    ONN("second hook never called", args.result == -1);
    if (args.result) return FAIL;

    ne_session_destroy(sess);

    return OK;    
}

static int serve_check_method(ne_socket *sock, void *ud)
{
    char *method = ud;
    char buf[20];
    size_t methlen = strlen(method);

    if (ne_sock_read(sock, buf, methlen) != (ssize_t)methlen)
        return -1;
    
    ONN("method corrupted", memcmp(buf, method, methlen));
    
    return single_serve_string(sock, "HTTP/1.1 204 OK\r\n\r\n");
}
                             

/* Test that the method string passed to ne_request_create is
 * strdup'ed. */
static int dup_method(void)
{
    char method[] = "FOO";
    ne_session *sess;
    ne_request *req;

    CALL(make_session(&sess, serve_check_method, method));
    
    req = ne_request_create(sess, method, "/bar");
    
    strcpy(method, "ZZZ");

    ONREQ(ne_request_dispatch(req));
    ne_request_destroy(req);
    ne_session_destroy(sess);
    CALL(await_server());

    return OK;
}

ne_test tests[] = {
    T(lookup_localhost),
    T(single_get_clength),
    T(single_get_eof),
    T(single_get_chunked),
    T(no_body_204),
    T(no_body_205),
    T(no_body_304),
    T(no_body_HEAD),
    T(no_body_empty_clength),
    T(no_body_bad_clength),
    T(no_headers),
    T(chunks),
    T(te_header),
    T(any_te_header),
    T(reason_phrase),
    T(chunk_numeric),
    T(chunk_extensions),
    T(chunk_trailers),
    T(chunk_oversize),
    T(te_over_clength),
    T(te_over_clength2),
    T(no_body_chunks),
    T(persist_http11),
    T(persist_chunked),
    T(persist_http10),
    T(persist_timeout),
    T(no_persist_http10),
    T(ptimeout_eof),
    T(ptimeout_eof2),
    T(closed_connection),
    T(close_not_retried),
    T(send_progress),
    T(ignore_bad_headers),
    T(fold_headers),
    T(fold_many_headers),
    T(multi_header),
    T(empty_header),
    T(trailing_header),
    T(ignore_header_case),
    T(ignore_header_ws),
    T(ignore_header_ws2),
    T(ignore_header_ws3),
    T(ignore_header_tabs),
    T(continued_header),
    T(skip_interim_1xx),
    T(skip_many_1xx),
    T(skip_1xx_hdrs),
    T(send_bodies),
    T(expect_100_once),
    T(unbounded_headers),
    T(unbounded_folding),
    T(blank_response),
    T(not_http),
    T(fail_eof_continued),
    T(fail_eof_headers),
    T(fail_eof_chunk),
    T(fail_eof_badclen),
    T(fail_long_header),
    T(fail_corrupt_chunks),
    T(read_timeout),
    T(fail_lookup),
    T(fail_double_lookup),
    T(fail_connect),
    T(proxy_no_resolve),
    T(fail_chunksize),
    T(abort_respbody),
    T(retry_after_abort),
    T(fail_statusline),
    T(dup_method),
    T(versions),
    T(hook_create_req),
    T(NULL)
};