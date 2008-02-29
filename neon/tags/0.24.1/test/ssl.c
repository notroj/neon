/* 
   neon test suite
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

#include <sys/stat.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ne_request.h"
#include "ne_socket.h"
#include "ne_auth.h"

#include "tests.h"
#include "child.h"
#include "utils.h"

#ifndef NEON_SSL
/* this file shouldn't be built if SSL is not enabled. */
#error SSL not supported
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define ERROR_SSL_STRING (ERR_reason_error_string(ERR_get_error()))

#define SERVER_CERT "server.cert"
#define CA_CERT "ca/cert.pem"

#define SERVER_DNAME "Neon QA Dept, Neon Hackers Ltd, " \
                     "Cambridge, Cambridgeshire, GB"
#define CACERT_DNAME "Random Dept, Neosign, Oakland, California, US"

static SSL_CTX *server_ctx = NULL;

static char *srcdir = ".";

static ne_ssl_certificate *def_ca_cert = NULL, *def_server_cert;
static ne_ssl_client_cert *def_cli_cert;

static int check_dname(const ne_ssl_dname *dn, const char *expected,
                       const char *which);

static int s_strwrite(SSL *s, const char *buf)
{
    size_t len = strlen(buf);
    
    ONV(SSL_write(s, buf, len) != (int)len,
	("SSL_write failed: %s", ERROR_SSL_STRING));

    return OK;
}

/* Do an SSL response over socket given context; returning ssl session
 * structure in *sess if sess is non-NULL. */
static int do_ssl_response(ne_socket *sock, SSL_CTX *ctx, SSL_SESSION **sess,
			   const char *resp, int unclean)
{
    int fd = ne_sock_fd(sock), ret;
    /* we don't want OpenSSL to close this socket for us. */
    BIO *bio = BIO_new_socket(fd, BIO_NOCLOSE);
    char buf[BUFSIZ];
    SSL *ssl = SSL_new(ctx);

    ONN("SSL_new failed", ssl == NULL);

    SSL_set_bio(ssl, bio, bio);

    ONV(SSL_accept(ssl) != 1,
	("SSL_accept failed: %s", ERROR_SSL_STRING));

    ret = SSL_read(ssl, buf, BUFSIZ - 1);
    if (ret == 0)
	return 0; /* connection closed by parent; give up. */
    ONV(ret < 0, ("SSL_read failed (%d): %s", ret, ERROR_SSL_STRING));

    buf[ret] = '\0';

    NE_DEBUG(NE_DBG_HTTP, "Request over SSL was: [%s]\n", buf);

    ONN("request over SSL contained Proxy-Authorization header",
        strstr(buf, "Proxy-Authorization:") != NULL);

    CALL(s_strwrite(ssl, resp));

    /* copy out the session if requested. */
    if (sess) {
	*sess = SSL_get1_session(ssl);
    }	
    
    if (!unclean) {
	/* Erk, shutdown is messy! See Eric Rescorla's article:
	 * http://www.linuxjournal.com/article.php?sid=4822 ; we'll just
	 * hide our heads in the sand here. */
	SSL_shutdown(ssl);
	SSL_free(ssl);
    }

    return 0;
}

#define DEF_RESP "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"

/* Standard server callback to send an HTTP response; SSL negotiated
 * using certificate passed as userdata. */
static int serve_ssl(ne_socket *sock, void *ud)
{
    const char *cert = ud;

    NE_DEBUG(NE_DBG_HTTP, "using server cert %s\n", cert);

    ONN("failed to load certificate",
	!SSL_CTX_use_certificate_file(server_ctx, cert, SSL_FILETYPE_PEM));

    CALL(do_ssl_response(sock, server_ctx, NULL, DEF_RESP, 0));

    return OK;
}

static int serve_response_unclean(ne_socket *sock, void *ud)
{
    const char *resp = ud;

    ONN("failed to load certificate",
	!SSL_CTX_use_certificate_file(server_ctx, 
				      SERVER_CERT, SSL_FILETYPE_PEM));

    CALL(do_ssl_response(sock, server_ctx, NULL, resp, 1));

    return OK;
}    

/* Server function which requires the use of a client cert.
 * 'userdata' must be the name of the file giving acceptable CA
 * certificates. */
static int serve_ccert(ne_socket *sock, void *ud)
{
    const char *calist = ud;

    ONN("failed to load certificate",
	!SSL_CTX_use_certificate_file(server_ctx, SERVER_CERT, SSL_FILETYPE_PEM));
    
    /* require a client cert. */
    SSL_CTX_set_verify(server_ctx, SSL_VERIFY_PEER | 
		       SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* load the CA used to verify the client cert. */
    ONN("failed to load CA cert",
	SSL_CTX_load_verify_locations(server_ctx, CA_CERT, NULL) != 1);

    if (calist) {
        /* send acceptable CA cert list to the client */
        SSL_CTX_set_client_CA_list(server_ctx, SSL_load_client_CA_file(calist));
    }

    CALL(do_ssl_response(sock, server_ctx, NULL, DEF_RESP, 0));

    return OK;
}

/* serve_ssl wrapper which ignores server failure and always succeeds */
static int fail_serve(ne_socket *sock, void *ud)
{
    serve_ssl(sock, ud);
    return OK;
}

/* Wrapper for serve_ssl which registers the verify location, so that
 * the CA cert will be sent along with the server cert itself in the
 * certificate exchange. */
static int serve_ssl_chained(ne_socket *sock, void *ud)
{
    SSL_CTX_load_verify_locations(server_ctx, "ca/cert.pem", NULL);
    return serve_ssl(sock, ud);
}

#define DEFSESS  (ne_session_create("https", "localhost", 7777))

/* Run a request in the given session. */
static int any_ssl_request(ne_session *sess, server_fn fn, void *server_ud,
			   char *ca_cert,
			   ne_ssl_verify_fn verify_fn, void *verify_ud)
{
    int ret;
    
    if (ca_cert) {
        ne_ssl_certificate *ca = ne_ssl_cert_read(ca_cert);
        ONV(ca == NULL, ("could not load CA cert `%s'", ca_cert));
        ne_ssl_trust_cert(sess, ca);
        ne_ssl_cert_free(ca);
    }

    CALL(spawn_server(7777, fn, server_ud));

    if (verify_fn)
	ne_ssl_set_verify(sess, verify_fn, verify_ud);

    ret = any_request(sess, "/foo");

    CALL(await_server());
    
    ONREQ(ret);

    return OK;
}

static int init(void)
{
    char *server_key;
 
    /* take srcdir as argv[1]. */
    if (test_argc > 1) {
	srcdir = test_argv[1];
	server_key = ne_concat(srcdir, "/server.key", NULL);
    } else {
	server_key = "server.key";
    }
    
    if (ne_sock_init()) {
	t_context("could not initialize socket/SSL library.");
	return FAILHARD;
    }

    server_ctx = SSL_CTX_new(SSLv23_server_method());
    if (server_ctx == NULL) {
	t_context("could not create SSL_CTX: %s", ERROR_SSL_STRING);
	return FAILHARD;
    } else if (!SSL_CTX_use_PrivateKey_file(server_ctx, server_key, 
					    SSL_FILETYPE_PEM)) {
	t_context("failed to load private key: %s", ERROR_SSL_STRING);
	return FAILHARD;
    }

    def_ca_cert = ne_ssl_cert_read(CA_CERT);
    if (def_ca_cert == NULL) {
        t_context("couldn't load CA cert %s", CA_CERT);
        return FAILHARD;
    }

    def_server_cert = ne_ssl_cert_read(SERVER_CERT);
    if (def_server_cert == NULL) {
        t_context("couldn't load server cert %s", SERVER_CERT);
        return FAILHARD;
    }
    
    /* tests for the encrypted client cert, client.p12 */
    def_cli_cert = ne_ssl_clicert_read("client.p12");
    ONN("could not load client.p12", def_cli_cert == NULL);

    ONN("client.p12 is not encrypted!?", 
        !ne_ssl_clicert_encrypted(def_cli_cert));
    
    ONN("failed to decrypt client.p12",
        ne_ssl_clicert_decrypt(def_cli_cert, "foobar"));

    return OK;
}

/* just check the result codes of loading server certs. */
static int load_server_certs(void)
{
    ne_ssl_certificate *cert;

    cert = ne_ssl_cert_read("Makefile");
    ONN("invalid CA cert file loaded successfully", cert != NULL);

    cert = ne_ssl_cert_read("nonesuch.pem");
    ONN("non-existent 'nonesuch.pem' loaded successfully", cert != NULL);

    cert = ne_ssl_cert_read("ssigned.pem");
    ONN("could not load ssigned.pem", cert == NULL);
    ne_ssl_cert_free(cert);

    return OK;
}

static int trust_default_ca(void)
{
    ne_session *sess = DEFSESS;
    ne_ssl_trust_default_ca(sess);
    ne_session_destroy(sess);
    return OK;
}

#define CC_NAME "Just A Neon Client Cert"

/* Tests for loading client certificates */
static int load_client_cert(void)
{
    ne_ssl_client_cert *cc;
    const ne_ssl_certificate *cert;
    const char *name;

    cc = ne_ssl_clicert_read("client.p12");
    ONN("could not load client.p12", cc == NULL);
    ONN("client.p12 not encrypted!?", !ne_ssl_clicert_encrypted(cc));
    name = ne_ssl_clicert_name(cc);
    ONN("no friendly name given", name == NULL);
    ONV(strcmp(name, CC_NAME), ("friendly name was %s not %s", name, CC_NAME));
    ONN("failed to decrypt", ne_ssl_clicert_decrypt(cc, "foobar"));
    ne_ssl_clicert_free(cc);

    cc = ne_ssl_clicert_read("client.p12");
    ONN("decrypted client.p12 with incorrect password!?",
        ne_ssl_clicert_decrypt(cc, "barfoo") == 0);
    ne_ssl_clicert_free(cc);

    /* tests for the unencrypted client cert, client2.p12 */
    cc = ne_ssl_clicert_read("unclient.p12");
    ONN("could not load unencrypted cert unclient.p12", cc == NULL);
    ONN("unencrypted cert marked encrypted?", ne_ssl_clicert_encrypted(cc));
    cert = ne_ssl_clicert_owner(cc);
    ONN("client cert had no certificate", cert == NULL);
    CALL(check_dname(ne_ssl_cert_subject(cert),
                     "Neon Client Cert, Neon Hackers Ltd, "
                     "Cambridge, Cambridgeshire, GB",
                     "client cert subject"));
    CALL(check_dname(ne_ssl_cert_issuer(cert), CACERT_DNAME, 
                     "client cert issuer"));
    ne_ssl_clicert_free(cc);

    /* test for ccert without a friendly name, noclient.p12 */
    cc = ne_ssl_clicert_read("noclient.p12");
    ONN("could not load noclient.p12", cc == NULL);
    name = ne_ssl_clicert_name(cc);
    ONV(name != NULL, ("noclient.p12 had friendly name `%s'", name));
    ne_ssl_clicert_free(cc);

    /* tests for loading bogus files. */
    cc = ne_ssl_clicert_read("Makefile");
    ONN("loaded Makefile as client cert!?", cc != NULL);

    /* test for loading nonexistent file. */
    cc = ne_ssl_clicert_read("nosuch.pem");
    ONN("loaded nonexistent file as client cert!?", cc != NULL);

    return OK;
}

/* Test that 'cert', which is signed by CA_CERT, is accepted
 * unconditionaly. */
static int accept_signed_cert(char *cert)
{
    ne_session *sess = DEFSESS;
    /* no verify callback needed. */
    CALL(any_ssl_request(sess, serve_ssl, cert, CA_CERT, NULL, NULL));
    ne_session_destroy(sess);
    return OK;
}

static int simple(void)
{
    return accept_signed_cert(SERVER_CERT);
}

/* Serves using HTTP/1.0 get-till-EOF semantics. */
static int serve_eof(ne_socket *sock, void *ud)
{
    const char *cert = ud;

    NE_DEBUG(NE_DBG_HTTP, "using server cert %s\n", cert);

    ONN("failed to load certificate",
	!SSL_CTX_use_certificate_file(server_ctx, cert, SSL_FILETYPE_PEM));

    CALL(do_ssl_response(sock, server_ctx, NULL,
			 "HTTP/1.0 200 OK\r\n"
			 "Connection: close\r\n"
			 "\r\n"
			 "This is a response body, like it or not.",
			 0));

    return OK;
}

/* Test read-til-EOF behaviour with SSL. */
static int simple_eof(void)
{
    ne_session *sess = DEFSESS;

    CALL(any_ssl_request(sess, serve_eof, SERVER_CERT, CA_CERT, NULL, NULL));
    ne_session_destroy(sess);
    return OK;
}

static int empty_truncated_eof(void)
{
    ne_session *sess = DEFSESS;
    
    CALL(any_ssl_request(sess, serve_response_unclean,
			 "HTTP/1.0 200 OK\r\n" "\r\n",
			 CA_CERT, NULL, NULL));

    ne_session_destroy(sess);
    return OK;
}

static int fail_truncated_eof(void)
{
    ne_session *sess = DEFSESS;
    int ret;
    
    ne_ssl_trust_cert(sess, def_ca_cert);
    CALL(spawn_server(7777, serve_response_unclean,
		      "HTTP/1.0 200 OK\r\n" "\r\n"
		      "This is some content\n"
		      "Followed by a truncation attack!\n"));
    
    ret = any_request(sess, "/foo");
    CALL(await_server());
    
    ONV(ret != NE_ERROR,
	("request failed with %d not error: `%s'", ret, ne_get_error(sess)));
    ne_session_destroy(sess);
    return OK;
}

/* Server function which just sends a string then EOF. */
static int just_serve_string(ne_socket *sock, void *userdata)
{
    const char *str = userdata;
    server_send(sock, str, strlen(str));
    return 0;
}

/* test for the SSL negotiation failing. */
static int fail_not_ssl(void)
{
    ne_session *sess = DEFSESS;
    int ret;
    
    CALL(spawn_server(7777, just_serve_string, "Hello, world.\n"));
    ret = any_request(sess, "/bar");
    CALL(await_server());

    ONN("request did not fail", ret != NE_ERROR);

    ne_session_destroy(sess);
    return OK;
}

static int wildcard_ok = 0;    

static int wildcard_init(void)
{
    struct stat stbuf;
    
    t_context("wildcard.cert not found:\n"
	      "This test requires a Linux-like hostname command, see makekeys.sh");
    PRECOND(stat("wildcard.cert", &stbuf) == 0);

    PRECOND(lookup_hostname() == OK);

    wildcard_ok = 1;
    return OK;
}

static int wildcard_match(void)
{
    ne_session *sess;

    PRECOND(wildcard_ok);
    
    sess = ne_session_create("https", local_hostname, 7777);

    CALL(any_ssl_request(sess, serve_ssl, 
			 "wildcard.cert", CA_CERT, NULL, NULL));
    ne_session_destroy(sess);
    
    return OK;
}

/* Check that hostname comparisons are not cases-sensitive. */
static int caseless_match(void)
{
    return accept_signed_cert("caseless.cert");
}

/* Test that the subjectAltName extension has precedence over the
 * commonName attribute */
static int subject_altname(void)
{
    return accept_signed_cert("altname.cert");
}

/* tests for multiple altNames. */
static int two_subject_altname(void)
{
    return accept_signed_cert("altname2.cert");
}

static int two_subject_altname2(void)
{
    return accept_signed_cert("altname3.cert");
}

/* Test that a subject altname with *only* an eMail entry is
 * ignored, and the commonName is used instead. */
static int notdns_altname(void)
{
    return accept_signed_cert("altname4.cert");
}

/* test that the *most specific* commonName attribute is used. */
static int multi_commonName(void)
{
    return accept_signed_cert("twocn.cert");
}

/* regression test for neon <= 0.23.4 where if commonName was the first
 * RDN in the subject DN, it was ignored. */
static int commonName_first(void)
{
    return accept_signed_cert("cnfirst.cert");
}

static int check_dname(const ne_ssl_dname *dn, const char *expected,
                       const char *which)
{
    char *dname;

    ONV(dn == NULL, ("certificate %s dname was NULL", which));
    
    dname = ne_ssl_readable_dname(dn);

    NE_DEBUG(NE_DBG_SSL, "Got dname `%s', expecting `%s'\n", dname, expected);

    ONV(strcmp(dname, expected), 
        ("certificate %s dname was `%s' not `%s'", which, dname, expected));

    ne_free(dname);

    return 0;
}

/* Check that the readable subject issuer dnames of 'cert' match
 * 'subject' and 'issuer' (if non-NULL). */
static int check_cert_dnames(const ne_ssl_certificate *cert,
                             const char *subject, const char *issuer)
{
    ONN("no server certificate presented", cert == NULL);
    CALL(check_dname(ne_ssl_cert_subject(cert), subject, "subject"));
    return issuer ? check_dname(ne_ssl_cert_issuer(cert), issuer, "issuer") : OK;
}

/* Verify callback which checks that the certificate presented has the
 * predetermined subject and issuer DN (as per makekeys.sh). */
static int check_cert(void *userdata, int fs, const ne_ssl_certificate *cert)
{
    int *ret = userdata;

    if (check_cert_dnames(cert, SERVER_DNAME, CACERT_DNAME) == FAIL)
        *ret = -1;
    else
        *ret = 1;

    return 0;
}

/* Check that certificate attributes are passed correctly. */
static int parse_cert(void)
{
    ne_session *sess = DEFSESS;
    int ret = 0;

    /* don't give a CA cert; should force the verify callback to be
     * used. */
    CALL(any_ssl_request(sess, serve_ssl, SERVER_CERT, NULL, 
			 check_cert, &ret));
    ne_session_destroy(sess);

    ONN("cert verification never called", ret == 0);

    if (ret == -1)
	return FAIL;

    return OK;
}

/* Check the certificate chain presented against known dnames. */
static int check_chain(void *userdata, int fs, const ne_ssl_certificate *cert)
{
    int *ret = userdata;

    if (check_cert_dnames(cert, SERVER_DNAME, CACERT_DNAME) == FAIL) {
        *ret = -1;
        return 0;
    }
    
    cert = ne_ssl_cert_signedby(cert);
    if (cert == NULL) {
        t_context("no CA cert in chain");
        *ret = -1;
        return 0;
    }
    
    if (check_cert_dnames(cert, CACERT_DNAME, CACERT_DNAME) == FAIL) {
        *ret = -1;
        return 0;
    }
    
    *ret = 1;
    return 0;
}

/* Check that certificate attributes are passed correctly. */
static int parse_chain(void)
{
    ne_session *sess = DEFSESS;
    int ret = 0;

    /* don't give a CA cert; should force the verify callback to be
     * used. */
    CALL(any_ssl_request(sess, serve_ssl_chained, SERVER_CERT, NULL, 
			 check_chain, &ret));
    ne_session_destroy(sess);

    ONN("cert verification never called", ret == 0);

    if (ret == -1)
	return FAIL;

    return OK;
}


static int count_vfy(void *userdata, int fs, const ne_ssl_certificate *c)
{
    int *count = userdata;
    (*count)++;
    return 0;
}

static int no_verify(void)
{
    ne_session *sess = DEFSESS;
    int count = 0;

    CALL(any_ssl_request(sess, serve_ssl, SERVER_CERT, CA_CERT, count_vfy,
			 &count));

    ONN("verify callback called unnecessarily", count != 0);

    ne_session_destroy(sess);

    return OK;
}

static int cache_verify(void)
{
    ne_session *sess = DEFSESS;
    int ret, count = 0;
    
    /* force verify cert. */
    ret = any_ssl_request(sess, serve_ssl, SERVER_CERT, NULL, count_vfy,
			  &count);

    CALL(spawn_server(7777, serve_ssl, SERVER_CERT));
    ret = any_request(sess, "/foo2");
    CALL(await_server());

    ONV(count != 1,
	("verify callback result not cached: called %d times", count));

    ne_session_destroy(sess);

    return OK;
}

/* Copy failures into *userdata, and fail verification. */
static int get_failures(void *userdata, int fs, const ne_ssl_certificate *c)
{
    int *out = userdata;
    *out = fs;
    return -1;
}

/* Helper function: run a request using the given self-signed server
 * certificate, and expect the request to fail with the given
 * verification failure flags. */
static int fail_ssl_request(char *cert, char *cacert, 
			    const char *msg, int failures)
{
    ne_session *sess = DEFSESS;
    int gotf = 0, ret;

    ret = any_ssl_request(sess, fail_serve, cert, cacert,
			  get_failures, &gotf);

    ONV(gotf == 0,
	("no error in verification callback; request failed: %s",
	 ne_get_error(sess)));

    ONV(gotf & ~NE_SSL_FAILMASK,
	("verification flags %x outside mask %x", gotf, NE_SSL_FAILMASK));

    /* check the failure flags were as expected. */
    ONV(failures != gotf,
	("verification flags were %d not %d", gotf, failures));

    /* and check that the request was failed too. */
    ONN(msg, ret == NE_OK);

    ne_session_destroy(sess);

    return OK;
}

/* Note that the certs used for fail_* are all self-signed, so the
 * cert is passed as CA cert and server cert to fail_ssl_request. */

/* Check that a certificate with the incorrect commonName attribute is
 * flagged as such. */
static int fail_wrongCN(void)
{
    return fail_ssl_request("wrongcn.pem", "wrongcn.pem",
			    "certificate with incorrect CN was accepted",
			    NE_SSL_IDMISMATCH);
}

/* Check that an expired certificate is flagged as such. */
static int fail_expired(void)
{
    char *c = ne_concat(srcdir, "/expired.pem", NULL);
    CALL(fail_ssl_request(c, c, "expired certificate was accepted",
                          NE_SSL_EXPIRED));
    ne_free(c);
    return OK;
}

static int fail_notvalid(void)
{
    char *c = ne_concat(srcdir, "/notvalid.pem", NULL);
    CALL(fail_ssl_request(c, c, "not yet valid certificate was accepted",
                          NE_SSL_NOTYETVALID));
    ne_free(c);
    return OK;    
}

/* Check that a server cert with a random issuer and self-signed cert
 * fail with UNTRUSTED. */
static int fail_untrusted_ca(void)
{
    return fail_ssl_request("server.cert", NULL, "untrusted CA.",
			    NE_SSL_UNTRUSTED);
}

static int fail_self_signed(void)
{
    return fail_ssl_request("ssigned.pem", NULL, "self-signed cert", 
			    NE_SSL_UNTRUSTED);
}

/* Test for failure when a server cert is presented which has no
 * commonName (and no alt names either). */
static int fail_missing_CN(void)
{
    ne_session *sess = DEFSESS;

    ONN("accepted server cert with missing commonName",
        any_ssl_request(sess, fail_serve, "missingcn.cert", SERVER_CERT,
                        NULL, NULL) == NE_OK);
    
    ONV(strstr(ne_get_error(sess), "missing commonName") == NULL,
        ("unexpected session error `%s'", ne_get_error(sess)));

    ne_session_destroy(sess);
    return OK;
}                            

struct scache_args {
    SSL_CTX *ctx;
    char *cert;
    int count;
    SSL_SESSION *sess;
};

/* FIXME: factor out shared code with serve_ssl */
static int serve_scache(ne_socket *sock, void *ud)
{
    struct scache_args *args = ud;
    SSL_SESSION *sess;
    
    if (args->count == 0) {
	/* enable OpenSSL's internal session cache, enabling the
	 * negotiation to re-use a session if both sides support it. */
	SSL_CTX_set_session_cache_mode(args->ctx, SSL_SESS_CACHE_SERVER);
	
	ONN("failed to load certificate",
	    !SSL_CTX_use_certificate_file(args->ctx, 
					  args->cert, SSL_FILETYPE_PEM));
    }

    args->count++;

    CALL(do_ssl_response(sock, args->ctx, &sess, DEF_RESP, 0));

    /* dump session to child.log for debugging. */
    SSL_SESSION_print_fp(ne_debug_stream, sess);

    if (args->count == 1) {
	/* save the session. */
	args->sess = sess;
    } else {
	/* could just to do this with SSL_CTX_sess_hits really,
	 * but this is a more thorough test. */
	ONN("cached SSL session not used",
	    SSL_SESSION_cmp(args->sess, sess));
	SSL_SESSION_free(args->sess);
	SSL_SESSION_free(sess);
    }

    return 0;
}

/* Test that the SSL session is cached across connections. */
static int session_cache(void)
{
    struct scache_args args;
    ne_session *sess = ne_session_create("https", "localhost", 7777);
    
    args.ctx = server_ctx;
    args.count = 0;
    args.cert = SERVER_CERT;

    ne_ssl_trust_cert(sess, def_ca_cert);

    /* have spawned server listen for several connections. */
    CALL(spawn_server_repeat(7777, serve_scache, &args, 4));

    ONREQ(any_request(sess, "/req1"));
    ONREQ(any_request(sess, "/req2"));
    ne_session_destroy(sess);
    /* server should still be waiting for connections: if not,
     * something went wrong. */
    ONN("error from child", dead_server());
    /* now get rid of it. */
    reap_server();

    return OK;
}

/* Callback for client_cert_provider; takes a c. cert as userdata and
 * registers it. */
static void ccert_provider(void *userdata, ne_session *sess,
                           const ne_ssl_dname *const *dns, int dncount)
{
    const ne_ssl_client_cert *cc = userdata;
    ne_ssl_set_clicert(sess, cc);
}

/* Test that the on-demand client cert provider callback is used. */
static int client_cert_provided(void)
{
    ne_session *sess = DEFSESS;
    ne_ssl_client_cert *cc;

    cc = ne_ssl_clicert_read("client.p12");
    ONN("could not load client.p12", cc == NULL);
    ONN("could not decrypt client.p12", 
        ne_ssl_clicert_decrypt(cc, "foobar"));
    
    ne_ssl_provide_clicert(sess, ccert_provider, cc);
    CALL(any_ssl_request(sess, serve_ccert, NULL, CA_CERT,
                         NULL, NULL));

    ne_session_destroy(sess);
    ne_ssl_clicert_free(cc);
    return OK;
}

static void cc_check_dnames(void *userdata, ne_session *sess,
                            const ne_ssl_dname *const *dns, int dncount)
{
    int n, *ret = userdata;
    static const char *expected[4] = {
        "First Random CA, CAs Ltd., Lincoln, Lincolnshire, GB",
        "Second Random CA, CAs Ltd., Falmouth, Cornwall, GB",
        "Third Random CA, CAs Ltd., Ipswich, Suffolk, GB",
        "Fourth Random CA, CAs Ltd., Norwich, Norfolk, GB"
    };

    ne_ssl_set_clicert(sess, def_cli_cert);

    if (dncount != 4) {
        t_context("dname count was %d not 4", dncount);
        *ret = -1;
        return;
    }
    
    for (n = 0; n < 4; n++) {
        char which[5];

        sprintf(which, "%d", n);

        if (check_dname(dns[n], expected[n], which) == FAIL) {
            *ret = -1;
            return;
        }
    }

    *ret = 1;
}

/* Test for the list of acceptable dnames sent to the client. */
static int cc_provided_dnames(void)
{
    int check = 0;
    ne_session *sess = DEFSESS;

    PRECOND(def_cli_cert);

    ne_ssl_provide_clicert(sess, cc_check_dnames, &check);

    CALL(any_ssl_request(sess, serve_ccert, "calist.pem", CA_CERT, NULL, NULL));

    ne_session_destroy(sess);

    ONN("provider function not called", check == 0);

    return (check == -1) ? FAIL : OK;
}

/* Tests use of a client certificate. */
static int client_cert_pkcs12(void)
{
    ne_session *sess = DEFSESS;

    PRECOND(def_cli_cert);

    ne_ssl_set_clicert(sess, def_cli_cert);
    CALL(any_ssl_request(sess, serve_ccert, NULL, CA_CERT, NULL, NULL));

    ne_session_destroy(sess);    
    return OK;
}


/* Tests use of an unencrypted client certificate. */
static int ccert_unencrypted(void)
{
    ne_session *sess = DEFSESS;
    ne_ssl_client_cert *ccert;

    ccert = ne_ssl_clicert_read("unclient.p12");
    ONN("unclient.p12 was encrypted", ne_ssl_clicert_encrypted(ccert));

    ne_ssl_set_clicert(sess, ccert);
    CALL(any_ssl_request(sess, serve_ccert, NULL, CA_CERT, NULL, NULL));

    ne_ssl_clicert_free(ccert);
    ne_session_destroy(sess);
    return OK;
}

static int serve_tunnel(ne_socket *sock, void *ud)
{
    CALL(discard_request(sock));
 
    SEND_STRING(sock, "HTTP/1.1 200 OK\r\nServer: Fish\r\n\r\n");
    return serve_ssl(sock, ud);
}

/* neon versions <= 0.21.2 segfault here because ne_sock_close would
 * be called twice on the socket after the server cert verification
 * fails. */
static int fail_tunnel(void)
{
    ne_session *sess = ne_session_create("https", "example.com", 443);
    ne_session_proxy(sess, "localhost", 7777);

    ONN("server cert verification didn't fail",
	any_ssl_request(sess, serve_tunnel, SERVER_CERT, CA_CERT,
			NULL, NULL) != NE_ERROR);
    
    ne_session_destroy(sess);
    return OK;
}

static int proxy_tunnel(void)
{
    ne_session *sess = ne_session_create("https", "localhost", 443);
    ne_session_proxy(sess, "localhost", 7777);
    
    /* CA cert is trusted, so no verify callback should be needed. */
    CALL(any_ssl_request(sess, serve_tunnel, SERVER_CERT, CA_CERT,
			 NULL, NULL));

    ne_session_destroy(sess);
    return OK;
}

/* a tricky test which requires spawning a second server process in
 * time for a new connection after a 407. */
static int apt_post_send(ne_request *req, void *ud, const ne_status *st)
{
    if (st->code == 407) {
        NE_DEBUG(NE_DBG_HTTP, "Got 407, awaiting server...\n");
        CALL(await_server());
        NE_DEBUG(NE_DBG_HTTP, "Spawning proper tunnel server...\n");
        CALL(spawn_server(7777, serve_tunnel, SERVER_CERT));
        NE_DEBUG(NE_DBG_HTTP, "Spawned.\n");
    }
    return OK;
}

static int apt_creds(void *userdata, const char *realm, int attempt,
                     char *username, char *password)
{
    strcpy(username, "foo");
    strcpy(password, "bar");
    return 0;
}

/* Test for using SSL over a CONNECT tunnel via a proxy server which
 * requires authentication.  Broke briefly between 0.23.x and
 * 0.24.0. */
static int auth_proxy_tunnel(void)
{
    ne_session *sess = ne_session_create("https", "localhost", 443);
    int ret;
    
    ne_session_proxy(sess, "localhost", 7777);
    ne_hook_post_send(sess, apt_post_send, NULL);
    ne_set_proxy_auth(sess, apt_creds, NULL);
    
    CALL(spawn_server(7777, single_serve_string,
                      "HTTP/1.0 407 I WANT MORE BISCUITS\r\n"
                      "Proxy-Authenticate: Basic realm=\"bigbluesea\"\r\n"
                      "Connection: close\r\n" "\r\n"));
    
    /* trust the CA */
    ne_ssl_trust_cert(sess, def_ca_cert);
    /* run the dreaded request. */
    ret = any_request(sess, "/foobar");
    CALL(await_server());
    ONREQ(ret);

    ne_session_destroy(sess);
    return 0;
}

/* Compare against known digest of notvalid.pem.  Via:
 *   $ openssl x509 -fingerprint -sha1 -noout -in notvalid.pem */
#define THE_DIGEST "cf:5c:95:93:76:c6:3c:01:8b:62:" \
                   "b1:6f:f7:7f:42:32:ac:e6:69:1b"

static int cert_fingerprint(void)
{
    char *fn = ne_concat(srcdir, "/notvalid.pem", NULL);
    ne_ssl_certificate *cert = ne_ssl_cert_read(fn);
    char digest[60];
    
    ne_free(fn);

    ONN("could not load notvalid.pem", cert == NULL);

    ONN("failed to digest", ne_ssl_cert_digest(cert, digest));
    ne_ssl_cert_free(cert);

    ONV(strcmp(digest, THE_DIGEST),
        ("digest was %s not %s", digest, THE_DIGEST));

    return OK;
}

/* verify that identity of certificate in filename 'fname' is 'identity' */
static int check_identity(const char *fname, const char *identity)
{
    ne_ssl_certificate *cert = ne_ssl_cert_read(fname);
    const char *id;

    ONV(cert == NULL, ("could not read cert `%s'", fname));

    id = ne_ssl_cert_identity(cert);

    if (identity) {
        ONV(id == NULL, ("certificate `%s' had no identity", fname));
        ONV(strcmp(id, identity), 
            ("certificate `%s' had identity `%s' not `%s'", fname, 
             id, identity));
    } else {
        ONV(id != NULL, ("certificate `%s' had identity `%s' (expected none)",
                         fname, id));
    }            
    
    ne_ssl_cert_free(cert);
    return OK;
}

/* check certificate identities. */
static int cert_identities(void)
{
    static const struct {
        const char *fname, *identity;
    } certs[] = {
        { "twocn.cert", "localhost" },
        { "altname.cert", "localhost" },
        { "altname2.cert", "nohost.example.com" },
        { "altname4.cert", "localhost" },
        { "ca4.pem", "fourth.example.com" },
        { NULL, NULL }
    };
    int n;

    for (n = 0; certs[n].fname != NULL; n++)
        CALL(check_identity(certs[n].fname, certs[n].identity));

    return OK;
}

static int check_validity(const char *fname,
                          const char *from, const char *until)
{
    char actfrom[NE_SSL_VDATELEN], actuntil[NE_SSL_VDATELEN];
    ne_ssl_certificate *cert;

    cert = ne_ssl_cert_read(fname);
    ONV(cert == NULL, ("could not load cert `%s'", fname));

    /* cover all calling combos for nice coverage analysis */
    ne_ssl_cert_validity(cert, NULL, NULL);
    ne_ssl_cert_validity(cert, actfrom, NULL);
    ne_ssl_cert_validity(cert, NULL, actuntil);
    ne_ssl_cert_validity(cert, actfrom, actuntil);

    ONV(strcmp(actfrom, from), 
        ("%s: start time was `%s' not `%s'", fname, actfrom, from));

    ONV(strcmp(actuntil, until), 
        ("%s: end time was `%s' not `%s'", fname, actuntil, until));

    ne_ssl_cert_free(cert);
    return OK;
}

/* ceritificate validity times. */
static int cert_validity(void)
{
    char *cert = ne_concat(srcdir, "/expired.pem", NULL);
    CALL(check_validity(cert, "Jan 21 20:39:04 2002 GMT", "Jan 31 20:39:04 2002 GMT"));
    ne_free(cert);
    cert = ne_concat(srcdir, "/notvalid.pem", NULL);
    CALL(check_validity(cert, "Dec 27 20:40:29 2023 GMT", "Dec 28 20:40:29 2023 GMT"));
    ne_free(cert);
    return OK;
}

/* dname comparisons. */
static int dname_compare(void)
{
    ne_ssl_certificate *ssigned;
    const ne_ssl_dname *dn1, *dn2;
    
    dn1 = ne_ssl_cert_subject(def_server_cert);
    dn2 = ne_ssl_cert_subject(def_server_cert);
    ONN("identical subject names not equal", ne_ssl_dname_cmp(dn1, dn2) != 0);

    dn2 = ne_ssl_cert_issuer(def_server_cert);
    ONN("issuer and subject names equal for signed cert",
        ne_ssl_dname_cmp(dn1, dn2) == 0);
    
    dn1 = ne_ssl_cert_subject(def_ca_cert);
    ONN("issuer of signed cert not equal to subject of CA cert",
        ne_ssl_dname_cmp(dn1, dn2) != 0);

    ssigned = ne_ssl_cert_read("ssigned.pem");
    ONN("could not load ssigned.pem", ssigned == NULL);

    dn1 = ne_ssl_cert_subject(ssigned);
    dn2 = ne_ssl_cert_issuer(ssigned);
    ONN("issuer and subject names not equal for self-signed cert",
        ne_ssl_dname_cmp(dn1, dn2));
    ne_ssl_cert_free(ssigned);

    return OK;
}

/* tests for ne_ssl_readable_dname */
static int dname_readable(void)
{
    ne_ssl_certificate *cert;

    cert = ne_ssl_cert_read("justmail.cert");
    ONN("could not load justmail.cert", cert == NULL);

    CALL(check_cert_dnames(cert, "blah@example.com", NULL));
    ne_ssl_cert_free(cert);

    return OK;
}

/* test cert comparisons */
static int cert_compare(void)
{
    ne_ssl_certificate *c1, *c2;

    c1 = ne_ssl_cert_read("server.cert");
    c2 = ne_ssl_cert_read("server.cert");
    ONN("identical certs don't compare equal", ne_ssl_cert_cmp(c1, c2) != 0);
    ONN("identical certs don't compare equal", ne_ssl_cert_cmp(c2, c1) != 0);
    ne_ssl_cert_free(c2);

    c2 = ne_ssl_cert_read("ssigned.pem");
    ONN("different certs don't compare different",
        ne_ssl_cert_cmp(c1, c2) == 0);
    ONN("different certs don't compare different",
        ne_ssl_cert_cmp(c2, c1) == 0);
    ne_ssl_cert_free(c2);
    ne_ssl_cert_free(c1);

    return OK;
}

/* Extract raw base64 string from a PEM file */
static int flatten_pem(const char *fname, char **out)
{
    FILE *fp = fopen(fname, "r");
    char buf[80];
    size_t outlen = 0;
    int ignore = 1;

    ONV(fp == NULL, ("could not open %s", fname));

    *out = NULL;

    while (fgets(buf, sizeof buf, fp) != NULL) {
        size_t len = strlen(buf) - 1;
        
        if (len < 1) continue;

        /* look for the wrapper lines. */
        if (strncmp(buf, "-----", 5) == 0) {
            ignore = !ignore;
            continue;
        }

        /* ignore until the first wrapper line */
        if (ignore) continue;
        
        *out = realloc(*out, outlen + len + 1);
        memcpy(*out + outlen, buf, len);
        outlen += len;
    }

    (*out)[outlen] = '\0';
    fclose(fp);

    return OK;
}

/* check export cert data 'actual' against expected data 'expected */
static int check_exported_data(const char *actual, const char *expected)
{
    ONN("could not export cert", actual == NULL);

    ONN("export data contained newline",
        strchr(actual, '\r') || strchr(actual, '\n'));        

    ONV(strcmp(actual, expected), ("exported cert differed from expected:\n"
                                   "actual: %s\nexpected: %s", 
                                   actual, expected));
    return OK;
}

/* Test import and export of certificates.  The export format is PEM
 * without the line feeds and wrapping; compare against . */
static int import_export(void)
{
    char *expected, *actual;
    ne_ssl_certificate *cert, *imp;

    CALL(flatten_pem("server.cert", &expected));
    
    cert = ne_ssl_cert_read("server.cert");
    ONN("could not load server.cert", cert == NULL);

    /* export the cert to and compare it with the PEM file */
    actual = ne_ssl_cert_export(cert);
    CALL(check_exported_data(actual, expected));

    /* import the exported cert data, check it looks the same */
    imp = ne_ssl_cert_import(actual);
    ONN("failed to import exported cert", imp == NULL);
    ONN("imported cert was different to original", 
        ne_ssl_cert_cmp(imp, cert));

    /* re-export the imported cert and check that looks the same */
    ne_free(actual);
    actual = ne_ssl_cert_export(imp);
    CALL(check_exported_data(actual, expected));
    ne_ssl_cert_free(imp);

    /* try importing from bogus data */
    imp = ne_ssl_cert_import("!!");
    ONN("imported bogus cert from bogus base64", imp != NULL);
    imp = ne_ssl_cert_import("aaaa");
    ONN("imported bogus cert from valid base64", imp != NULL);

    ne_ssl_cert_free(cert);
    ne_free(actual);
    ne_free(expected);
    return OK;
}

/* Test write/read */
static int read_write(void)
{
    ne_ssl_certificate *c1, *c2;

    c1 = ne_ssl_cert_read("server.cert");
    ONN("could not load server.cert", c1 == NULL);

    ONN("could not write output.pem", ne_ssl_cert_write(c1, "output.pem"));
    
    ONN("wrote to nonexistent directory",
        ne_ssl_cert_write(c1, "nonesuch/output.pem") == 0);

    c2 = ne_ssl_cert_read("output.pem");
    ONN("could not read output.pem", c2 == NULL);
    
    ONN("read of output.pem differs from original",
        ne_ssl_cert_cmp(c2, c1));

    ne_ssl_cert_free(c1);
    ne_ssl_cert_free(c2);

    return OK;
}

/* A verification callback which caches the passed cert. */
static int verify_cache(void *userdata, int fs,
                        const ne_ssl_certificate *cert)
{
    char **cache = userdata;
    
    if (*cache == NULL) {
        *cache = ne_ssl_cert_export(cert);
        return 0;
    } else {
        return -1;
    }
}

/* Test a common use of the SSL API; cache the server cert across
 * sessions. */
static int cache_cert(void)
{
    ne_session *sess = DEFSESS;
    char *cache = NULL;
    ne_ssl_certificate *cert;

    ONREQ(any_ssl_request(sess, serve_ssl, "ssigned.pem", CA_CERT,
                          verify_cache, &cache));
    ne_session_destroy(sess);

    ONN("no cert was cached", cache == NULL);
    
    /* make a real cert */
    cert = ne_ssl_cert_import(cache);
    ONN("could not import cached cert", cert == NULL);
    ne_free(cache);

    /* create a new session */
    sess = DEFSESS;
    /* trust the cert */
    ne_ssl_trust_cert(sess, cert);
    ne_ssl_cert_free(cert);
    /* now, the request should succeed without manual verification */
    ONREQ(any_ssl_request(sess, serve_ssl, "ssigned.pem", CA_CERT,
                          NULL, NULL));
    ne_session_destroy(sess);
    return OK;
}

/* TODO: code paths still to test in cert verification:
 * - server cert changes between connections: Mozilla gives
 * a "bad MAC decode" error for this; can do better?
 * - server presents no certificate (using ADH ciphers)... can
 * only really happen if they mess with the SSL_CTX and enable
 * ADH cipher manually; but good to check the failure case is 
 * safe.
 * From the SSL book:
 * - an early FIN should be returned as a possible truncation attack,
 * NOT just an NE_SOCK_CLOSED.
 * - unexpected close_notify is an error but not an attack.
 * - never attempt session resumption after any aborted connection.
 */

ne_test tests[] = {
    T_LEAKY(init),

    T(load_server_certs),
    T(trust_default_ca),

    T(cert_fingerprint),
    T(cert_identities),
    T(cert_validity),
    T(cert_compare),
    T(dname_compare),
    T(dname_readable),
    T(import_export),
    T(read_write),

    T(load_client_cert),

    T(simple),
    T(simple_eof),
    T(empty_truncated_eof),
    T(fail_truncated_eof),
    T(fail_not_ssl),
    T(cache_cert),

    T(client_cert_pkcs12),
    T(ccert_unencrypted),
    T(client_cert_provided),
    T(cc_provided_dnames),

    T(parse_cert),
    T(parse_chain),

    T(no_verify),
    T(cache_verify),
    T_LEAKY(wildcard_init),
    T(wildcard_match),
    T(caseless_match),

    T(subject_altname),
    T(two_subject_altname),
    T(two_subject_altname2),
    T(notdns_altname),

    T(multi_commonName),
    T(commonName_first),

    T(fail_wrongCN),
    T(fail_expired),
    T(fail_notvalid),
    T(fail_untrusted_ca),
    T(fail_self_signed),
    T(fail_missing_CN),

    T(session_cache),
	
    T(fail_tunnel),
    T(proxy_tunnel),
    T(auth_proxy_tunnel),

    T(NULL) 
};