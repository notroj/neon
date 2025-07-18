/* 
   neon test suite
   Copyright (C) 2002-2025, Joe Orton <joe@manyfish.co.uk>

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
#include <errno.h>

#include "ne_request.h"
#include "ne_socket.h"
#include "ne_ssl.h"
#include "ne_auth.h"

#include "tests.h"
#include "child.h"
#include "utils.h"

#ifndef NE_HAVE_SSL
/* this file shouldn't be built if SSL is not enabled. */
#error SSL not supported
#endif

#include "ne_pkcs11.h"

#define SERVER_CERT "server.cert"
#define CA2_SERVER_CERT "ca2server.pem"
#define CA_CERT "ca/cert.pem"

#define P12_PASSPHRASE "foobar"

#define SERVER_DNAME "Neon QA Dept, Neon Hackers Ltd, " \
                     "Cambridge, Cambridgeshire, GB"
#define CACERT_DNAME "Random Dept, Neosign, Oakland, California, US"

static char *srcdir = ".";
static char *server_key = NULL; 

static ne_ssl_certificate *def_ca_cert = NULL, *def_server_cert;
static ne_ssl_client_cert *def_cli_cert;

static char *nul_cn_fn;

static int check_dname(const ne_ssl_dname *dn, const char *expected,
                       const char *which);

static int check_cert_dnames(const ne_ssl_certificate *cert,
                             const char *subject, const char *issuer)
    ne_attribute((nonnull (2)));

/* Arguments for running the SSL server */
struct ssl_server_args {
    char *cert; /* the server cert to present. */
    const char *key; /* server key filename */
    const char *response; /* the HTTP response message to send. */
    int numreqs; /* number of request/responses to handle over the SSL connection. */

    /* client cert handling: */
    int require_cc; /* require a client cert if non-NULL */
    const char *ca_list; /* file of CA certs to verify client cert against */
    int fail_silently; /* exit with success if handshake fails */
    
    /* session caching: */
    int cache; /* use the session cache if non-zero */
    struct ssl_session {
        unsigned char id[128];
        size_t len;
    } session;
    int count; /* internal use. */

    /* minimum, maximum version. */
    enum ne_ssl_protocol minver, maxver;
};

/* default response string if args->response is NULL */
#define DEF_RESP "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"

/* An SSL server inna bun. */
static int ssl_server(ne_socket *sock, void *userdata)
{
    struct ssl_server_args *args = userdata;
    int ret;
    char buf[BUFSIZ];
    const char *key;
    static ne_ssl_context *ctx = NULL;

    if (ctx == NULL) {
        ctx = ne_ssl_context_create(NE_SSL_CTX_SERVER);
    }

    ONV(ctx == NULL, ("could not create SSL context"));

    key = args->key ? args->key : server_key;
    NE_DEBUG(NE_DBG_HTTP, "SSL server init with keypair (%s, %s).\n",
             args->cert, key);
             
    ONV(ne_ssl_context_keypair(ctx, args->cert, key),
        ("failed to load server keypair: ..."));

    if (args->require_cc && !args->ca_list) {
        args->ca_list = CA_CERT;
    }

    ne_ssl_context_set_verify(ctx, args->require_cc, 
                              args->ca_list, args->ca_list);

    ret = ne_sock_accept_ssl(sock, ctx);
    if (ret && args->fail_silently) {
        return 0;
    }
    ONV(ret, ("SSL accept failed: %s", ne_sock_error(sock)));

    args->count++;

    /* loop handling requests: */
    do {
        const char *response = args->response ? args->response : DEF_RESP;

        ret = ne_sock_read(sock, buf, BUFSIZ - 1);
        if (ret == NE_SOCK_CLOSED)
            return 0; /* connection closed by parent; give up. */
        ONV(ret < 0, ("SSL read failed (%d): %s", ret, 
                      ne_sock_error(sock)));
        
        buf[ret] = '\0';
        
        NE_DEBUG(NE_DBG_HTTP, "Request over SSL was: [%s]\n", buf);
        
        if (strstr(buf, "Proxy-Authorization:") != NULL) {
            NE_DEBUG(NE_DBG_HTTP, "Got Proxy-Auth header over SSL!\n");
            response = "HTTP/1.1 500 Client Leaks Credentials\r\n"
                "Content-Length: 0\r\n" "\r\n";
        }
        
        ONV(ne_sock_fullwrite(sock, response, strlen(response)),
            ("SSL write failed: %s", ne_sock_error(sock)));
        
    } while (--args->numreqs > 0);

    if (args->minver || args->maxver) {
        unsigned int vers = ne_sock_getproto(sock);
        const char *name = ne_ssl_proto_name(vers);

        NE_DEBUG(NE_DBG_HTTP, "ssl: TLS protocol version (%d): [%s]\n", 
                 vers, name);

        ONV((args->minver && vers < args->minver)
            || (args->maxver && vers > args->maxver),
            ("SSL protocol version %d (%s) outside range (%d, %d)",
             vers, name, args->minver, args->maxver));
    }

    if (args->cache) {
        unsigned char sessid[128];
        size_t len = sizeof sessid;

        ONN("could not retrieve session ID",
            ne_sock_sessid(sock, sessid, &len));
        
#ifdef NE_DEBUGGING
        {
            char *b64 = ne_base64(sessid, len);
            NE_DEBUG(NE_DBG_SSL, "ssl: Session id retrieved (%d): [%s]\n", 
                     args->count, b64);
            ne_free(b64);
        }
#endif
        
        if (args->count == 1) {
            /* save the session. */
            memcpy(args->session.id, sessid, len);
            args->session.len = len;
        } else {
            /* Compare with stored session. */
            ONN("cached session not used", 
                args->session.len != len
                || memcmp(args->session.id, sessid, len));
        }
    }	

    ret = ne_sock_shutdown(sock, NE_SOCK_SEND);
    NE_DEBUG(NE_DBG_SSL, "ssl: Shutdown received %d\n", ret);
    
    return 0;
}

#define DEFSESS  (ne_session_create("https", "localhost", 7777))

static int make_ssl_session_port(ne_session **sess,
                                 const char *hostname, int port,
                                 server_fn fn, void *userdata)
{
    return fakeproxied_session_server(sess, "https", hostname, port,
                                      fn, userdata);
}

static int make_ssl_session(ne_session **sess, const char *hostname,
                            server_fn fn, void *userdata)
{
    return make_ssl_session_port(sess,
                                 hostname ? hostname : "localhost", 7777,
                                 fn, userdata);
}

/* Runs SSL server which will accept 'count' connections, running
 * ssl_server as callback with given 'args'. */
static int multi_ssl_session(int count, ne_session **sess,
                             struct ssl_server_args *args)
{
    return fakeproxied_multi_session_server(count, sess, "https",
                                            "localhost",
                                            7777,
                                            ssl_server, args);
}


static int load_and_trust_cert(ne_session *sess, const char *ca_cert)
{
    ne_ssl_certificate *ca = ne_ssl_cert_read(ca_cert);
    ONV(ca == NULL, ("could not load CA cert `%s'", ca_cert));
    ne_ssl_trust_cert(sess, ca);
    ne_ssl_cert_free(ca);
    return OK;
}

static int make_ssl_request(struct ssl_server_args *args,
                            const char *ca_cert, const char *hostname,
                            ne_ssl_verify_fn verify_fn, void *verify_ud)
{
    ne_session *sess;

    CALL(make_ssl_session(&sess, hostname, ssl_server, args));

    if (ca_cert) CALL(load_and_trust_cert(sess, ca_cert));
    
    if (verify_fn) ne_ssl_set_verify(sess, verify_fn, verify_ud);

    CALL(any_2xx_request(sess, "/foo"));

    return destroy_and_wait(sess);
}

/* Run a request in the given session. */
static int any_ssl_request(ne_session *sess, server_fn fn, void *server_ud,
			   char *ca_cert,
			   ne_ssl_verify_fn verify_fn, void *verify_ud)
{
    if (ca_cert) {
        CALL(load_and_trust_cert(sess, ca_cert));
    }

    CALL(spawn_server(7777, fn, server_ud));

    if (verify_fn)
	ne_ssl_set_verify(sess, verify_fn, verify_ud);

    ONREQ(any_request(sess, "/foo"));

    return await_server();
}

static int init(void)
{
    /* take srcdir as argv[1] for VPATH builds. */
    if (test_argc > 1) {
        srcdir = test_argv[1];
    }
        
    /* take srcdir as argv[1]. */
    server_key = "server.key";
    
    if (ne_sock_init()) {
	t_context("could not initialize socket/SSL library.");
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
    if (def_cli_cert == NULL) {
        t_context("could not load client.p12");
        return FAILHARD;
    }

    if (!ne_ssl_clicert_encrypted(def_cli_cert)) {
        ne_ssl_clicert_free(def_cli_cert);
        def_cli_cert = NULL;
        t_context("client.p12 is not encrypted!?");
        return FAIL;
    }

    if (ne_ssl_clicert_decrypt(def_cli_cert, P12_PASSPHRASE)) {
        ne_ssl_clicert_free(def_cli_cert);
        def_cli_cert = NULL;
        t_context("failed to decrypt client.p12");
        return FAIL;
    }

    nul_cn_fn = ne_concat(srcdir, "/nulcn.pem", NULL);

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
    if (name == NULL) {
        t_warning("no friendly name given");
    } else {
        ONV(strcmp(name, CC_NAME), ("friendly name was %s not %s", name, CC_NAME));
    }
    ONN("failed to decrypt", ne_ssl_clicert_decrypt(cc, P12_PASSPHRASE));
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

    /* test for ccert with a bundled CA. */
    cc = ne_ssl_clicert_read("clientca.p12");
    ONN("could not load clientca.p12", cc == NULL);
    ONN("encrypted cert marked unencrypted?", !ne_ssl_clicert_encrypted(cc));
    ONN("could not decrypt clientca.p12", 
        ne_ssl_clicert_decrypt(cc, P12_PASSPHRASE));
    ne_ssl_clicert_free(cc);

    /* test for ccert without a private key, nkclient.p12 */
    cc = ne_ssl_clicert_read("nkclient.p12");
    ONN("did not fail to load clicert without pkey", cc != NULL);
    
    /* test for ccert without a cert, ncclient.p12 */
    cc = ne_ssl_clicert_read("ncclient.p12");
    ONN("did not fail to load clicert without cert", cc != NULL);

    /* tests for loading bogus files. */
    cc = ne_ssl_clicert_read("Makefile");
    ONN("loaded Makefile as client cert!?", cc != NULL);

    /* test for loading nonexistent file. */
    cc = ne_ssl_clicert_read("nosuch.pem");
    ONN("loaded nonexistent file as client cert!?", cc != NULL);

    return OK;
}

static int clicert_import(void)
{
    ne_ssl_client_cert *cc;
    ne_buffer *buf = ne_buffer_create();

    CALL(file_to_buffer("client.p12", buf));

    cc = ne_ssl_clicert_import((unsigned char *)buf->data, ne_buffer_size(buf));
    ONN("could not import client cert from buffer", cc == NULL);
    
    ONN("failed to decrypt", ne_ssl_clicert_decrypt(cc, P12_PASSPHRASE));
    ne_ssl_clicert_free(cc);
    ne_buffer_destroy(buf);

    return OK;
}

/* Test that 'cert', which is signed by CA_CERT, is accepted
 * unconditionally. */
static int accept_signed_cert_for_hostname(char *cert, const char *hostname)
{
    struct ssl_server_args args = {cert, 0};

    /* no verify callback needed. */
    return make_ssl_request(&args, CA_CERT, hostname, NULL, NULL);
}


static int accept_signed_cert(char *cert)
{
    return accept_signed_cert_for_hostname(cert, "localhost");
}

static int simple(void)
{
    return accept_signed_cert(SERVER_CERT);
}

/* Test read-til-EOF behaviour with SSL. */
static int simple_eof(void)
{
    struct ssl_server_args args = {SERVER_CERT, 0};

    args.response = "HTTP/1.0 200 OK\r\n"
        "Connection: close\r\n"
        "\r\n"
        "This is a response body, like it or not.";

    return make_ssl_request(&args, CA_CERT, NULL, NULL, NULL);
}

static int intermediary(void)
{
    struct ssl_server_args args = {CA2_SERVER_CERT, 0};

    return make_ssl_request(&args, CA_CERT, NULL, NULL, NULL);
}

static int empty_truncated_eof(void)
{
    struct ssl_server_args args = {0};

    args.cert = SERVER_CERT;
    args.response = "HTTP/1.0 200 OK\r\n" "\r\n";
    
    return make_ssl_request(&args, CA_CERT, NULL, NULL, NULL);
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
    ne_session *sess;
    int ret;
    
    CALL(make_ssl_session(&sess, NULL, just_serve_string, "Hello, world.\n"));
    ret = any_request(sess, "/bar");
    ONN("request did not fail", ret != NE_ERROR);

    return destroy_and_wait(sess);
}

static int wildcard_match(void)
{
    struct ssl_server_args args = {"wildcard.cert", 0};

    return make_ssl_request(&args, CA_CERT, "bar.example.com", NULL, NULL);
}

static int wildcard_match_altname(void)
{
    struct ssl_server_args args = {"altname9.cert", 0};

    return make_ssl_request(&args, CA_CERT, "foo.example.com", NULL, NULL);
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
    return accept_signed_cert("altname1.cert");
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

static int ipaddr_altname(void)
{
    return accept_signed_cert_for_hostname("altname5.cert", "127.0.0.1");
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

    ONV(!dname || strcmp(dname, expected),
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
    struct ssl_server_args args = {SERVER_CERT, 0};
    int ret = 0;

    /* don't give a CA cert; should force the verify callback to be
     * used. */
    CALL(make_ssl_request(&args, NULL, NULL, check_cert, &ret));

    ONN("cert verification never called", ret == 0);

    if (ret == -1)
	return FAIL;

    return OK;
}

#define WRONGCN_DNAME "Bad Hostname Department, Neon Hackers Ltd, " \
    "Cambridge, Cambridgeshire, GB"

/* Check the certificate chain presented against known dnames. */
static int check_chain(void *userdata, int fs, const ne_ssl_certificate *cert)
{
    int *ret = userdata;

    if (check_cert_dnames(cert, WRONGCN_DNAME, CACERT_DNAME) == FAIL) {
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
    int ret = 0;
    struct ssl_server_args args = {"wrongcn.cert", 0};

    args.ca_list = CA_CERT;

    /* The cert is signed by the CA but has a CN mismatch, so will
     * force the verification callback to be invoked. */
    CALL(make_ssl_request(&args, CA_CERT, NULL, check_chain, &ret));

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
    int count = 0;
    struct ssl_server_args args = {SERVER_CERT, 0};

    CALL(make_ssl_request(&args, CA_CERT, NULL, count_vfy, &count));

    ONN("verify callback called unnecessarily", count != 0);

    return OK;
}

/* Checks that the verify callback is only called on the first
 * connection to the SSL server, and not on subsequent connections. */
static int cache_verify(void)
{
    ne_session *sess;
    int count = 0;
    struct ssl_server_args args = {SERVER_CERT, 0};

    CALL(multi_ssl_session(2, &sess, &args));

    ne_ssl_set_verify(sess, count_vfy, &count);

    ONREQ(any_request(sess, "/foo-alpha"));
    ONREQ(any_request(sess, "/foo-beta"));

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
    NE_DEBUG(NE_DBG_SSL, "test: fail_ssl_request verify callback - %d\n", fs);
    return -1;
}

/* Helper function for expected-to-fail SSL tests.
 *
 * An SSL server is spawned using 'cert' and 'key' as the key pair.
 * The client will trust CA cert 'cacert', and use 'host' as the server
 * name.  If realhost is non-NULL, this address will be used to connect
 * to in favour of host; the server is otherwise identified as 'host'.
 * 'msg' must be a substring of the error string.
 * 'failures' must equal the failure bitmask passed to the verify
 * callback in the client.
 * If none of the expected conditions is met, 'errstr' will be
 * used in the test failure context.
 */
static int fail_ssl_request_with_error2(char *cert, char *key, char *cacert, 
                                        const char *host, const char *realhost,
                                        const char *msg, int failures,
                                        const char *errstr)
{
    ne_session *sess;
    int gotf = 0, ret;
    struct ssl_server_args args = {0};
    ne_sock_addr *addr = NULL;
    const ne_inet_addr **list = NULL;

    args.cert = cert;
    args.key = key;
    args.fail_silently = 1;
    
    CALL(fakeproxied_session_server(&sess, "https", host, 7777, ssl_server, &args));

    if (cacert) {
        CALL(load_and_trust_cert(sess, cacert));
    }

    ne_ssl_set_verify(sess, get_failures, &gotf);

    ret = any_request(sess, "/expect-to-fail");

    NE_DEBUG(NE_DBG_SSL, "test: fail_ssl_request - request code %d, error: %s\n",
             ret, ne_get_error(sess));

    ONV(gotf == 0,
	("no error in verification callback; request rv %d error string: %s",
	 ret, ne_get_error(sess)));

    ONV(gotf & ~NE_SSL_FAILMASK,
	("verification flags %x outside mask %x", gotf, NE_SSL_FAILMASK));

    /* check the failure flags were as expected. */
    ONV(failures != gotf,
	("verification flags were %d not %d", gotf, failures));

    /* and check that the request was failed too. */
    ONV(ret == NE_OK, ("%s", msg));

    ONV(errstr && strstr(ne_get_error(sess), errstr) == NULL,
        ("unexpected failure message '%s', wanted '%s'",
         ne_get_error(sess), errstr));
        
    ne_session_destroy(sess);
    if (addr) ne_addr_destroy(addr);
    if (list) ne_free(list);

    return OK;
}

/* Helper function: run a request using the given self-signed server
 * certificate, and expect the request to fail with the given
 * verification failure flags. */
static int fail_ssl_request_with_error(char *cert, char *cacert, const char *host,
                                       const char *msg, int failures,
                                       const char *errstr)
{
    return fail_ssl_request_with_error2(cert, NULL, cacert, host, NULL,
                                        msg, failures, errstr);
}


/* Helper function: run a request using the given self-signed server
 * certificate, and expect the request to fail with the given
 * verification failure flags. */
static int fail_ssl_request(char *cert, char *cacert, const char *host,
			    const char *msg, int failures)
{
    return fail_ssl_request_with_error(cert, cacert, host, msg, failures,
                                       NULL);
}        

/* Note that the certs used for fail_* are mostly self-signed, so the
 * cert is passed as CA cert and server cert to fail_ssl_request. */

/* Check that a certificate with the incorrect commonName attribute is
 * flagged as such. */
static int fail_wrongCN(void)
{
    return fail_ssl_request_with_error("wrongcn.cert", "ca/cert.pem", "localhost",
                                       "certificate with incorrect CN was accepted",
                                       NE_SSL_IDMISMATCH,
                                       "certificate issued for a different hostname");
                            
}

#define SRCDIR(s) ne_concat(srcdir, "/" s, NULL)

#if 0
static int fail_nul_cn(void)
{
    char *key = SRCDIR("nulsrv.key"), *ca = SRCDIR("nulca.pem");
    CALL(fail_ssl_request_with_error2(nul_cn_fn, key, ca,
                                      "www.bank.com", "localhost",
                                      "certificate with incorrect CN was accepted",
                                      NE_SSL_IDMISMATCH|NE_SSL_EXPIRED|NE_SSL_BADCHAIN,
                                      "certificate issued for a different hostname"));
    ne_free(key);
    ne_free(ca);
    return OK;
}

static int fail_nul_san(void)
{
    char *cert = SRCDIR("nulsan.pem"), *key = SRCDIR("nulsrv.key"),
        *ca = SRCDIR("nulca.pem");
    CALL(fail_ssl_request_with_error2(cert, key, ca, 
                                      "www.bank.com", "localhost",
                                      "certificate with incorrect CN was accepted",
                                      NE_SSL_IDMISMATCH|NE_SSL_EXPIRED|NE_SSL_BADCHAIN,
                                      "certificate issued for a different hostname"));
    ne_free(cert);
    ne_free(key);
    ne_free(ca);
    return OK;
}
#endif

/* Check that an expired certificate is flagged as such. */
static int fail_expired(void)
{
    return fail_ssl_request_with_error("expired.cert", CA_CERT,  "localhost",
                                       "expired certificate was accepted", 
                                       NE_SSL_EXPIRED,
                                       "certificate has expired");
}

static int fail_notvalid(void)
{
    return fail_ssl_request_with_error("notyet.cert", CA_CERT,  "localhost",
                                       "not yet valid certificate was accepted",
                                       NE_SSL_NOTYETVALID,
                                       "certificate is not yet valid");
}

/* Check that a server cert with a random issuer and self-signed cert
 * fail with UNTRUSTED. */
static int fail_untrusted_ca(void)
{
    return fail_ssl_request_with_error("server.cert", NULL, "localhost",
                                       "untrusted CA.", NE_SSL_UNTRUSTED,
                                       "issuer is not trusted");
}

static int fail_self_signed(void)
{
    return fail_ssl_request("ssigned.pem", NULL,  "localhost",
                            "self-signed cert", NE_SSL_UNTRUSTED);
}

/* Test for failure when a server cert is presented which has no
 * commonName (and no alt names either). */
static int fail_missing_CN(void)
{
    struct ssl_server_args args = {0};
    ne_session *sess;
    int ret;

    args.cert = "missingcn.cert";

    CALL(make_ssl_session(&sess, "localhost", ssl_server, &args));

    ret = any_request(sess, "/fail-missing-cn");
    ONN("request did not fail", ret != NE_ERROR);

    ONV(strstr(ne_get_error(sess), "missing commonName attribute") == NULL,
        ("error string unexpected: %s", ne_get_error(sess)));

    return destroy_and_wait(sess);
}

/* test for a bad ipAddress altname */
static int fail_bad_ipaltname(void)
{
    return fail_ssl_request("altname6.cert", CA_CERT, "127.0.0.1",
                            "bad IP altname cert", NE_SSL_IDMISMATCH);
}

/* test for a ipAddress which matched against the hostname as per neon
 * 0.24 behaviour. */
static int fail_host_ipaltname(void)
{
    return fail_ssl_request("altname5.cert", CA_CERT, "localhost",
                            "bad IP altname cert", NE_SSL_IDMISMATCH);
}

static int fail_wildcard(void)
{
    return fail_ssl_request("altname9.cert", CA_CERT, "localhost",
                            "subjaltname not honored", NE_SSL_IDMISMATCH);
}

static int fail_wildcard_ip(void)
{
    return fail_ssl_request("wildip.cert", CA_CERT, "127.0.0.1",
                            "wildcard IP", NE_SSL_IDMISMATCH);
}

static int fail_ca_expired(void)
{
    return fail_ssl_request_with_error("ca1server.cert", "ca1/cert.pem", 
                                       "localhost", "issuer ca expired", 
                                       NE_SSL_BADCHAIN,
                                       "bad certificate chain");
}

static int fail_ca_notyetvalid(void)
{
    return fail_ssl_request("ca3server.cert", "ca3/cert.pem", "localhost",
                            "issuer ca not yet valid", NE_SSL_BADCHAIN);
}

/* Test that the SSL session is cached across connections. */
static int session_cache(void)
{
    struct ssl_server_args args = {0};
    ne_session *sess;

    args.cert = SERVER_CERT;
    args.cache = 1;

    CALL(multi_session_server(&sess, "https", "localhost",
                              2, ssl_server, &args));

    /* This currently fails under OpenSSL with TLSv1.3. */
    ne_ssl_set_protovers(sess, NE_SSL_PROTO_UNSPEC,
                         NE_SSL_PROTO_TLS_1_2);

    ne_ssl_trust_cert(sess, def_ca_cert);

    ONREQ(any_request(sess, "/req1"));
    ONREQ(any_request(sess, "/req2"));

    return destroy_and_wait(sess);
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
    struct ssl_server_args args = {SERVER_CERT, NULL};

    args.require_cc = 1;

    cc = ne_ssl_clicert_read("client.p12");
    ONN("could not load client.p12", cc == NULL);
    ONN("could not decrypt client.p12", 
        ne_ssl_clicert_decrypt(cc, P12_PASSPHRASE));
    
    ne_ssl_provide_clicert(sess, ccert_provider, cc);
    CALL(any_ssl_request(sess, ssl_server, &args, CA_CERT,
                         NULL, NULL));

    ne_session_destroy(sess);
    ne_ssl_clicert_free(cc);
    return OK;
}

#define DN_COUNT 5

static void cc_check_dnames(void *userdata, ne_session *sess,
                            const ne_ssl_dname *const *dns, int dncount)
{
    int n, *ret = userdata;
    static const char *expected[DN_COUNT] = {
        CACERT_DNAME,
        "First Random CA, CAs Ltd., Lincoln, Lincolnshire, GB",
        "Second Random CA, CAs Ltd., Falmouth, Cornwall, GB",
        "Third Random CA, CAs Ltd., Ipswich, Suffolk, GB",
        "Fourth Random CA, CAs Ltd., Norwich, Norfolk, GB"
    };

    ne_ssl_set_clicert(sess, def_cli_cert);

    if (dncount != DN_COUNT) {
        t_context("dname count was %d not %d", dncount, 
                  DN_COUNT);
        *ret = -1;
        return;
    }
    
    for (n = 0; n < DN_COUNT; n++) {
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
    struct ssl_server_args args = {SERVER_CERT, NULL};

    args.require_cc = 1;
    args.ca_list = "calist.pem";

    PRECOND(def_cli_cert);

    ne_ssl_provide_clicert(sess, cc_check_dnames, &check);

    CALL(any_ssl_request(sess, ssl_server, &args, CA_CERT, NULL, NULL));

    ne_session_destroy(sess);

    ONN("provider function not called", check == 0);

    return (check == -1) ? FAIL : OK;
}

/* Tests use of a client certificate. */
static int client_cert_pkcs12(void)
{
    ne_session *sess = DEFSESS;
    struct ssl_server_args args = {SERVER_CERT, NULL};

    args.require_cc = 1;

    PRECOND(def_cli_cert);

    ne_ssl_set_clicert(sess, def_cli_cert);
    CALL(any_ssl_request(sess, ssl_server, &args, CA_CERT, NULL, NULL));

    ne_session_destroy(sess);    
    return OK;
}

/* Test use of a PKCS#12 cert with an embedded CA cert - fails with <=
 * 0.28.3 in GnuTLS build. */
static int client_cert_ca(void)
{
    ne_session *sess = DEFSESS;
    struct ssl_server_args args = {SERVER_CERT, NULL};
    ne_ssl_client_cert *cc;

    args.require_cc = 1;

    cc = ne_ssl_clicert_read("clientca.p12");
    ONN("could not load clientca.p12", cc == NULL);
    ONN("encrypted cert marked unencrypted?", !ne_ssl_clicert_encrypted(cc));
    ONN("could not decrypt clientca.p12", 
        ne_ssl_clicert_decrypt(cc, P12_PASSPHRASE));

    ne_ssl_set_clicert(sess, cc);
    CALL(any_ssl_request(sess, ssl_server, &args, CA_CERT, NULL, NULL));

    ne_ssl_clicert_free(cc);

    ne_session_destroy(sess);    
    return OK;
}

/* Tests use of an unencrypted client certificate. */
static int ccert_unencrypted(void)
{
    ne_session *sess = DEFSESS;
    ne_ssl_client_cert *ccert;
    struct ssl_server_args args = {SERVER_CERT, NULL};

    args.require_cc = 1;

    ccert = ne_ssl_clicert_read("unclient.p12");
    ONN("could not load unclient.p12", ccert == NULL);
    ONN("unclient.p12 was encrypted", ne_ssl_clicert_encrypted(ccert));

    ne_ssl_set_clicert(sess, ccert);
    CALL(any_ssl_request(sess, ssl_server, &args, CA_CERT, NULL, NULL));

    ne_ssl_clicert_free(ccert);
    ne_session_destroy(sess);
    return OK;
}

#define NOCERT_MESSAGE "client certificate was requested"
/* random SSL read may fail like this with TLSv1.3 */
#define NOCERT_ALT "certificate required"

/* Tests for useful error message if a handshake fails where a client
 * cert was requested. */
static int no_client_cert(void)
{
    ne_session *sess;
    struct ssl_server_args args = {SERVER_CERT, NULL};
    int ret;

    args.require_cc = 1;
    args.fail_silently = 1;

    CALL(make_ssl_session(&sess, NULL, ssl_server, &args));

    ne_ssl_trust_cert(sess, def_ca_cert);
    
    ret = any_request(sess, "/failme");

    ONV(ret != NE_ERROR,
        ("unexpected result %d: %s", ret, ne_get_error(sess)));

    ONV(strstr(ne_get_error(sess), NOCERT_MESSAGE) == NULL
        && strstr(ne_get_error(sess), NOCERT_ALT) == NULL,
        ("error message was '%s', missing '%s'", 
         ne_get_error(sess), NOCERT_MESSAGE));
    
    reap_server();

    ne_session_destroy(sess);    
    return OK;
}

/* non-zero if a server auth header was received */
static int got_server_auth; 

/* Utility function which accepts the 'tunnel' header. */
static void tunnel_header(char *value)
{
    got_server_auth = 1;
}

/* Server which acts as a proxy accepting a CONNECT request. */
static int serve_tunnel(ne_socket *sock, void *ud)
{
    struct ssl_server_args *args = ud;

    /* check for a server auth function */
    want_header = "Authorization";
    got_header = tunnel_header;
    got_server_auth = 0;

    /* give the plaintext tunnel reply, acting as the proxy */
    CALL(discard_request(sock));

    if (got_server_auth) {
        SEND_STRING(sock, "HTTP/1.1 500 Leaked Server Auth Creds\r\n"
                    "Content-Length: 0\r\n" "Server: serve_tunnel\r\n\r\n");
        return 0;
    } else {
        SEND_STRING(sock, "HTTP/1.1 200 OK\r\nServer: serve_tunnel\r\n\r\n");
        return ssl_server(sock, args);
    }
}

/* neon versions <= 0.21.2 segfault here because ne_sock_close would
 * be called twice on the socket after the server cert verification
 * fails. */
static int fail_tunnel(void)
{
    ne_session *sess = ne_session_create("https", "example.com", 443);
    struct ssl_server_args args = {SERVER_CERT, NULL};

    ne_session_proxy(sess, "localhost", 7777);

    ONN("server cert verification didn't fail",
	any_ssl_request(sess, serve_tunnel, &args, CA_CERT,
			NULL, NULL) != NE_ERROR);
    
    ne_session_destroy(sess);
    return OK;
}

static int proxy_tunnel(void)
{
    ne_session *sess = ne_session_create("https", "localhost", 443);
    struct ssl_server_args args = {SERVER_CERT, NULL};

    ne_session_proxy(sess, "localhost", 7777);
    
    /* CA cert is trusted, so no verify callback should be needed. */
    CALL(any_ssl_request(sess, serve_tunnel, &args, CA_CERT,
			 NULL, NULL));

    ne_session_destroy(sess);
    return OK;
}

struct tunnel_args {
    int iteration;
    const char *first_response; /* first CONNECT response. */
    const char *second_response; /* second CONNECT response. */
    struct ssl_server_args *args;
};

/* Server which acts as a proxy accepting a CONNECT request. */
static int serve_auth_tunnel(ne_socket *sock, void *ud)
{
    struct tunnel_args *args = ud;

    /* check for a server auth function */
    want_header = "Authorization";
    got_header = tunnel_header;
    got_server_auth = 0;

    CALL(discard_request(sock));

    if (got_server_auth) {
        SEND_STRING(sock, "HTTP/1.1 500 Leaked Server Auth Creds\r\n"
                    "Content-Length: 0\r\n" "Server: serve_tunnel\r\n\r\n");
        return 0;
    }
    
    if (args->iteration++ == 0) {
        /* give the plaintext tunnel reply, acting as the proxy */

        SEND_STRING(sock, args->first_response);

        return OK;
    }

    SEND_STRING(sock, args->second_response);

    return ssl_server(sock, args->args);
}

static int apt_creds(void *userdata, const char *realm, int attempt,
                     char *username, char *password)
{
    strcpy(username, "foo");
    strcpy(password, "bar");
    return attempt;
}

/* Test for using SSL over a CONNECT tunnel via a proxy server which
 * requires authentication.  Broke briefly between 0.23.x and
 * 0.24.0. */
static int auth_proxy_tunnel(void)
{
    struct ssl_server_args args = {SERVER_CERT, NULL};
    struct tunnel_args tunnel;
    ne_session *sess;

    tunnel.first_response =
        "HTTP/1.0 407 I WANT MORE BISCUITS\r\n"
        "Server: auth_proxy_tunnel\r\n"
        "Proxy-Authenticate: Basic realm=\"bigbluesea\"\r\n"
        "Connection: close\r\n" "\r\n";
    tunnel.second_response = "HTTP/1.1 200 OK\r\n"
        "Server: auth_proxy_tunnel r2\r\n\r\n";
    tunnel.iteration = 0;
    tunnel.args = &args;

    CALL(proxied_multi_session_server(2, &sess, "https", "localhost", 443,
                                      serve_auth_tunnel, &tunnel));
    
    ne_set_proxy_auth(sess, apt_creds, NULL);
    ne_ssl_trust_cert(sess, def_ca_cert);
    
    CALL(any_2xx_request(sess, "/foobar"));

    return destroy_and_wait(sess);
}

/* Regression test to check that server credentials aren't sent to the
 * proxy in a CONNECT request. */
static int auth_tunnel_creds(void)
{
    struct ssl_server_args args = {SERVER_CERT, NULL};
    struct tunnel_args tunnel;
    ne_session *sess;

    args.response = "HTTP/1.1 401 I want a Shrubbery\r\n"
        "WWW-Authenticate: Basic realm=\"bigredocean\"\r\n"
        "Server: auth_tunnel_creds\r\n" "Content-Length: 0\r\n" "\r\n"
        ""
        "HTTP/1.1 200 OK\r\n\r\n";

    tunnel.second_response = "HTTP/1.1 200 OK\r\n\r\n";
    tunnel.args = &args;
    tunnel.iteration = 1;

    CALL(proxied_multi_session_server(2, &sess, "https", "localhost", 443,
                                      serve_auth_tunnel, &tunnel));
    
    ne_set_server_auth(sess, apt_creds, NULL);
    ne_ssl_trust_cert(sess, def_ca_cert);
    
    CALL(any_2xx_request(sess, "/foobar"));
    CALL(any_2xx_request(sess, "/foobar"));

    return destroy_and_wait(sess);
}

static int auth_tunnel_fail(void)
{
    ne_session *sess = ne_session_create("https", "localhost", 443);
    int ret;

    CALL(spawn_server(7777, single_serve_string,
                      "HTTP/1.1 407 Nyaaaaah\r\n"
                      "Proxy-Authenticate: GaBoogle\r\n"
                      "Connection: close\r\n"
                      "\r\n"));
    
    ne_session_proxy(sess, "localhost", 7777);

    ne_set_proxy_auth(sess, apt_creds, NULL);
     
    ret = any_request(sess, "/bar");
    ONV(ret != NE_PROXYAUTH, ("bad error code for tunnel failure: %d", ret));

    ONV(strstr(ne_get_error(sess), "GaBoogle") == NULL,
        ("bad error string for tunnel failure: %s", ne_get_error(sess)));

    return destroy_and_wait(sess);
}

/* compare against known digest of notvalid.pem.  Via:
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

static int cert_hdigests(void)
{
    static const struct {
        unsigned int flags;
        const char *digest;
    } ts[] = {
        { NE_HASH_MD5|NE_HASH_COLON, "76:26:eb:db:09:e8:53:5c:79:61:0c:30:3d:77:ed:65" },
        { NE_HASH_MD5, "7626ebdb09e8535c79610c303d77ed65" },
        { NE_HASH_SHA256, "ea4a4f4f08a91a83e841e772171a2befa3f6e576b5cd9f5cd6d12e9683fe89b3" },
        { NE_HASH_SHA512, "35373c533f4000ee9b6173a45eedae732f6c953dcf76f5fba5ffb7be380de559893d0679e94051950be2a5917fa7922fbf50ef10222d5be4eea53ba948cf7703" },
        { 0, NULL }
    };
    unsigned int n, passed = 0;
    char *fn = ne_concat(srcdir, "/notvalid.pem", NULL);
    ne_ssl_certificate *cert = ne_ssl_cert_read(fn);

    ONN("could not load notvalid.pem", cert == NULL);

    for (n = 0; ts[n].flags; n++) {
        char *dig = ne_ssl_cert_hdigest(cert, ts[n].flags);

        /* Can reasonably for almost any hash (either too modern or
         * too old), so what can you do? */
        if (dig == NULL) {
            t_warning("failed to htdigest with flags %u", ts[n].flags);
            continue;
        }

        NE_DEBUG(NE_DBG_SSL, "ssl: hDigest %u got %s, expected %s\n",
                 ts[n].flags, dig, ts[n].digest);

        ONV(strcmp(dig, ts[n].digest),
            ("digest was %s not %s", dig, ts[n].digest));

        passed++;
        ne_free(dig);
    }

    ONN("no algorithms supported for ne_ssl_cert_hdigest", passed == 0);

    ne_ssl_cert_free(cert);
    ne_free(fn);

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
        { "ssigned.pem", "localhost" },
        { "twocn.cert", "localhost" },
        { "altname1.cert", "localhost" },
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

static int nulcn_identity(void)
{
    ne_ssl_certificate *cert = ne_ssl_cert_read(nul_cn_fn);
    const char *id;

    ONN("could not read nulcn.pem", cert == NULL);

    id = ne_ssl_cert_identity(cert);

    ONN("embedded NUL byte not quoted",
        id != NULL && strcmp(id, "www.bank.com") == 0);
    
    ne_ssl_cert_free(cert);
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
    CALL(check_validity(cert, 
                        "Mon, 21 Jan 2002 20:39:04 GMT", "Thu, 31 Jan 2002 20:39:04 GMT"));
    ne_free(cert);
    cert = ne_concat(srcdir, "/notvalid.pem", NULL);
    CALL(check_validity(cert, 
                        "Wed, 27 Dec 2023 20:40:29 GMT", "Thu, 28 Dec 2023 20:40:29 GMT"));
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

/* The dname with the UTF-8 encoding of the Unicode string: 
 * "H<LATIN SMALL LETTER E WITH GRAVE>llo World". */
#define I18N_DNAME "H\xc3\xa8llo World, Neon Hackers Ltd, Cambridge, Cambridgeshire, GB"

/* N.B. t61subj.cert encodes an ISO-8859-1 string in a T61String
 * field, which is strictly wrong but the common usage. */

/* tests for ne_ssl_readable_dname */
static int dname_readable(void)
{
    struct {
        const char *cert;
        const char *subjdn, *issuerdn;
    } ts[] = {
        { "justmail.cert", "blah@example.com", NULL },
        { "t61subj.cert", I18N_DNAME, NULL },
        { "bmpsubj.cert", I18N_DNAME, NULL },
        { "utf8subj.cert", I18N_DNAME, NULL },
        { "twoou.cert", "First OU Dept, Second OU Dept, Neon Hackers Ltd, "
          "Cambridge, Cambridgeshire, GB", NULL }
    };
    size_t n;

    for (n = 0; n < sizeof(ts)/sizeof(ts[0]); n++) {
        ne_ssl_certificate *cert = ne_ssl_cert_read(ts[n].cert);
        ONV(cert == NULL, ("could not load cert %s", ts[n].cert));
        CALL(check_cert_dnames(cert, ts[n].subjdn, ts[n].issuerdn));
        ne_ssl_cert_free(cert);
    }

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
    struct ssl_server_args args = {0};

    args.cert = "ssigned.pem";
    args.cache = 1;

    ONREQ(any_ssl_request(sess, ssl_server, &args, CA_CERT,
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
    ONREQ(any_ssl_request(sess, ssl_server, &args, CA_CERT,
                          NULL, NULL));
    ne_session_destroy(sess);
    return OK;
}

static int nonssl_trust(void)
{
    ne_session *sess = ne_session_create("http", "www.example.com", 80);
    
    ne_ssl_trust_cert(sess, def_ca_cert);
    ne_ssl_trust_default_ca(sess);
    
    ne_session_destroy(sess);

    return OK;
}

#ifdef HAVE_PAKCHOIS
#define PINMAX (2)
struct pindata {
    const char *password[PINMAX];
    ne_buffer *trace;
};

/* PIN password provider callback. */
static int pkcs11_pin(void *userdata, int attempt,
                      const char *slot_descr, const char *token_label,
                      unsigned int flags, char *pin)
{
    struct pindata *data = userdata;

    NE_DEBUG(NE_DBG_SSL, "pk11: slot = [%s], token = [%s]\n",
             slot_descr, token_label);

    ne_buffer_snprintf(data->trace, 200, "pin(%d,%s,%s,%u)\n",
                       attempt, slot_descr?slot_descr:"[none]",
                       token_label?token_label:"[none]", flags);

    if (attempt < PINMAX && data->password[attempt]) {
        strcpy(pin, data->password[attempt]);
        return 0;
    }
    else {
        return -1;
    }
}

#define SLOT_NSS "NSS User Private Key and Certificate Services"
#define TOKEN_NSS "NSS Certificate DB"

static int nss_pkcs11_test(const char *dbname)
{
    ne_session *sess = DEFSESS;
    struct ssl_server_args args = {SERVER_CERT, NULL};
    ne_ssl_pkcs11_provider *prov;
    struct pindata pindata;
    int ret;

    args.require_cc = 1;

    if (access(dbname, R_OK|X_OK)) {
        t_warning("NSS required for PKCS#11 testing");
        return SKIP;
    }

    ret = ne_ssl_pkcs11_nss_provider_init(&prov, "softokn3", dbname, NULL, 
                                          NULL, NULL);
    if (ret) {
        if (ret == NE_PK11_NOTIMPL)
            t_context("pakchois library required for PKCS#11 support");
        else
            t_context("could not load NSS softokn3 PKCS#11 provider");
        return SKIP;
    }

    pindata.password[0] = "notfoobar";
    pindata.password[1] = "foobar";
    pindata.trace = ne_buffer_create();

    ne_ssl_pkcs11_provider_pin(prov, pkcs11_pin, &pindata);
    ne_ssl_set_pkcs11_provider(sess, prov);

    ret = any_ssl_request(sess, ssl_server, &args, CA_CERT, NULL, NULL);

    ne_session_destroy(sess);
    ne_ssl_pkcs11_provider_destroy(prov);

    if (ret == OK)
        ONCMPN("pin(0," SLOT_NSS "," TOKEN_NSS ",0)\n"
               "pin(1," SLOT_NSS "," TOKEN_NSS ",0)\n", pindata.trace->data, "pin callback", "data");
    ne_buffer_destroy(pindata.trace);

    return ret;
}

static int pkcs11(void)
{
    return nss_pkcs11_test("nssdb");
}

static int pkcs11_dsa(void)
{
    return nss_pkcs11_test("nssdb-dsa");
}
#endif

static int protovers(void)
{
    ne_session *sess = DEFSESS;
    struct ssl_server_args args = {SERVER_CERT, NULL};

    args.minver = NE_SSL_PROTO_TLS_1_2;
    args.maxver = NE_SSL_PROTO_TLS_1_2;

    ONV(ne_ssl_set_protovers(sess, args.minver, args.maxver),
        ("setting TLS protocol version failed: %s", ne_get_error(sess)));

    CALL(any_ssl_request(sess, ssl_server, &args, CA_CERT, NULL, NULL));

    ne_session_destroy(sess);
    return OK;
}

static int notifier(void)
{
    ne_session *sess = DEFSESS;
    struct ssl_server_args args = {SERVER_CERT, NULL};
    ne_buffer *buf = ne_buffer_create();

    args.minver = NE_SSL_PROTO_TLS_1_2;
    args.maxver = NE_SSL_PROTO_TLS_1_2;

    ONV(ne_ssl_set_protovers(sess, args.minver, args.maxver),
        ("setting TLS protocol version failed: %s", ne_get_error(sess)));

    ne_set_notifier(sess, sess_notifier, buf);

    CALL(any_ssl_request(sess, ssl_server, &args, CA_CERT, NULL, NULL));

    ONV(strstr(buf->data, "-handshake(TLSv1.2, TLS_") == NULL
        && strstr(buf->data, "-handshake(TLSv1.2, [none]") == NULL,
        ("missing handshake from notifier: %s", buf->data));

    ne_session_destroy(sess);
    ne_buffer_destroy(buf);

    return OK;
}

#define TEST_URI "./enclient.pem"

static int clicert_uri(void)
{
    ne_session *sess;
    struct ssl_server_args args = {SERVER_CERT, NULL};
    ne_ssl_client_cert *cc;
    int ret;

    args.require_cc = 1;

    cc = ne_ssl_clicert_fromuri(TEST_URI, 0);
    if (!cc && errno == ENOTSUP) {
        t_context("client certificate URI support not available");
        return SKIP;
    }
    ONV(!cc, ("could not load client certificate URI %s: %s",
              TEST_URI, strerror(errno)));

    ONN("cc not in encrypted state", !ne_ssl_clicert_encrypted(cc));
    ONN("successful decrypt with bad password",
        ne_ssl_clicert_decrypt(cc, "not-the-password") == 0);
    ONN("unsuccessful decrypt with good password",
        ne_ssl_clicert_decrypt(cc, P12_PASSPHRASE) != 0);

    sess = DEFSESS;
    ne_ssl_set_clicert(sess, cc);

    ret = any_ssl_request(sess, ssl_server, &args, CA_CERT, NULL, NULL);

    ne_session_destroy(sess);
    ne_ssl_clicert_free(cc);

    return ret;
}


/* TODO: code paths still to test in cert verification:
 * - server cert changes between connections: Mozilla gives
 * a "bad MAC decode" error for this; can do better?
 * - server presents no certificate (using ADH ciphers)... can
 * only really happen if they mess with the SSL_CTX and enable
 * ADH cipher manually; but good to check the failure case is 
 * safe.
 * -  SSL cert changes between connections; handle as normal & re-verify
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
    T(cert_hdigests),
    T(cert_identities),
    T(cert_validity),
    T(cert_compare),
    T(dname_compare),
    T(dname_readable),
    T(import_export),
    T(read_write),

    T(load_client_cert),
    T(clicert_import),

    T(simple),
    T(simple_eof),
    T(empty_truncated_eof),
    T(fail_not_ssl),
    T(cache_cert),
    T(intermediary),

    T(client_cert_pkcs12),
    T(ccert_unencrypted),
    T(client_cert_provided),
    T(cc_provided_dnames),
    T(no_client_cert),
    T(client_cert_ca),

    T(parse_cert),
    T(parse_chain),

    T(no_verify),
    T(cache_verify),
    T(wildcard_match),
    T(wildcard_match_altname),
    T(caseless_match),

    T(subject_altname),
    T(two_subject_altname),
    T(two_subject_altname2),
    T(notdns_altname),
    T(ipaddr_altname),

    T(multi_commonName),
    T(commonName_first),

    T(fail_wrongCN),
    T(fail_expired),
    T(fail_notvalid),
    T(fail_untrusted_ca),
    T(fail_self_signed),
    T(fail_missing_CN),
    T(fail_host_ipaltname),
    T(fail_bad_ipaltname),
    T(fail_wildcard),
    T(fail_wildcard_ip),
    T(fail_ca_notyetvalid),
    T(fail_ca_expired),

    T(nulcn_identity),
#if 0
    /* These certs were created with a SHA#1 digest so are rejected by
     * modern TLS libraries. */
    T(fail_nul_cn),
    T(fail_nul_san),
#endif

    T(session_cache),

    T(fail_tunnel),
    T(proxy_tunnel),
    T(auth_proxy_tunnel),
    T(auth_tunnel_creds),
    T(auth_tunnel_fail),

    T(protovers),

    T(nonssl_trust),

#ifdef HAVE_PAKCHOIS
    T(pkcs11),
    T_XFAIL(pkcs11_dsa), /* unclear why this fails currently. */
#endif
    T(notifier),
    T(clicert_uri),

    T(NULL) 
};
