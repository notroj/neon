/*
   neon SSL/TLS support using GNU TLS
   Copyright (C) 2002-2004, Joe Orton <joe@manyfish.co.uk>
   Copyright (C) 2004, Aleix Conchillo Flaque <aleix@member.fsf.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

#include "config.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>

#include "ne_ssl.h"
#include "ne_string.h"
#include "ne_session.h"
#include "ne_i18n.h"

#include "ne_private.h"
#include "ne_privssl.h"

struct ne_ssl_dname_s {
    char *dn;
};

struct ne_ssl_certificate_s {
    ne_ssl_dname subj_dn, issuer_dn;
    gnutls_x509_crt subject;
    ne_ssl_certificate *issuer;
    char *identity;
};

struct ne_ssl_client_cert_s {
    gnutls_pkcs12 p12;
    int decrypted; /* non-zero if successfully decrypted. */
    ne_ssl_certificate cert;
    char *friendly_name;
};

char *ne_ssl_readable_dname(const ne_ssl_dname *name)
{
    return name->dn;
}

int ne_ssl_dname_cmp(const ne_ssl_dname *dn1, const ne_ssl_dname *dn2)
{
    return strcmp(dn1->dn, dn2->dn);
}

void ne_ssl_clicert_free(ne_ssl_client_cert *cc)
{
#warning incomplete
}

void ne_ssl_cert_validity(const ne_ssl_certificate *cert,
                          char *from, char *until)
{
    if (from) {
        time_t t = gnutls_x509_crt_get_activation_time(cert->subject);
        strftime(from, NE_SSL_VDATELEN, "%b %d %H:%M:%S %Y%Z", localtime(&t));
    }
    if (until) {
        time_t t = gnutls_x509_crt_get_expiration_time(cert->subject);
        strftime(from, NE_SSL_VDATELEN, "%b %d %H:%M:%S %Y%Z", localtime(&t));
    }
}

/* Returns a new buffer with X509 subject's (or issuer) distinguished name. */
static char *x509_get_dn(gnutls_x509_crt x5, int subject)
{
    int ret, len;
    char *dn;

    if (subject)
        ret = gnutls_x509_crt_get_dn(x5, NULL, &len);
    else
        ret = gnutls_x509_crt_get_issuer_dn(x5, NULL, &len);

    if (ret < 0)
        return NULL;

    dn = ne_malloc(len);
    if (subject)
        gnutls_x509_crt_get_dn(x5, dn, &len);
    else
        gnutls_x509_crt_get_issuer_dn(x5, dn, &len);

    return dn;
}

/* Populate an ne_ssl_certificate structure from an X509 object. */
static ne_ssl_certificate *populate_cert(ne_ssl_certificate *cert,
                                         gnutls_x509_crt x5)
{
    cert->subj_dn.dn = x509_get_dn(x5, 1);
    cert->issuer_dn.dn = x509_get_dn(x5, 0);
    cert->issuer = NULL;
    cert->subject = x5;
    cert->identity = NULL;
    return cert;
}

void ne_ssl_set_clicert(ne_session *sess, const ne_ssl_client_cert *cc)
{
#warning incomplete
}

ne_ssl_context *ne_ssl_context_create(void)
{
    ne_ssl_context *ctx = ne_malloc(sizeof *ctx);

    gnutls_dh_params_init(&ctx->dh_params);
    gnutls_dh_params_generate2(ctx->dh_params, 1024);

    gnutls_rsa_params_init(&ctx->rsa_params);
    gnutls_rsa_params_generate2(ctx->rsa_params, 1024);

    gnutls_certificate_allocate_credentials(&ctx->cred.cert);
    gnutls_certificate_set_dh_params(ctx->cred.cert, ctx->dh_params);
    gnutls_certificate_set_rsa_params(ctx->cred.cert, ctx->rsa_params);

    return ctx;
}

void ne_ssl_context_destroy(ne_ssl_context *ctx)
{
    if (ctx->sess)
        gnutls_deinit(ctx->sess);
    if (ctx->dh_params)
        gnutls_dh_params_deinit(ctx->dh_params);
    if (ctx->rsa_params)
        gnutls_rsa_params_deinit(ctx->rsa_params);
    if (ctx->cred.cert)
        gnutls_certificate_free_credentials(ctx->cred.cert);
    ne_free(ctx);
}

/* For internal use only. */
int ne__negotiate_ssl(ne_request *req)
{
    ne_session *sess = ne_get_session(req);
    ne_ssl_context *ctx = sess->ssl_context;
    const gnutls_datum *chain;
    unsigned int chain_size;

    NE_DEBUG(NE_DBG_SSL, "Doing SSL negotiation.\n");

    if (ne_sock_connect_ssl(sess->socket, ctx)) {
	if (ctx->sess) {
	    /* remove cached session. */
	    gnutls_deinit(ctx->sess);
	    ctx->sess = NULL;
	}
	ne_set_error(sess, _("SSL negotiation failed: %s"),
		     ne_sock_error(sess->socket));
	return NE_ERROR;
    }

    return NE_OK;
}

const ne_ssl_dname *ne_ssl_cert_issuer(const ne_ssl_certificate *cert)
{
    return &cert->issuer_dn;
}

const ne_ssl_dname *ne_ssl_cert_subject(const ne_ssl_certificate *cert)
{
    return &cert->subj_dn;
}

const ne_ssl_certificate *ne_ssl_cert_signedby(const ne_ssl_certificate *cert)
{
    return cert->issuer;
}

const char *ne_ssl_cert_identity(const ne_ssl_certificate *cert)
{
    return cert->identity;
}

void ne_ssl_ctx_trustcert(ne_ssl_context *ctx, const ne_ssl_certificate *cert)
{
#warning incomplete
}

void ne_ssl_trust_default_ca(ne_session *sess)
{
#warning incomplete
}

/* Functions from GNU TLS manual examples.
 *
 * Helper functions to load a certificate and key
 * files into memory. They use mmap for simplicity.
 */
static gnutls_datum mmap_file(const char* filename)
{
    int fd;
    gnutls_datum mmaped_file = { NULL, 0 };
    struct stat stat_st;
    void* ptr;

    fd = open(filename, 0);
    if (fd == -1)
        return mmaped_file;

    fstat(fd, &stat_st);

    if ((ptr = mmap(NULL, stat_st.st_size,
                    PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
        return mmaped_file;

    mmaped_file.data = ptr;
    mmaped_file.size = stat_st.st_size;

    return mmaped_file;
}

static void munmap_file( gnutls_datum data)
{
    munmap(data.data, data.size);
}

ne_ssl_client_cert *ne_ssl_clicert_read(const char *filename)
{
    return NULL;
}

int ne_ssl_clicert_encrypted(const ne_ssl_client_cert *cc)
{
    return !cc->decrypted;
}

int ne_ssl_clicert_decrypt(ne_ssl_client_cert *cc, const char *password)
{
    return 0;
}

const ne_ssl_certificate *ne_ssl_clicert_owner(const ne_ssl_client_cert *cc)
{
    return &cc->cert;
}

const char *ne_ssl_clicert_name(ne_ssl_client_cert *ccert)
{
    return ccert->friendly_name;
}

ne_ssl_certificate *ne_ssl_cert_read(const char *filename)
{
    int ret;
    gnutls_datum data;
    gnutls_x509_crt x5;

    data = mmap_file(filename);
    if (data.data == NULL)
        return NULL;

    if (gnutls_x509_crt_init(&x5) != 0)
        return NULL;

    ret = gnutls_x509_crt_import(x5, &data, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        gnutls_x509_crt_deinit(x5);
        return NULL;
    }

    return populate_cert(ne_calloc(sizeof(struct ne_ssl_certificate_s)), x5);
}

int ne_ssl_cert_write(const ne_ssl_certificate *cert, const char *filename)
{
    int ret;
    unsigned char buffer[10*1024];
    int len = sizeof buffer;

    FILE *fp = fopen(filename, "w");

    if (fp == NULL) return -1;

    if (gnutls_x509_crt_export(cert->subject, GNUTLS_X509_FMT_PEM, buffer,
                               &len) < 0) {
        fclose(fp);
        return -1;
    }

    if (fwrite(buffer, len, 1, fp) != 1) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0)
        return -1;

    return 0;
}

void ne_ssl_cert_free(ne_ssl_certificate *cert)
{
    gnutls_x509_crt_deinit(cert->subject);
    if (cert->subj_dn.dn) ne_free(cert->subj_dn.dn);
    if (cert->issuer_dn.dn) ne_free(cert->issuer_dn.dn);
    if (cert->identity) ne_free(cert->identity);

    if (cert->issuer)
        ne_ssl_cert_free(cert->issuer);
    if (cert->identity)
        ne_free(cert->identity);
    ne_free(cert);
}

int ne_ssl_cert_cmp(const ne_ssl_certificate *c1, const ne_ssl_certificate *c2)
{
    int ret1, ret2;
    char digest1[100], digest2[100];

    ret1 = ne_ssl_cert_digest(c1, digest1);
    ret2 = ne_ssl_cert_digest(c2, digest2);

    if (ret1 < 0 || ret2 < 0)
        return -1;

    return strcmp(digest1, digest2);
}

/* The certificate import/export format is the base64 encoding of the
 * raw DER; PEM without the newlines and wrapping. */

ne_ssl_certificate *ne_ssl_cert_import(const char *data)
{
    int ret;
    size_t len;
    unsigned char *der;
    gnutls_datum buffer = { NULL, 0 };
    gnutls_x509_crt x5;

    if (gnutls_x509_crt_init(&x5) != 0)
        return NULL;

    /* decode the base64 to get the raw DER representation */
    len = ne_unbase64(data, &der);
    if (len == 0) return NULL;

    buffer.data = der;
    buffer.size = len;

    ret = gnutls_x509_crt_import(x5, &buffer, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        gnutls_x509_crt_deinit(x5);
        return NULL;
    }

    return populate_cert(ne_calloc(sizeof(struct ne_ssl_certificate_s)), x5);
}

char *ne_ssl_cert_export(const ne_ssl_certificate *cert)
{
    int ret;
    unsigned char der[10*1024];
    int len = sizeof der;

    /* find the length of the DER encoding. */
    ret = gnutls_x509_crt_export(cert->subject, GNUTLS_X509_FMT_DER, der, &len);
    if (ret < 0)
        return NULL;

    return ne_base64(der, len);
}

int ne_ssl_cert_digest(const ne_ssl_certificate *cert, char *digest)
{
    int ret;
    size_t len;
    unsigned char *sha1;
    unsigned int j;
    char *p;

    ret = gnutls_x509_crt_get_fingerprint(cert->subject, GNUTLS_DIG_SHA,
                                          NULL, &len);
    if (ret < 0 || len != 20)
        return -1;

    sha1 = (unsigned char*) gnutls_malloc(len);
    if (sha1 == NULL)
        return -1;

    gnutls_x509_crt_get_fingerprint(cert->subject, GNUTLS_DIG_SHA,
                                    sha1, &len);

    for (j = 0, p = digest; j < 20; j++) {
        *p++ = NE_HEX2ASC((sha1[j] >> 4) & 0x0f);
        *p++ = NE_HEX2ASC(sha1[j] & 0x0f);
        *p++ = ':';
    }

    *--p = '\0';
    return 0;
}
