/* 
   Common SSL/TLS handling routines
   Copyright (C) 2001-2026, Joe Orton <joe@manyfish.co.uk>

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

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "ne_alloc.h"
#include "ne_utils.h"
#include "ne_internal.h"
#include "ne_string.h"
#include "ne_privssl.h"

#ifdef NE_HAVE_SSL
/* This doesn't actually implement complete RFC 2818 logic; omits
 * "f*.example.com" support for simplicity. */
int ne__ssl_match_hostname(const char *cn, size_t cnlen, const char *hostname)
{
    const char *dot;

    if (!hostname) {
        return 0;
    }

    NE_DEBUG(NE_DBG_SSL, "ssl: Match common name '%s' against '%s'\n",
             cn, hostname);

    if (strncmp(cn, "*.", 2) == 0 && cnlen > 2
        && (dot = strchr(hostname, '.')) != NULL) {
	hostname = dot + 1;
	cn += 2;
        cnlen -= 2;
    }

    return cnlen == strlen(hostname) && !ne_strcasecmp(cn, hostname);
}

void ne_ssl_context_set_ccprovide(ne_ssl_context *ctx,
                                  ne_ssl_ccprovide_fn provider, void *userdata)
{
    ctx->provider = provider;
    ctx->provider_ud = userdata;
}
#endif /* NE_HAVE_SSL */

#ifdef HAVE_ECH
static size_t extract_echparam(const char *params, unsigned char **echparam)
{
    char *pcopy, *tok, *p;
    size_t ret = 0;

    p = pcopy = ne_strdup(params);

    while ((tok = ne_qtoken(&p, ' ', "\"")) != NULL) {
        tok = ne_shave(tok, " ");
        if (strncmp(tok, "ech=", 4) == 0) {
            ret = ne_unbase64(tok+4, echparam);
            NE_DEBUG(NE_DBG_SSL, "ssl: Parsing ECH parameter: %s - %s\n", tok,
                     ret == 0 ? "failed" : "success");
            break;
        }
    }

    ne_free(pcopy);
    return ret;
}
#endif

int ne_ssl_context_resolve_ech(ne_ssl_context *ctx, const char *hostname,
                               unsigned int flags)
{
    int ret = ENOENT;
#ifdef HAVE_ECH
    ne_sock_addr *sa;

    if (ctx->ech) return 0;

    sa = ne_addr_resolve(hostname, NE_ADDR_HTTPS);
    if (ne_addr_result(sa) == 0) {
        const ne_addr_data *ad;

        if (ne_addr_first(sa)) {
            ad = ne_addr_getdata(sa, NE_ADDR_SVCB);
            if (ad && ad->svcb.params) {
                NE_DEBUG(NE_DBG_SSL, "ssl: Got SVCB parameters for %s: [%s]\n",
                         hostname, ad->svcb.params);
                ctx->echlen = extract_echparam(ad->svcb.params, &ctx->ech);
                if (ctx->echlen) ret = 0;
            }
        }
    }
    else {
        NE_DEBUG(NE_DBG_SSL, "ssl: No HTTPS record for %s\n", hostname);
    }

    ne_addr_destroy(sa);
#endif
    return ret;
}
