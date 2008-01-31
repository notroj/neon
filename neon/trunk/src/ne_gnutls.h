/* 
   Direct GnuTLS interfaces for neon
   Copyright (C) 2008, Joe Orton <joe@manyfish.co.uk>

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

/* ne_gnutls.h defines an interface for direct access to GnuTLS
 * functions with neon.  This interface is implemented by a separate
 * library to libneon itself, named libneon-gnutls.  Any applications
 * using interfaces defined in this header file must link against
 * libneon-gnutls in addition to libneon.  */

/* N.B.  These interfaces exist essentially to allow layering
 * violations; for interfaces to the SSL toolkit where no
 * toolkit-independent abstraction is possible. */

#ifndef NE_GNUTLS_H
#define NE_GNUTLS_H 1

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>

#include "ne_defs.h"
#include "ne_session.h"

NE_BEGIN_DECLS

#if LIBGNUTLS_VERSION_NUMBER >= 0x010711
#define NE_HAVE_SSL_SET_GNUTLS_SIGNCB 1
#endif

#ifdef NE_HAVE_SSL_SET_GNUTLS_SIGNCB
/* Install 'func' as an external signing function; see GnuTLS
 * documentation for gnutls_sign_callback_set(). */
void ne_ssl_set_gnutls_signcb(ne_session *sess,
                              gnutls_sign_func func,
                              void *userdata);
#endif

NE_END_DECLS

#endif /* NE_GNUTLS_H */
