/* 
   PKCS#11 support for neon
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

#ifndef NE_PKCS11_H
#define NE_PKCS11_H 1

#include "ne_defs.h"
#include "ne_session.h"

NE_BEGIN_DECLS

#define NE_SSL_P11PIN_COUNT_LOW (0x01) /* an incorrect PIN has been
                                        * entered. */
#define NE_SSL_P11PIN_FINAL_TRY (0x02) /* token will become locked if
                                        * entered PIN is incorrect */

/* Callback for PKCS#11 PIN entry.  The callback provides the PIN code
 * to unlock the token with label 'token_label' in the slot described
 * by 'slot_descr'.
 *
 * The PIN code, as a NUL-terminated ASCII string, should be copied
 * into the 'pin' buffer (of fixed length NE_SSL_P11PINLEN), and
 * return 0 to indicate success. Alternatively, the callback may
 * return -1 to indicate failure (in which case, the pin buffer is
 * ignored).  When the PIN is needed for the first time, the 
 *
 * The NE_SSL_P11PIN_COUNT_LOW and/or NE_SSL_P11PIN_FAST_TRY hints may
 * be set in the 'flags' argument, if these hints are made available
 * by the token. */
typedef int (*ne_ssl_pkcs11_pin_fn)(void *userdata, int attempt,
                                    const char *slot_descr,
                                    const char *token_label,
                                    unsigned int flags,
                                    char *pin);
#define NE_SSL_P11PINLEN (256)

void ne_ssl_set_pkcs11_pin(ne_session *sess, ne_ssl_pkcs11_pin_fn fn,
                           void *userdata);

/* Use a PKCS#11 provider of given name to supply a client certificate
 * if requested.  Returns NE_OK on success, NE_LOOKUP if the provider
 * could not be loaded/initialized (in which case, the session error
 * string is set), and NE_FAILED if PKCS#11 is not supported. */
int ne_ssl_provide_pkcs11_clicert(ne_session *sess, 
                                  const char *provider);

/* Use a NSS softoken pseudo-PKCS#11 provider of given name
 * (e.g. "softokn3") to supply a client certificate if requested,
 * using database in given directory name; the other parameters may be
 * NULL.  Returns NE_OK on success, NE_LOOKUP if the provider could
 * not be loaded/initialized (in which case, the session error string
 * is set), and NE_FAILED if PKCS#11 is not supported. */
int ne_ssl_provide_nsspk11_clicert(ne_session *sess, 
                                   const char *provider,
                                   const char *directory,
                                   const char *cert_prefix,
                                   const char *key_prefix,
                                   const char *secmod_db);

NE_END_DECLS

#endif /* NE_PKCS11_H */
