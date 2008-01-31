/*
   neon GnuTLS support library
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

#include "config.h"

#include "ne_gnutls.h"
#include "ne_private.h"
#include "ne_privssl.h"

#ifdef HAVE_GNUTLS_SIGN_CALLBACK_SET
void ne_ssl_set_gnutls_signcb(ne_session *sess,
                              gnutls_sign_func func,
                              void *userdata)
{
    sess->ssl_context->sign_func = func;
    sess->ssl_context->sign_data = userdata;
}
#endif
