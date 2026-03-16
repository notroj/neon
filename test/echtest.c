/* 
   Test program for the neon resolver interface
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

#include <stdio.h>
#include <string.h>

#include "ne_session.h"
#include "ne_basic.h"

#define BUFLEN (8192)

int main(int argc, char **argv)
{
    ne_session *sess;
    ne_uri uri;
    char buf[BUFLEN];
    size_t buflen = sizeof buf;
    
    if (argc != 2) {
	fprintf(stderr, "%s: Usage: %s <uri>\n", argv[0], argv[0]);
	return 1;
    }
    if (ne_sock_init()) {
	fprintf(stderr, "%s: Failed to initialize socket library.\n", argv[0]);
        return 1;
    }

    ne_debug_init(stderr, NE_DBG_SSL);
    
    if (ne_uri_parse(argv[1], &uri) || uri.host == NULL || uri.scheme == NULL) {
	fprintf(stderr, "%s: Could not parse URI `%s`.\n", argv[0], argv[1]);
        return 1;
    }

    if (uri.port == 0) uri.port = ne_uri_defaultport(uri.scheme);
    sess = ne_session_create(uri.scheme, uri.host, uri.port);

    ne_set_useragent(sess, "neon-echtest/" NEON_VERSION);
    ne_set_session_flag(sess, NE_SESSFLAG_TLS_ECH, 1);
    ne_ssl_trust_default_ca(sess);
    
    if (ne_getbuf(sess, uri.path, buf, &buflen) != NE_OK) {
	fprintf(stderr, "%s: Request failed: `%s`.\n", argv[0], ne_get_error(sess));
        return 1;
    }

    if (fwrite(buf, buflen, 1, stdout) != 1) {
        fprintf(stderr, "%s: Could not write to stdout.\n", argv[0] );
        return 2;
    }
    
    ne_session_destroy(sess);
    return 0;
}
