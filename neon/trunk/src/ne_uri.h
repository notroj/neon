/* 
   URI manipulation routines.
   Copyright (C) 1999-2005, Joe Orton <joe@manyfish.co.uk>

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

#ifndef NE_URI_H
#define NE_URI_H

#include "ne_defs.h"

BEGIN_NEON_DECLS

/* Return a copy of a path string with anything other than
 * "unreserved" and the forward-slash character percent-encoded
 * according to the URI encoding rules.  Returns a malloc-allocated
 * string and never NULL. */
char *ne_path_escape(const char *path);

/* Return a decoded copy of a percent-encoded path string. Returns
 * malloc-allocated path on success, or NULL if the string contained
 * any syntactically invalid percent-encoding sequences. */
char *ne_path_unescape(const char *epath);

/* Returns malloc-allocated parent of path, or NULL if path has no
 * parent (such as "/"). */
char *ne_path_parent(const char *path);

/* Returns strcmp-like value giving comparison between p1 and p2,
 * ignoring trailing-slashes. */
int ne_path_compare(const char *p1, const char *p2);

/* Returns non-zero if child is a child of parent */
int ne_path_childof(const char *parent, const char *child);

/* Returns non-zero if path has a trailing slash character */
int ne_path_has_trailing_slash(const char *path);

/* Return the default port for the given scheme, or 0 if none is
 * known. */
unsigned int ne_uri_defaultport(const char *scheme);

typedef struct {
    char *scheme;
    char *host;
    unsigned int port;
    char *path;
    char *authinfo;
} ne_uri;

/* Parse absoluteURI 'uri' and place parsed segments in *parsed.
 * Returns zero on success, non-zero on parse error. Fields of *parsed
 * are malloc'ed, structure should be free'd with uri_free on
 * successful return.  Any unspecified URI fields are set to NULL or 0
 * appropriately in *parsed. */
int ne_uri_parse(const char *uri, ne_uri *parsed);

/* Turns a URI structure back into a string.  String is
 * malloc-allocated, and must be free'd by the caller. */
char *ne_uri_unparse(const ne_uri *uri);

/* Compares URIs u1 and u2, returns non-zero if they are found to be
 * non-equal.  The sign of the return value is <0 if 'u1' is less than
 * 'u2', or >0 if 'u2' is greater than 'u1'. */
int ne_uri_cmp(const ne_uri *u1, const ne_uri *u2);

/* Free URI object. */
void ne_uri_free(ne_uri *parsed);

END_NEON_DECLS

#endif /* NE_URI_H */

