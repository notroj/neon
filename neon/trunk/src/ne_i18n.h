/* 
   Internationalization of neon
   Copyright (C) 2005, Joe Orton <joe@manyfish.co.uk>

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

#ifndef NE_I18N_H
#define NE_I18N_H

/* Initialize translated error messages within neon.  This call is
 * strictly only necessary if this copy of the neon library has been
 * installed into a different prefix than the gettext() implementation
 * on which it depends for i18n purposes.  If this call is not made,
 * the message catalogs will not be found in that case, but the
 * library will operate otherwise correctly (albeit giving
 * English-only error messages).
 *
 * If 'encoding' is non-NULL, it specifies the character encoding for
 * the generated translated strings.  If it is NULL, the appropriate
 * character encoding for the locale will be used. */
void ne_i18n_init(const char *encoding);

#endif /* NE_I18N_H */
