/* 
   Test cases for the ne_xmlreq.h interface.
   Copyright (C) 2005-2006, Joe Orton <joe@manyfish.co.uk>

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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ne_xmlreq.h"

#include "tests.h"
#include "utils.h"

/* Dummy start_element callback; takes int * userdata and toggles the
 * pointed-to int iff the root element has name "hello".  Accepts all
 * elements. */
static int startelm(void *userdata, int state,
                    const char *nspace, const char *name,
		    const char **atts)
{
    int *flag = userdata;

    if (state == NE_XML_STATEROOT && strcmp(name, "hello") == 0) {
        *flag = !*flag;
    }

    return ++state;
}

static int pc_startelm(void *userdata, int state,
                    const char *nspace, const char *name,
		    const char **atts)
{
    ne_buffer *buf = userdata;
    ne_buffer_concat(buf, "<", "{", nspace, "}", name, ">", NULL);
    return state + 1;
}

static int pc_chardata(void *userdata, int state, const char *cdata, size_t len)
{
    ne_buffer *buf = userdata;
    ne_buffer_append(buf, cdata, len);
    return NE_XML_DECLINE;
}

static int parse_for_ctype(const char *ctype, const char *body,
                           const char *output)
{
    ne_session *sess;
    ne_request *req;
    ne_xml_parser *parser;
    ne_buffer *buf = ne_buffer_create();
    char response[BUFSIZ];

    ne_snprintf(response, sizeof response,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: %s\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s", 
                ctype, body);

    CALL(make_session(&sess, single_serve_string, response));
    
    req = ne_request_create(sess, "PARSE", "/");
    parser = ne_xml_create();

    ne_xml_push_handler(parser, pc_startelm, pc_chardata, NULL, buf);
    
    ONREQ(ne_xml_dispatch_request(req, parser));

    if (output) {
        ONV(strcmp(buf->data, output),
            ("for '%s': result mismatch: %s not %s", ctype, buf->data,
             output));
    }

    ne_buffer_destroy(buf);
    ne_xml_destroy(parser);
    ne_request_destroy(req);
    return destroy_and_wait(sess);
}

#define ISO_FOOBAR "f\xd8\xd8" "b\xe1" "r"

static int success(void)
{
    static const struct {
        const char *ctype, *body, *output;
    } ts[] = {
        { "text/xml", "<?xml version='1.0' encoding='UTF-8'?>\n<hello>foo</hello>", "<{}hello>foo" },
        { "text/xml; charset=ISO-8859-1", "<?xml version='1.0'?>\n<hello>" ISO_FOOBAR "</hello>",
          "<{}hello>fØØbár" },
        { "application/xml", "<?xml version='1.0'?><hello/>" },
    };
    unsigned n;

    for (n = 0; n < sizeof(ts)/sizeof(ts[0]); n++)
        CALL(parse_for_ctype(ts[n].ctype, ts[n].body, ts[n].output));

    return OK;
}

static int failure(void)
{
    ne_session *sess;
    ne_request *req;
    ne_xml_parser *parser;
    
    CALL(make_session(&sess, single_serve_string, 
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Type: text/xml\r\n"
                      "Connection: close\r\n" "\r\n"
                      "<?xml version='1.0' encoding='UTF-8'?>\n"
                      "<hello>"));
    
    req = ne_request_create(sess, "PARSE", "/");
    parser = ne_xml_create();
    
    ONN("XML parse did not fail",
        ne_xml_dispatch_request(req, parser) == NE_OK);

    NE_DEBUG(NE_DBG_HTTP, "error string: %s\n", ne_get_error(sess));
    
    ONV(strstr(ne_get_error(sess), "200 OK") != NULL,
        ("no error string set on parse error: '%s'", ne_get_error(sess)));

    ne_xml_destroy(parser);
    ne_request_destroy(req);
    return destroy_and_wait(sess);
}

static int fail_ctype(void)
{
    ne_session *sess;
    ne_request *req;
    ne_xml_parser *parser;

    CALL(make_session(&sess, single_serve_string, 
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Type: text/xml; charset=FOOBAR-16\r\n"
                      "Connection: close\r\n" "\r\n"
                      "<?xml version='1.0' encoding='UTF-8'?>\n"
                      "<hello/>"));

    req = ne_request_create(sess, "PARSE", "/");
    parser = ne_xml_create();

    ONN("XML parse did not fail",
        ne_xml_dispatch_request(req, parser) == NE_OK);

    NE_DEBUG(NE_DBG_HTTP, "error string: %s\n", ne_get_error(sess));

    ONV(strstr(ne_get_error(sess), "200 OK") != NULL,
        ("no error string set on parse error: '%s'", ne_get_error(sess)));

    ne_xml_destroy(parser);
    ne_request_destroy(req);
    return destroy_and_wait(sess);
}

static int types(void)
{
    static const struct {
        const char *type;
        int is_xml;
    } ts[] = {
        { "text/xml", 1 },
        { "tExT/XmL", 1 },
        { "text/html", 0 },
        { "application/foo+xml", 1 },
        { "aPpLiCaTION/FoOOO+xMl", 1 },
        { "application/xml", 1 },
        { "application/+xml", 0 },
        { "application/fish+xml2", 0 },
        { "foo/bar+xml", 1 },
        { "f/b", 0 },
        { "garble garble wotsit", 0 }
    };
    unsigned n;

    for (n = 0; n < sizeof(ts)/sizeof(ts[0]); n++) {
        char resp[128];
        ne_session *sess;
        ne_request *req;
        ne_xml_parser *parser;
        int flag = 0;

        ne_snprintf(resp, sizeof resp,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: %s\r\n"
                    "Connection: close\r\n" "\r\n"
                    "<?xml version='1.0' encoding='UTF-8'?>\n"
                    "<hello/>",
                    ts[n].type);

        CALL(make_session(&sess, single_serve_string, resp));
    
        req = ne_request_create(sess, "PARSE", "/");
        parser = ne_xml_create();
        
        ne_xml_push_handler(parser, startelm, NULL, NULL, &flag);
        
        ONREQ(ne_xml_dispatch_request(req, parser));
        
        ONV(flag && !ts[n].is_xml,
            ("XML parser invoked for non-XML type: %s", ts[n].type));
        ONV(!flag && ts[n].is_xml,
            ("XML parser not invoked for XML type: %s", ts[n].type));
        
        ne_xml_destroy(parser);
        ne_request_destroy(req);
        ne_session_destroy(sess);
        CALL(await_server());
    }

    return OK;
}

ne_test tests[] = {
    T(success),
    T(failure),
    T(fail_ctype),
    T(types),
    T(NULL)
};

