#include <stdio.h>
#include <string.h>

#include "MKPlugin.h"

MONKEY_PLUGIN("fastcgi",		/* shortname */
              "FastCGI client",		/* name */
              VERSION,			/* version */
              MK_PLUGIN_STAGE_30);	/* hooks */

int _mkp_init(struct plugin_api **api, char *confdir)
{
	mk_api = *api;
	return 0;
}

void _mkp_exit()
{
}

int _mkp_stage_30(struct plugin *plugin, struct client_session *cs,
		struct session_request *sr)
{
	char mime[] = "text/plain\r\n";
	const int status = MK_HTTP_OK;
	const char content[] = "Hello world";
	const mk_pointer mime_ptr = { .data = mime, .len = strlen(mime) };

	int n = 0;
	char *url = NULL;

	url = mk_api->mem_alloc_z(sr->uri.len + 1);
	memcpy(url, sr->uri.data, sr->uri.len);

	printf("[FCGI] Got URL %s\n", url);

	if (strcmp(url, "/hello"))
		return MK_PLUGIN_RET_NOT_ME;

	free(url);

	mk_api->header_set_http_status(sr, status);
	sr->headers.cgi = SH_CGI;
	sr->headers.breakline = MK_HEADER_BREAKLINE;
	sr->headers.content_type = mime_ptr;
	sr->headers.content_length = strlen(content);

	n  = mk_api->header_send(cs->socket, cs, sr);
	n += mk_api->socket_send(cs->socket, content, strlen(content));

	sr->close_now = MK_TRUE;

	return MK_PLUGIN_RET_END;
}
