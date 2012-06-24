#include <stdio.h>
#include <string.h>

#include "MKPlugin.h"

#define DEBUG

#include "dbg.h"
#include "mk_stream.h"
#include "protocol.h"

MONKEY_PLUGIN("fastcgi",		/* shortname */
              "FastCGI client",		/* name */
              VERSION,			/* version */
              MK_PLUGIN_STAGE_30);	/* hooks */

static struct fcgi_server server;

int fcgi_conf(char *confdir)
{
	unsigned long len;
	char *conf_path = NULL;

	struct mk_config_section *section;
	struct mk_list *head;

	mk_api->str_build(&conf_path, &len, "%s/fastcgi.conf", confdir);
	server.conf = mk_api->config_create(conf_path);

	mk_list_foreach(head, &server.conf->sections) {
		section = mk_list_entry(head, struct mk_config_section, _head);

		if (strcasecmp(section->name, "FASTCGI") != 0)
			continue;

		server.addr = mk_api->config_section_getval(
			section, "ServerAddr", MK_CONFIG_VAL_STR);
		server.port = (size_t)mk_api->config_section_getval(
			section, "ServerPort", MK_CONFIG_VAL_NUM);
	}

	mk_api->mem_free(conf_path);

	return 0;
}

int fcgi_validate_conf(void)
{
	check(server.addr != NULL, "No server addr configured.");
	check(server.port != 0, "No server port configured.");

	return 0;
error:
	return -1;
}

int _mkp_init(struct plugin_api **api, char *confdir)
{
	mk_api = *api;

	mk_bug(fcgi_validate_struct_sizes());

	fcgi_conf(confdir);
	fcgi_validate_conf();

	return 0;
}

void _mkp_exit()
{
}

int fcgi_send_request(int fcgi_fd,
		struct client_session *cs,
		struct session_request *sr)
{
	struct fcgi_header h = {
		.version  = FCGI_VERSION_1,
		.type     = 0,
		.req_id   = 1,
		.body_len = 0,
		.body_pad = 0,
	};
	ssize_t bytes_sent;
	struct pkg_stream ps;

	check(!mk_stream_init(&ps, fcgi_fd, 4096), "Failed to create stream.");
	ps.end = ps.size;

	// Write BEGIN_REQ.
	check(!fcgi_write_begin_req(&ps, 1, FCGI_RESPONDER, 0),
		"Failed to write begin req.");

	// Write PARAMS eos.
	h.type     = FCGI_PARAMS;
	h.body_len = 0;
	check(!fcgi_write_header(&ps, &h),
		"Failed to write params end-of-stream.");
	stream_pkg_mark_end(&ps);

	// Write STDIN eos.
	h.type     = FCGI_STDIN;
	h.body_len = 0;
	check(!fcgi_write_header(&ps, &h),
		"Failed to write stdin end-of-stream.");
	stream_pkg_mark_end(&ps);

	bytes_sent = mk_stream_flush(&ps);
	log_info("Sent %ld bytes on fd %d.", bytes_sent, fcgi_fd);
	check(bytes_sent != -1, "Failed to send BEGIN_REQ.");

	mk_stream_destroy(&ps);
	return 0;
error:
	mk_stream_destroy(&ps);
	mk_api->header_set_http_status(sr, MK_SERVER_INTERNAL_ERROR);
	return -1;
}

int fcgi_recv_response(int fcgi_fd,
		struct client_session *cs,
		struct session_request *sr)
{
	ssize_t bytes_read;
	struct fcgi_header h;
	struct pkg_stream ps;
	struct mk_iov *iov;

	check(!mk_stream_init(&ps, fcgi_fd, 4096), "Failed to create stream.");

	do {
		bytes_read = mk_stream_refill(&ps);

		check(bytes_read != -1, "Error receiving response.");

		debug("Received %ld bytes on fd %i.",
			bytes_read, fcgi_fd);

	} while (bytes_read > 0);

	ps.pos = 0;
	iov = mk_api->iov_create(32, 0);

	while (stream_rem(&ps) > 0) {
		fcgi_read_header(&ps, &h);

		if (h.type == FCGI_STDOUT && h.body_len > 0) {
			mk_api->iov_add_entry(iov,
				(char *)stream_ptr(&ps),
				(int)h.body_len,
				mk_iov_none,
				MK_IOV_NOT_FREE_BUF);
		}
		if (h.body_len > 0) {
			stream_commit(&ps, h.body_len + h.body_pad);
		}
	}


	mk_api->header_set_http_status(sr,  MK_HTTP_OK);
	sr->headers.cgi = SH_CGI;
	sr->headers.content_length = iov->total_len - 27;
	mk_api->header_send(cs->socket, cs, sr);
	mk_api->socket_sendv(cs->socket, iov);

	mk_stream_destroy(&ps);
	return 0;
error:
	mk_stream_destroy(&ps);
	mk_api->header_set_http_status(sr, MK_SERVER_INTERNAL_ERROR);
	return -1;
}

int _mkp_stage_30(struct plugin *plugin, struct client_session *cs,
		struct session_request *sr)
{
	char host[] = "localhost";
	int port = 7999;

	char *url = NULL;
	int fcgi_fd = -1;

	url = mk_api->mem_alloc_z(sr->uri.len + 1);
	memcpy(url, sr->uri.data, sr->uri.len);

	if (strcmp(url, "/hello")) {
		mk_api->mem_free(url);
		return MK_PLUGIN_RET_NOT_ME;
	}
	mk_api->mem_free(url);

	fcgi_fd = mk_api->socket_connect(host, port);
	check(fcgi_fd > 0,
		"Could not connect to %s:%i.", host, port);
	mk_api->socket_cork_flag(fcgi_fd, MK_FALSE);

	check(!fcgi_send_request(fcgi_fd, cs, sr),
		"Failed to send request");
	check(!fcgi_recv_response(fcgi_fd, cs, sr),
		"Failed to received response.");

	mk_api->socket_close(fcgi_fd);

	sr->close_now = MK_TRUE;

	return MK_PLUGIN_RET_END;
error:
	mk_api->header_set_http_status(sr, MK_SERVER_INTERNAL_ERROR);
	return MK_PLUGIN_RET_CLOSE_CONX;
}
