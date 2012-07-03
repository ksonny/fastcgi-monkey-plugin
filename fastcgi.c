#include <stdio.h>
#include <string.h>

#include "MKPlugin.h"

#define DEBUG

#include "dbg.h"
#include "mk_stream.h"
#include "protocol.h"

struct fcgi_server {
	struct mk_config *conf;
	char  *addr;
	int    port;
};

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

#define __write_param(env, len, pos, key, value) do { \
		check(len - pos > fcgi_param_write(NULL, key, value), \
			"Out of memory."); \
		pos += fcgi_param_write(env + pos, key, value); \
	} while (0)

int fcgi_create_static_env(void)
{
	mk_pointer key, value;

	mk_api->pointer_set(&key,   "PATH_INFO");
	mk_api->pointer_set(&value, "");
	log_info("%.*s=%.*s", (int)key.len, key.data, (int)value.len, value.data);

	mk_api->pointer_set(&key,   "GATEWAY_INTERFACE");
	mk_api->pointer_set(&value, "CGI/1.1");
	log_info("%.*s=%.*s", (int)key.len, key.data, (int)value.len, value.data);

	mk_api->pointer_set(&key,   "REDIRECT_STATUS");
	mk_api->pointer_set(&value, "200");
	log_info("%.*s=%.*s", (int)key.len, key.data, (int)value.len, value.data);

	mk_api->pointer_set(&key,   "SERVER_SOFTWARE");
	value = mk_api->config->server_software;
	log_info("%.*s=%.*s", (int)key.len, key.data, (int)value.len, value.data);

	return 0;
}

mk_pointer fcgi_create_env(struct session_request *sr)
{
	mk_pointer key, value;
	char buffer[128];
	char *tmpuri = NULL;
	size_t pos = 0, len = 4096;
	uint8_t *env;

	env = mk_api->mem_alloc(len);
	check_mem(env);

	mk_api->pointer_set(&key,   "PATH_INFO");
	mk_api->pointer_set(&value, "");
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "GATEWAY_INTERFACE");
	mk_api->pointer_set(&value, "CGI/1.1");
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "REDIRECT_STATUS");
	mk_api->pointer_set(&value, "200");
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "SERVER_SOFTWARE");
	mk_api->pointer_set(&value, sr->host_conf->host_signature);
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "SCRIPT_FILENAME");
	value = sr->real_path;
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "SCRIPT_NAME");
	value = sr->uri_processed;
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "REQUEST_METHOD");
	value = sr->method_p;
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "HTTP_HOST");
	value = sr->host;
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "SERVER_PROTOCOL");
	value = sr->protocol_p;
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "REQUEST_URI");
	if (sr->query_string.len > 0) {
		value.len = sr->uri.len + sr->query_string.len + 2;
		tmpuri = mk_api->mem_alloc(value.len);
		check_mem(tmpuri);
		value.data = tmpuri;
		snprintf(value.data, value.len, "%.*s?%.*s",
			(int)sr->uri.len, sr->uri.data,
			(int)sr->query_string.len, sr->query_string.data);
	} else {
		value = sr->uri;
	}
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "QUERY_STRING");
	value = sr->query_string;
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "CONTENT_TYPE");
	value = sr->content_type;
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "CONTENT_LENGTH");
	snprintf(buffer, 128, "%d", sr->content_length);
	mk_api->pointer_set(&value, buffer);
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "HTTP_COOKIE");
	value = mk_api->header_get(&sr->headers_toc, "Cookie:", 7);
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "HTTP_USER_AGENT");
	value = mk_api->header_get(&sr->headers_toc, "User-Agent:", 11);
	__write_param(env, len, pos, key, value);

	if (tmpuri) mk_api->mem_free(tmpuri);
	return (mk_pointer){ .len = pos, .data = (char *)env };
error:
	if (tmpuri) mk_api->mem_free(tmpuri);
	if (env) mk_api->mem_free(env);
	return (mk_pointer){ .len = 0, .data = NULL };
}

#undef __write_param

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
		struct session_request *sr)
{
	struct fcgi_begin_req_body b = {
		.role  = FCGI_RESPONDER,
		.flags = 0,
	};
	struct fcgi_header h = {
		.version  = FCGI_VERSION_1,
		.type     = 0,
		.req_id   = 1,
		.body_len = 0,
		.body_pad = 0,
	};
	mk_pointer env;
	ssize_t bytes_sent;
	struct mk_iov *iov = NULL;
	size_t len1 = sizeof(h) + sizeof(b),
	       len2 = sizeof(h),
	       len3 = 2 * sizeof(h);
	uint8_t p1[len1], p2[len2], p3[len3];

	env = fcgi_create_env(sr);

	// Write begin request.
	h.type     = FCGI_BEGIN_REQUEST;
	h.body_len = sizeof(b);
	fcgi_write_header(p1, &h);
	fcgi_write_begin_req_body(p1 + sizeof(h), &b);

	// Write parameter.
	h.type = FCGI_PARAMS;
	h.body_len = env.len;
	fcgi_write_header(p2, &h);

	// Write parameter end.
	h.type = FCGI_PARAMS;
	h.body_len = 0;
	fcgi_write_header(p3, &h);

	// Write stdin end.
	h.type = FCGI_STDIN;
	h.body_len = 0;
	fcgi_write_header(p3 + sizeof(h), &h);

	iov = mk_api->iov_create(4, 0);
	check_mem(iov);
	mk_api->iov_add_entry(iov, (char *)p1, len1, mk_iov_none, 0);
	mk_api->iov_add_entry(iov, (char *)p2, len2, mk_iov_none, 0);
	mk_api->iov_add_entry(iov, env.data, env.len, mk_iov_none, 0);
	mk_api->iov_add_entry(iov, (char *)p3, len3, mk_iov_none, 0);

	bytes_sent = mk_api->iov_send(fcgi_fd, iov);
	check(bytes_sent == (ssize_t)iov->total_len, "Failed to sent request.");

	mk_api->mem_free(env.data);
	mk_api->iov_free(iov);
	return 0;
error:
	if (env.data) mk_api->mem_free(env.data);
	if (iov) mk_api->iov_free(iov);
	mk_api->header_set_http_status(sr, MK_SERVER_INTERNAL_ERROR);
	return -1;
}

static const char *strnchr(const char *p, const size_t len, const char c)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (*(p + i) == c) return (p + i);
	}
	return '\0';
}

#define SIZEOF_CRLF 2
#define SIZEOF_LF 1

static size_t fcgi_parse_cgi_headers(const char *data, size_t len)
{
	size_t cnt = 0, i;
	const char *p = data, *q = NULL;

	for (i = 0; q < (data + len); i++) {
		q = strnchr(p, len, '\n');
		if (!q) {
			break;
		}
		cnt += (size_t)(q - p) + SIZEOF_LF;
		if (p + SIZEOF_CRLF >= q) {
			break;
		}
		p = q + SIZEOF_LF;
	}
	return cnt;
}

int fcgi_recv_response(int fcgi_fd,
		struct client_session *cs,
		struct session_request *sr)
{
	ssize_t bytes_read, headers_offset;
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
		bytes_read = fcgi_read_header(stream_ptr(&ps), &h);
		stream_commit(&ps, bytes_read);

		if (h.type == FCGI_STDOUT && h.body_len > 0) {
			mk_api->iov_add_entry(iov,
				(char *)stream_ptr(&ps),
				(int)h.body_len,
				mk_iov_none,
				MK_IOV_NOT_FREE_BUF);
		}
		stream_commit(&ps, h.body_len + h.body_pad);
	}

	headers_offset = fcgi_parse_cgi_headers(iov->io[0].iov_base,
				iov->io[0].iov_len);

	mk_api->header_set_http_status(sr,  MK_HTTP_OK);
	sr->headers.cgi = SH_CGI;
	sr->headers.content_length = iov->total_len - headers_offset;
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
	(void)plugin;
	char *url = NULL;
	int fcgi_fd = -1;

	url = mk_api->mem_alloc_z(sr->uri.len + 1);
	memcpy(url, sr->uri.data, sr->uri.len);

	if (strcmp(url, "/hello")) {
		mk_api->mem_free(url);
		return MK_PLUGIN_RET_NOT_ME;
	}
	mk_api->mem_free(url);

	fcgi_fd = mk_api->socket_connect(server.addr, server.port);
	check(fcgi_fd > 0,
		"Could not connect to %s:%i.", server.addr, server.port);
	mk_api->socket_cork_flag(fcgi_fd, MK_FALSE);

	check(!fcgi_send_request(fcgi_fd, sr),
		"Failed to send request");
	check(!fcgi_recv_response(fcgi_fd, cs, sr),
		"Failed to received response.");

	mk_api->socket_close(fcgi_fd);

	return MK_PLUGIN_RET_END;
error:
	if (fcgi_fd != -1) mk_api->socket_close(fcgi_fd);
	mk_api->header_set_http_status(sr, MK_SERVER_INTERNAL_ERROR);
	sr->close_now = MK_TRUE;
	return MK_PLUGIN_RET_CLOSE_CONX;
}
