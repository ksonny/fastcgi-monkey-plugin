#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <regex.h>

#include "MKPlugin.h"

#include "dbg.h"
#include "fcgi_fd.h"
#include "protocol.h"
#include "chunk.h"
#include "request.h"

struct fcgi_server {
	struct mk_config *conf;
	regex_t match_regex;
	char   *addr;
	int     port;
};

struct fcgi_thread_data {
	struct chunk_list cm;
	struct request_list rl;
	struct fcgi_fd_list fdl;
};

MONKEY_PLUGIN("fastcgi",		/* shortname */
              "FastCGI client",		/* name */
              VERSION,			/* version */
              MK_PLUGIN_STAGE_30 | MK_PLUGIN_CORE_THCTX);	/* hooks */

static struct fcgi_server server;
static __thread struct fcgi_thread_data tdata;

static int fcgi_validate_conf(void)
{
	check(server.addr != NULL, "No server addr configured.");
	check(server.port != 0, "No server port configured.");

	return 0;
error:
	return -1;
}

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

	return fcgi_validate_conf();
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

mk_pointer fcgi_create_env(struct client_session *cs,
		struct session_request *sr)
{
	mk_pointer key, value;
	char buffer[128];
	char *tmpuri = NULL;
	size_t pos = 0, len = 4096;
	uint8_t *env;
	struct sockaddr_in addr;
	socklen_t addr_len;

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

	mk_api->pointer_set(&key,   "DOCUMENT_ROOT");
	value = sr->host_conf->documentroot;
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "SERVER_PROTOCOL");
	value = sr->protocol_p;
	__write_param(env, len, pos, key, value);

	mk_api->pointer_set(&key,   "SERVER_NAME");
	value.data = sr->host_alias->name;
	value.len  = sr->host_alias->len;
	__write_param(env, len, pos, key, value);

	addr_len = sizeof(addr);
	if (!getsockname(cs->socket, (struct sockaddr *)&addr, &addr_len)) {
		if (!inet_ntop(AF_INET, &addr.sin_addr, buffer, 128)) {
			log_warn("Failed to get bound address.");
			buffer[0] = '\0';
		}
		mk_api->pointer_set(&key,   "SERVER_ADDR");
		mk_api->pointer_set(&value, buffer);
		__write_param(env, len, pos, key, value);

		snprintf(buffer, 128, "%d", ntohs(addr.sin_port));
		mk_api->pointer_set(&key,   "SERVER_PORT");
		mk_api->pointer_set(&value, buffer);
		__write_param(env, len, pos, key, value);
	} else {
		log_warn("%s", clean_errno());
		errno = 0;
	}

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

	addr_len = sizeof(addr);
	if (!getpeername(cs->socket, (struct sockaddr *)&addr, &addr_len)) {
		inet_ntop(AF_INET, &addr.sin_addr, buffer, 128);
		mk_api->pointer_set(&key,   "REMOTE_ADDR");
		mk_api->pointer_set(&value, buffer);
		__write_param(env, len, pos, key, value);

		snprintf(buffer, 128, "%d", ntohs(addr.sin_port));
		mk_api->pointer_set(&key,   "REMOTE_PORT");
		mk_api->pointer_set(&value, buffer);
		__write_param(env, len, pos, key, value);
	} else {
		log_warn("%s", clean_errno());
		errno = 0;
	}

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
	int ret = 0;
	char error_str[80];

	mk_api = *api;

	chunk_module_init(mk_api->mem_alloc, mk_api->mem_free);
	request_module_init(mk_api->mem_alloc, mk_api->mem_free);
	fcgi_fd_module_init(mk_api->mem_alloc, mk_api->mem_free);

	check(!fcgi_validate_struct_sizes(),
		"Validating struct sizes failed.");
	check(!fcgi_conf(confdir),
		"Failed to read config.");

	ret = regcomp(&server.match_regex, "/fcgitest", REG_EXTENDED|REG_NOSUB);
	check(!ret, "Regex failure.");

	return 0;
error:
	if (ret) {
		regerror(ret, &server.match_regex, error_str, 80);
		log_err("Regex compile failed: %s", error_str);
	}
	return -1;
}

void _mkp_exit()
{
	regfree(&server.match_regex);
	log_info("Exit module.");
}

static size_t fcgi_parse_cgi_headers(const char *data, size_t len)
{
	size_t cnt = 0, i;
	const char *p = data, *q = NULL;

	for (i = 0; q < (data + len); i++) {
		q = memchr(p, '\n', len);
		if (!q) {
			break;
		}
		cnt += (size_t)(q - p) + 1;
		if (p + 2 >= q) {
			break;
		}
		p = q + 1;
	}
	return cnt;
}
/**
 * Will return 0 if there are any connections available to handle a
 * request. If such a connection is sleeping, wake it.
 */
int fcgi_wake_connection()
{
	struct fcgi_fd *fd;

	fd = fcgi_fd_list_get_by_state(&tdata.fdl,
			FCGI_FD_SLEEPING | FCGI_FD_READY);
	if (!fd) {
		return -1;
	}
	if (fd->state == FCGI_FD_SLEEPING) {

		PLUGIN_TRACE("[FCGI_FD %d] Waking up connection.", fd->fd);
		mk_api->event_socket_change_mode(fd->fd,
				MK_EPOLL_RW,
				MK_EPOLL_LEVEL_TRIGGERED);
		fcgi_fd_set_state(fd, FCGI_FD_READY);
	}
	return 0;
}

int fcgi_new_connection(struct plugin *plugin, struct client_session *cs,
		struct session_request *sr)
{
	struct fcgi_fd *fd;

	fd = fcgi_fd_list_get_by_state(&tdata.fdl, FCGI_FD_AVAILABLE);

	if (fd) {
		fd->fd = mk_api->socket_connect(server.addr, server.port);
		check(fd->fd > 0, "Could not connect to fcgi server.");

		mk_api->socket_set_nonblocking(fd->fd);
		mk_api->event_add(fd->fd,
				MK_EPOLL_RW,
				plugin,
				cs, sr,
				MK_EPOLL_LEVEL_TRIGGERED);

		fcgi_fd_set_state(fd, FCGI_FD_READY);
	} else {
		PLUGIN_TRACE("Connection limit reached.");
	}

	return 0;
error:
	return -1;
}

int fcgi_prepare_request(struct request *req)
{
	struct fcgi_begin_req_body b = {
		.role  = FCGI_RESPONDER,
		.flags = FCGI_KEEP_CONN,
	};
	struct fcgi_header h = {
		.version  = FCGI_VERSION_1,
		.body_pad = 0,
	};
	size_t len1 = sizeof(h) + sizeof(b),
	       len2 = sizeof(h),
	       len3 = 2 * sizeof(h);
	uint8_t *p1 = NULL, *p2 = NULL, *p3 = NULL;
	int req_id = -1;
	mk_pointer env = {0};

	req_id = request_list_index_of(&tdata.rl, req);
	check(req_id > 0, "Bad request id: %d.", req_id);
	env    = fcgi_create_env(req->ccs, req->sr);

	check(req_id != -1, "Could not get index of request.");

	p1 = mk_api->mem_alloc(len1 + len2 + len3);
	check_mem(p1);
	p2 = p1 + len1;
	p3 = p2 + len2;

	// Write begin request.
	h.type     = FCGI_BEGIN_REQUEST;
	h.req_id   = req_id;
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

	mk_api->iov_add_entry(&req->iov, (char *)p1, len1, mk_iov_none, 1);
	mk_api->iov_add_entry(&req->iov, (char *)p2, len2, mk_iov_none, 0);
	mk_api->iov_add_entry(&req->iov, env.data, env.len, mk_iov_none, 1);
	mk_api->iov_add_entry(&req->iov, (char *)p3, len3, mk_iov_none, 0);

	return 0;
error:
	if (p1) mk_api->mem_free(p1);
	if (env.data) mk_api->mem_free(env.data);
	return -1;
}

int fcgi_send_request(struct request *req, struct fcgi_fd *fd)
{
	check(mk_api->socket_sendv(fd->fd, &req->iov) > 0,
		"Socket error occured.");
	check(!request_set_state(req, REQ_SENT),
		"Failed to set req state.");
	request_release_chunks(req);
	return 0;
error:
	request_release_chunks(req);
	return -1;
}

int fcgi_send_abort_request(struct request *req, struct fcgi_fd *fd)
{
	struct fcgi_header h = {
		.version  = FCGI_VERSION_1,
		.type     = FCGI_ABORT_REQUEST,
		.req_id   = request_list_index_of(&tdata.rl, req),
		.body_len = 0,
		.body_pad = 0,
	};
	uint8_t buf[sizeof(h)];
	ssize_t ret;

	check(h.req_id > 0, "Bad request id: %d.", h.req_id);
	fcgi_write_header(buf, &h);

	ret = mk_api->socket_send(fd->fd, buf, sizeof(h));
	check(ret != -1, "Socket error.");

	return 0;
error:
	return -1;
}

int fcgi_end_request(struct request *req)
{
	ssize_t headers_offset;

	headers_offset = fcgi_parse_cgi_headers(req->iov.io[0].iov_base,
			req->iov.io[0].iov_len);

	mk_api->header_set_http_status(req->sr,  MK_HTTP_OK);
	req->sr->headers.cgi = SH_CGI;
	req->sr->headers.content_length = req->iov.total_len - headers_offset;

	mk_api->header_send(req->fd, req->ccs, req->sr);
	mk_api->socket_sendv(req->fd, &req->iov);

	request_release_chunks(req);
	return 0;
}

static ssize_t fcgi_handle_pkg(struct fcgi_fd *fd,
		struct fcgi_header h,
		struct chunk_ptr read)
{
	struct fcgi_end_req_body b;
	struct request *req;

	size_t pkg_size = sizeof(h) + h.body_len + h.body_pad;

	req = request_list_get(&tdata.rl, h.req_id);
	check(req, "Failed to get request %d.", h.req_id);

	switch (h.type) {
	case FCGI_STDERR:
		log_warn("[REQ %d] Received stderr.", h.req_id);
		break;

	case FCGI_STDOUT:
		if (h.body_len == 0) {
			check(!request_set_state(req, REQ_STREAM_CLOSED),
				"Failed to set request state.");
			break;
		}
		check(request_add_pkg(req, h, read) > 0,
			"[REQ %d] Failed to add pkg.",
			h.req_id);
		break;

	case FCGI_END_REQUEST:
		fcgi_read_end_req_body(read.data + sizeof(h), &b);

		switch (b.app_status) {
		case EXIT_SUCCESS:
			break;
		case EXIT_FAILURE:
			log_warn("[REQ %d] Application exit failure.",
				h.req_id);
			break;
		}

		switch (b.protocol_status) {
		case FCGI_REQUEST_COMPLETE:
			break;
		case FCGI_CANT_MPX_CONN:
		case FCGI_OVERLOADED:
		case FCGI_UNKNOWN_ROLE:
		default:
			log_warn("[REQ %d] Protocol status: %s",
				h.req_id,
				FCGI_PROTOCOL_STATUS_STR(b.protocol_status));
		}

		fcgi_fd_set_req_id(fd, 0);
		request_set_fcgi_fd(req, -1);

		check(!fcgi_fd_set_state(fd, FCGI_FD_READY),
			"Failed to set fd state.");
		check(!request_set_state(req, REQ_ENDED),
			"Failed to set request state.");
		break;

	case 0:
		sentinel("[REQ %d] Received NULL package.", h.req_id);
		break;
	default:
		log_info("[REQ %d] Ignore package: %s",
			h.req_id,
			FCGI_MSG_TYPE_STR(h.type));
	}

	return pkg_size;
error:
	return -1;
}

int fcgi_recv_response(struct fcgi_fd *fd)
{
	size_t pkg_size, inherit = 0;
	ssize_t ret = 0;
	int done = 0;

	struct fcgi_header h;
	struct chunk *c;
	struct chunk_ptr write = {0}, read = {0};

	PLUGIN_TRACE("[FCGI_FD %d] Receiving response.", fd->fd);

	c = chunk_list_current(&tdata.cm);
	if (c != NULL) {
		write = chunk_write_ptr(c);
		read  = chunk_read_ptr(c);
	}

	do {
		if (inherit > 0 || write.len < sizeof(h)) {
			PLUGIN_TRACE("New chunk, inherit %ld.", inherit);
			c = chunk_new(65536);
			check_mem(c);
			check(!chunk_list_add(&tdata.cm, c, inherit),
				"Failed to add chunk.");
			write   = chunk_write_ptr(c);
			inherit = 0;
		}

		ret = mk_api->socket_read(fd->fd, write.data, write.len);

		if (ret == 0) {
			check(!fcgi_fd_set_state(fd, FCGI_FD_CLOSING),
				"Failed to set fd state.");
			done = 1;
		} else if (ret == -1) {
			if (errno == EAGAIN) {
				errno = 0;
				done = 1;
			} else {
				sentinel("Socket read error.");
			}
		} else {
			write.data += ret;
			write.len  -= ret;
			check(!chunk_set_write_ptr(c, write),
				"Failed to set new write ptr.");
			read = chunk_read_ptr(c);
		}

		while (read.len > 0) {
			fcgi_read_header(read.data, &h);
			pkg_size = sizeof(h) + h.body_len + h.body_pad;

			if (read.len < pkg_size) {
				inherit = read.len;
				ret     = inherit;
			} else {
				ret = fcgi_handle_pkg(fd, h, read);
				check(ret > 0, "Failed to handle pkg.");
			}

			read.data += ret;
			read.len  -= ret;
		}

		if (read.parent == c) {
			check(!chunk_set_read_ptr(c, read),
				"Failed to set new read ptr.");
		}
	} while (!done);

	PLUGIN_TRACE("[FCGI_FD %d] Response received successfully.", fd->fd);

	return 0;
error:
	return -1;
}

int _mkp_stage_30(struct plugin *plugin, struct client_session *cs,
		struct session_request *sr)
{
	char *url = NULL;
	struct request *req = NULL;
	int req_id;

	req = request_list_get_by_fd(&tdata.rl, cs->socket);
	if (req) {
#ifdef TRACE
		req_id = request_list_index_of(&tdata.rl, req);
		PLUGIN_TRACE("[FD %d] Ghost event on req_id %d.",
			cs->socket, req_id);
#endif
		return MK_PLUGIN_RET_CONTINUE;
	}

	url = mk_api->mem_alloc_z(sr->uri.len + 1);
	memcpy(url, sr->uri.data, sr->uri.len);
	if (regexec(&server.match_regex, url, 0, NULL, 0)) {
		mk_api->mem_free(url);
		return MK_PLUGIN_RET_NOT_ME;
	}
	mk_api->mem_free(url);

	PLUGIN_TRACE("[FD %d] URI match found.", cs->socket);
	req = request_list_next_available(&tdata.rl);

	check(req, "[FD %d] No available request structs.", cs->socket);

	req_id = request_list_index_of(&tdata.rl, req);

	check(!request_assign(req, cs->socket, cs, sr),
		"[REQ_ID %d] Failed to assign request for fd %d.",
		req_id, cs->socket);
	check(!fcgi_prepare_request(req),
		"[REQ_ID %d] Failed to prepare request.", req_id);

	PLUGIN_TRACE("[FD %d] Assigned to req_id %d.", cs->socket, req_id);
	PLUGIN_TRACE("[REQ_ID %d] Request ready to be sent.", req_id);

	if (fcgi_wake_connection()) {
		PLUGIN_TRACE("[REQ_ID %d] Create new fcgi connection.", req_id);
		check_debug(!fcgi_new_connection(plugin, cs, sr),
			"New connection failed seriously.");
	} else {
		PLUGIN_TRACE("[REQ_ID %d] Found connection available.", req_id);
	}
	return MK_PLUGIN_RET_CONTINUE;
error:
	PLUGIN_TRACE("[FD %d] Connection has failed.", cs->socket);
	mk_api->header_set_http_status(sr, MK_SERVER_INTERNAL_ERROR);
	sr->close_now = MK_TRUE;
	return MK_PLUGIN_RET_CLOSE_CONX;
}

void _mkp_core_thctx(void)
{
	PLUGIN_TRACE("Init thread context.");
	check(!request_list_init(&tdata.rl, 1, mk_api->config->worker_capacity),
		"Failed to init request list.");
	check(!fcgi_fd_list_init(&tdata.fdl, 1),
		"Failed to init fd list.");

	chunk_list_init(&tdata.cm);

	return;
error:
	log_err("Failed to initiate thread context.");
	abort();
}

static int hangup(int socket)
{
	struct fcgi_fd *fd;

	fd = fcgi_fd_list_get_by_fd(&tdata.fdl, socket);

	if (fd) {
		PLUGIN_TRACE("[FCGI_FD %d] Hangup event received.", fd->fd);

		fd->fd     = -1;
		fd->req_id = 0;
		fd->state  = FCGI_FD_AVAILABLE;

		return MK_PLUGIN_RET_EVENT_OWNED;
	} else {
		return MK_PLUGIN_RET_EVENT_CONTINUE;
	}
}

int _mkp_event_write(int socket)
{
	int req_id;
	struct request *req = NULL;
	struct fcgi_fd *fd;

	fd  = fcgi_fd_list_get_by_fd(&tdata.fdl, socket);
	req = fd ? NULL : request_list_get_by_fd(&tdata.rl, socket);

	if (!fd && !req) {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}
	else if (req && req->state == REQ_ENDED) {
		req_id = request_list_index_of(&tdata.rl, req);

		PLUGIN_TRACE("[REQ_ID %d] Request ended.", req_id);

		check(!fcgi_end_request(req),
			"[REQ_ID %d] Failed to end request.", req_id);
		check(!request_set_state(req, REQ_FINISHED),
			"[REQ_ID %d] Request state transition failed.", req_id);

		request_recycle(req);
		mk_api->http_request_end(socket);

		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else if (fd && fd->state == FCGI_FD_READY) {
		req = request_list_next_assigned(&tdata.rl);

		if (req) {
			req_id = request_list_index_of(&tdata.rl, req);
			request_set_fcgi_fd(req, fd->fd);
			fcgi_fd_set_req_id(fd, req_id);

			PLUGIN_TRACE("[FCGI_FD %d] Sending request with id %d.",
					fd->fd, req_id);

			check(!fcgi_send_request(req, fd),
				"[REQ_ID %d] Failed to send request.", req_id);
			check(!fcgi_fd_set_state(fd, FCGI_FD_RECEIVING),
				"[FD %d] Failed to set fd state.", fd->fd);
		}
		else {
			PLUGIN_TRACE("[FCGI_FD %d] Putting fcgi_fd to sleep.",
					fd->fd);

			mk_api->event_socket_change_mode(fd->fd,
				MK_EPOLL_SLEEP,
				MK_EPOLL_LEVEL_TRIGGERED);
			check(!fcgi_fd_set_state(fd, FCGI_FD_SLEEPING),
				"Failed to set fd state.");
		}
		return MK_PLUGIN_RET_EVENT_OWNED;
	}

	return MK_PLUGIN_RET_EVENT_CONTINUE;
error:
	if (req) {
		mk_api->header_set_http_status(req->sr,
			MK_SERVER_INTERNAL_ERROR);
		req->sr->close_now = MK_TRUE;
	}
	return MK_PLUGIN_RET_EVENT_CLOSE;
}

int _mkp_event_read(int socket)
{
	struct fcgi_fd *fd;

	fd = fcgi_fd_list_get_by_fd(&tdata.fdl, socket);
	if (!fd) {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}
	else if (fd->state == FCGI_FD_RECEIVING) {
		PLUGIN_TRACE("[FCGI_FD %d] Receiving data.", fd->fd);

		check(!fcgi_recv_response(fd),
			"[FCGI_FD %d] Failed to receive response.", fd->fd);
		check_debug(fd->state != FCGI_FD_CLOSING,
			"[FCGI_FD %d] Closing connection.", fd->fd);

		PLUGIN_TRACE("[FCGI_FD %d] Data received.", fd->fd);

		return MK_PLUGIN_RET_EVENT_OWNED;
	} else {
		return MK_PLUGIN_RET_EVENT_CONTINUE;
	}
error:
	return MK_PLUGIN_RET_EVENT_CLOSE;
}

int _mkp_event_close(int socket)
{
	return hangup(socket);
}

int _mkp_event_error(int socket)
{
	return hangup(socket);
}
