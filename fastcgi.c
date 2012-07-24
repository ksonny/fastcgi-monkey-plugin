#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <regex.h>

#include "MKPlugin.h"

#include "dbg.h"
#include "fcgi_config.h"
#include "fcgi_context.h"
#include "fcgi_fd.h"
#include "protocol.h"
#include "chunk.h"
#include "request.h"

MONKEY_PLUGIN("fastcgi",		/* shortname */
              "FastCGI client",		/* name */
              VERSION,			/* version */
              MK_PLUGIN_STAGE_30 | MK_PLUGIN_CORE_THCTX);	/* hooks */

static struct fcgi_config fcgi_global_config;
static struct fcgi_context_list fcgi_global_context_list;

static __thread struct fcgi_context *fcgi_local_context;

#define __write_param(env, len, pos, key, value) do { \
		check(len - pos > 8 + key.len + value.len, "Out of memory."); \
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

int fcgi_server_connect(const struct fcgi_server *server)
{
	int sock_fd = -1;
	socklen_t addr_len;
	struct sockaddr_un addr;

	if (server->path) {
		sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		check(sock_fd != -1, "Failed to create unix socket.");

		addr.sun_family = AF_UNIX;
		check(sizeof(addr.sun_path) > strlen(server->path) + 1,
			"Socket path too long.");
		strcpy(addr.sun_path, server->path);

		addr_len = sizeof(addr.sun_family) + strlen(addr.sun_path);
		check(connect(sock_fd, (struct sockaddr *)&addr, addr_len) != -1,
			"Failed to connect unix socket.");
	}
	else if (server->addr) {
		sock_fd = mk_api->socket_connect(server->addr, server->port);
		check(sock_fd != -1, "Could not connect to fcgi server.");
	}

	return sock_fd;
error:
	return -1;
}

int fcgi_new_connection(struct plugin *plugin, int location_id)
{
	struct fcgi_fd_list *fdl = &fcgi_local_context->fdl;
	struct fcgi_fd *fd;
	struct fcgi_server *server;

	fd = fcgi_fd_list_get(fdl, FCGI_FD_AVAILABLE, location_id);
	if (!fd) {
		PLUGIN_TRACE("Connection limit reached.");
		return 0;
	}

	server = fcgi_config_get_server(&fcgi_global_config, fd->server_id);
	check(server, "Server for this fcgi_fd does not exist.");

	fd->fd = fcgi_server_connect(server);
	check(fd->fd != -1, "Failed to connect to server.");

	mk_api->socket_set_nonblocking(fd->fd);
	mk_api->event_add(fd->fd,
			MK_EPOLL_RW,
			plugin,
			MK_EPOLL_LEVEL_TRIGGERED);

	fcgi_fd_set_state(fd, FCGI_FD_READY);

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
	env = fcgi_create_env(req->cs, req->sr);

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

	chunk_iov_add_ptr(&req->iov, p1, len1, 1);
	chunk_iov_add_ptr(&req->iov, p2, len2, 0);
	chunk_iov_add_ptr(&req->iov, env.data, env.len, 1);
	chunk_iov_add_ptr(&req->iov, p3, len3, 0);

	return 0;
error:
	if (p1) mk_api->mem_free(p1);
	if (env.data) mk_api->mem_free(env.data);
	return -1;
}

int fcgi_send_request(struct request *req, struct fcgi_fd *fd)
{
	check(chunk_iov_sendv(fd->fd, &req->iov) > 0,
		"Socket error occured.");
	check(!request_set_state(req, REQ_SENT),
		"Failed to set req state.");

	chunk_iov_reset(&req->iov);
	return 0;
error:
	chunk_iov_reset(&req->iov);
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
	ssize_t ret;

	headers_offset = fcgi_parse_cgi_headers(req->iov.io[0].iov_base,
			req->iov.io[0].iov_len);

	mk_api->header_set_http_status(req->sr,  MK_HTTP_OK);
	req->sr->headers.cgi = SH_CGI;
	req->sr->headers.content_length =
		chunk_iov_length(&req->iov) - headers_offset;

	mk_api->header_send(req->fd, req->cs, req->sr);
	ret = chunk_iov_sendv(req->fd, &req->iov);
	check(ret, "Failed to send end_request.");
	mk_api->socket_cork_flag(req->fd, TCP_CORK_OFF);

	chunk_iov_reset(&req->iov);
	return 0;
error:
	return -1;
}

static int fcgi_handle_pkg(struct fcgi_fd *fd,
		struct request *req,
		struct fcgi_header h,
		struct chunk_ptr read)
{
	struct fcgi_end_req_body b;

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

		request_set_fcgi_fd(req, -1);

		check(!fcgi_fd_set_state(fd, FCGI_FD_READY),
			"Failed to set fd state.");

		if (req->state == REQ_STREAM_CLOSED) {
			check(!request_set_state(req, REQ_ENDED),
				"Failed to set request state.");
			mk_api->event_socket_change_mode(req->fd,
				MK_EPOLL_WRITE,
				MK_EPOLL_LEVEL_TRIGGERED);
		}
		else if (req->state == REQ_FAILED && req->fd == -1) {
			request_recycle(req);
		}

		break;
	case 0:
		sentinel("[REQ %d] Received NULL package.", h.req_id);
		break;
	default:
		log_info("[REQ %d] Ignore package: %s",
			h.req_id,
			FCGI_MSG_TYPE_STR(h.type));
	}

	return 0;
error:
	return -1;
}

int fcgi_recv_response(struct fcgi_fd *fd,
		struct chunk_list *cl,
		struct request_list *rl,
		int (*handle_pkg)(struct fcgi_fd *fd,
			struct request *req,
			struct fcgi_header h,
			struct chunk_ptr read))
{
	size_t pkg_size, inherit = 0;
	ssize_t ret = 0;
	int done = 0;

	struct fcgi_header h;
	struct request *req;
	struct chunk *c;
	struct chunk_ptr write = {0}, read = {0};

	PLUGIN_TRACE("[FCGI_FD %d] Receiving response.", fd->fd);

	c = chunk_list_current(cl);
	if (c != NULL) {
		write = chunk_write_ptr(c);
		read  = chunk_read_ptr(c);
	}

	do {
		if (inherit > 0 || write.len < sizeof(h)) {
			PLUGIN_TRACE("New chunk, inherit %ld.", inherit);
			c = chunk_new(65536);
			check_mem(c);
			check(!chunk_list_add(cl, c, inherit),
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
				req = request_list_get(rl, h.req_id);
				check(!handle_pkg(fd, req, h, read),
					"Failed to handle pkg.");
				ret = pkg_size;
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
		check_debug(!fcgi_new_connection(plugin, location_id),
			"New connection failed seriously.");
	} else {
		PLUGIN_TRACE("[REQ_ID %d] Found connection available.", req_id);
	}

	mk_api->event_socket_change_mode(cs->socket,
			MK_EPOLL_SLEEP,
			MK_EPOLL_LEVEL_TRIGGERED);


	return MK_PLUGIN_RET_CONTINUE;
error:
	PLUGIN_TRACE("[FD %d] Connection has failed.", cs->socket);
	mk_api->header_set_http_status(sr, MK_SERVER_INTERNAL_ERROR);
	sr->close_now = MK_TRUE;
	if (req) {
		PLUGIN_TRACE("[REQ_ID %d] Request failed in stage_30.", req_id);
		request_set_state(req, REQ_FAILED);
	}
	return MK_PLUGIN_RET_CLOSE_CONX;
}

int _mkp_init(struct plugin_api **api, char *confdir)
{
	mk_api = *api;

	chunk_module_init(mk_api->mem_alloc, mk_api->mem_free);
	request_module_init(mk_api->mem_alloc, mk_api->mem_free);
	fcgi_fd_module_init(mk_api->mem_alloc, mk_api->mem_free);
	fcgi_context_module_init(mk_api->mem_alloc, mk_api->mem_free);

	check(!fcgi_validate_struct_sizes(),
		"Validating struct sizes failed.");
	check(!fcgi_config_read(&fcgi_global_config, confdir),
		"Failed to read config.");

	return 0;
error:
	return -1;
}

void _mkp_exit()
{
	PLUGIN_TRACE("Free thread context list.");
	fcgi_context_list_free(&fcgi_global_context_list);

	PLUGIN_TRACE("Free configuration.");
	fcgi_config_free(&fcgi_global_config);
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
	struct request *req;
	int req_id;

	fd  = fcgi_fd_list_get_by_fd(&tdata.fdl, socket);
	req = fd ? NULL : request_list_get_by_fd(&tdata.rl, socket);

	if (!fd && !req) {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}
	else if (fd) {
		PLUGIN_TRACE("[FCGI_FD %d] Hangup event received.", fd->fd);

		fd->fd     = -1;
		fd->state  = FCGI_FD_AVAILABLE;
		return MK_PLUGIN_RET_EVENT_CONTINUE;
	}
	else if (req) {
		req_id = request_list_index_of(&tdata.rl, req);

		if (req->fcgi_fd == -1) {
			PLUGIN_TRACE("[REQ_ID %d] Hangup event.", req_id);
			request_recycle(req);
		}
		else {
			log_warn("[REQ_ID %d] Hangup event, request still running.",
				req_id);
			if (req->state != REQ_FAILED) {
				request_set_state(req, REQ_FAILED);
			}
			req->fd = -1;
			req->cs = NULL;
			req->sr = NULL;
		}
		return MK_PLUGIN_RET_EVENT_CONTINUE;
	}
	else {
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
	else if (fd && fd->state == FCGI_FD_RECEIVING) {

		req = request_list_get_by_fcgi_fd(&tdata.rl, fd->fd);

		if (req && req->state == REQ_FAILED) {
			log_info("[FD %d] We have failed request!", req->fd);

			chunk_iov_reset(&req->iov);

			check(!fcgi_send_abort_request(req, fd),
				"[FD %d] Failed to send abort request.", fd->fd);
		}
		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else {
		return MK_PLUGIN_RET_EVENT_CONTINUE;
	}
error:
	if (req) {
		request_set_state(req, REQ_FAILED);
	}
	return MK_PLUGIN_RET_EVENT_CLOSE;
}

int _mkp_event_read(int socket)
{
	struct chunk_list *cl = &tdata.cm;
	struct request_list *rl = &tdata.rl;
	struct fcgi_fd_list *fdl = &tdata.fdl;
	struct fcgi_fd *fd;

	fd = fcgi_fd_list_get_by_fd(fdl, socket);
	if (!fd) {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}
	else if (fd->state == FCGI_FD_RECEIVING) {
		PLUGIN_TRACE("[FCGI_FD %d] Receiving data.", fd->fd);

		check(!fcgi_recv_response(fd, cl, rl, fcgi_handle_pkg),
			"[FCGI_FD %d] Failed to receive response.", fd->fd);
		check_debug(fd->state != FCGI_FD_CLOSING,
			"[FCGI_FD %d] Closing connection.", fd->fd);

		PLUGIN_TRACE("[FCGI_FD %d] Data received.", fd->fd);

		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else {
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
