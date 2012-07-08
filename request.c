#include "request.h"

#include "dbg.h"
#include "protocol.h"

int request_init(struct request *preq, size_t iov_n)
{
	struct request req = {
		.state = AVAILABLE,
		.fd    = -1,
		.flags = 0,
		.cs    = NULL,
		.iov   = {
			.buf_to_free = NULL,
			.iov_idx     = 0,
			.buf_idx     = 0,
			.size        = iov_n,
			.total_len   = 0,
			.io          = NULL,
		},
	};
	struct chunk **cs  = NULL;
	struct iovec *io   = NULL;
	char **buf_to_free = NULL;
  
	io = mk_api->mem_alloc(iov_n * sizeof(*io));
	check_mem(io);

	cs = mk_api->mem_alloc(iov_n * sizeof(*cs));
	check_mem(cs);

	buf_to_free = mk_api->mem_alloc(iov_n * sizeof(*buf_to_free));
	check_mem(buf_to_free);

	req.cs              = cs;
	req.iov.io          = io;
	req.iov.buf_to_free = buf_to_free;

	memcpy(preq, &req, sizeof(req));
	return 0;
error:
	if (io) mk_api->mem_free(io);
	if (cs) mk_api->mem_free(cs);
	return -1;
}

static void request_reset(struct request *req)
{
	req->state         = AVAILABLE;
	req->flags         = 0;
	req->fd            = -1;
	req->iov.iov_idx   = 0;
	req->iov.buf_idx   = 0;
	req->iov.total_len = 0;
}

int request_assign(struct request *req,
	struct client_session *cs,
	struct session_request *sr)
{
	check(req->state == AVAILABLE,
		"Request state is not AVAILABLE.");

	req->state = ASSIGNED;
	req->fd    = cs->socket;
	req->ccs   = cs;
	req->sr    = sr;
	return 0;
error:
	return -1;
}

int request_make_available(struct request *req)
{
	check(req->state == REQUEST_ENDED,
		"Request state is not REQUEST_ENDED");

	request_reset(req);
	return 0;
error:
	return -1;
}

ssize_t request_add_pkg(struct request *req,
		struct fcgi_header h,
		struct chunk_ptr cp)
{
	size_t pkg_length;
	struct fcgi_end_req_body b;

	pkg_length = sizeof(h) + h.body_len + h.body_pad;
	check(cp.len >= pkg_length, "Missing package data.");

	switch (h.type) {
	case FCGI_STDERR:
		if (h.body_len == 0) {
		} else {
		}
		break;

	case FCGI_STDOUT:
		check(req->state == REQUEST_SENT, "Request not yet sent.");
		if (h.body_len == 0) {
			req->state = STREAM_CLOSED;
			break;
		}

		chunk_retain(cp.parent);
		req->cs[req->iov.iov_idx] = cp.parent;

		mk_api->iov_add_entry(&req->iov,
				(char *)cp.data + sizeof(h),
				h.body_len,
				mk_iov_none,
				0);
		break;

	case FCGI_END_REQUEST:
		check(req->state == STREAM_CLOSED, "Stream not yet closed.");
		fcgi_read_end_req_body(cp.data + sizeof(h), &b);

		switch (b.app_status) {
		case EXIT_SUCCESS:
			break;
		case EXIT_FAILURE:
			break;
		default:
			break;
		}

		switch (b.protocol_status) {
		case FCGI_REQUEST_COMPLETE:
			break;
		case FCGI_CANT_MPX_CONN:
			break;
		case FCGI_OVERLOADED:
			break;
		case FCGI_UNKNOWN_ROLE:
			break;
		default:
			break;
		}

		req->state = REQUEST_ENDED;
		break;

	case 0:
		sentinel("Received NULL package.");
		break;
	default:
		log_info("Ignore package: %s",
			FCGI_MSG_TYPE_STR(h.type));
	}

	return pkg_length;
error:
	return -1;
	
}

void request_release_chunks(struct request *req)
{
	int i;

	for (i = 0; i < req->iov.iov_idx; i++) {
		if (req->cs[i]) {
			chunk_release(req->cs[i]);
			req->cs[i] = NULL;
		}
	}
	for (i = 0; i < req->iov.buf_idx; i++) {
		if (req->iov.buf_to_free[i]) {
			mk_api->mem_free(req->iov.buf_to_free[i]);
			req->iov.buf_to_free[i] = NULL;
		}
	}
	req->iov.iov_idx   = 0;
	req->iov.buf_idx   = 0;
	req->iov.total_len = 0;
}

void request_free(struct request *req)
{
	request_reset(req);
	if (req->cs) {
		mk_api->mem_free(req->cs);
		req->cs = NULL;
	}
	if (req->iov.io) {
		mk_api->mem_free(req->iov.io);
		req->iov.io = NULL;
	}
}

int request_list_init(struct request_list *rl, int n)
{
	struct request *tmp = NULL;
	int i;

	tmp = mk_api->mem_alloc(n * sizeof(*tmp));
	check_mem(tmp);

	for (i = 0; i < n; i++) {
		check(!request_init(tmp + i, 4),
			"Failed to init request %d", i);
	}

	rl->n  = n;
	rl->rs = tmp;

	return 0;
error:
	if (tmp && i > 0) {
		n = i;
		for (i = 0; i < n; i++) {
			request_free(tmp + i);
		}
	}
	if (tmp) mk_api->mem_free(tmp);
	return -1;
}

static struct request *request_list_get_by_state(struct request_list *rl,
		enum request_state state)
{
	int i;
	struct request *r = NULL;

	for (i = 0; i < rl->n; i++) {
		r = rl->rs + i;
		if (r->state == state)
			return r;
	}
	return NULL;
}

struct request *request_list_get_available(struct request_list *rl)
{
	return request_list_get_by_state(rl, AVAILABLE);
}

struct request *request_list_get_assigned(struct request_list *rl)
{
	return request_list_get_by_state(rl, ASSIGNED);
}

struct request *request_list_get(struct request_list *rl, uint16_t req_id)
{
	check(req_id < rl->n, "Request id out of range.");

	return rl->rs + req_id;
error:
	return NULL;
}

int request_list_index_of(struct request_list *rl, struct request *r)
{
	ptrdiff_t offset = r - rl->rs;

	check(r >= rl->rs && r <= rl->rs + rl->n, "Request not part of list.");

	return offset;
error:
	return -1;

}

void request_list_free(struct request_list *rl)
{
	int i;

	for (i = 0; i < rl->n; i++) {
		request_free(rl->rs + i);
	}
	mk_api->mem_free(rl->rs);
	rl->n  = 0;
	rl->rs = NULL;
}
