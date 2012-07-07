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
	struct chunk **cs = NULL;
	struct iovec *io  = NULL;

	io = mk_api->mem_alloc(iov_n * sizeof(*io));
	check_mem(io);

	cs = mk_api->mem_alloc(iov_n * sizeof(*cs));
	check_mem(cs);

	req.cs     = cs;
	req.iov.io = io;

	memcpy(preq, &req, sizeof(req));
	return 0;
error:
	if (io) mk_api->mem_free(io);
	if (cs) mk_api->mem_free(cs);
	return -1;
}

int request_assign(struct request *req, int fd)
{
	check(req->state == AVAILABLE,
		"Request state is not AVAILABLE.");

	req->state = ASSIGNED;
	req->fd    = fd;
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
	struct chunk *c;
	ssize_t i;

	for (i = 0; i < req->iov.iov_idx; i++) {
		c = req->cs[i];
		chunk_release(c);
	}
}

void request_reset(struct request *req)
{
	req->fd = -1;
	req->iov.iov_idx     = 0;
	req->iov.buf_idx     = 0;
	req->iov.total_len   = 0;
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

