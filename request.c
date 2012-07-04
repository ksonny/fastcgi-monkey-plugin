#include "request.h"

#include "dbg.h"
#include "protocol.h"

int request_init(struct request *preq, size_t iov_n)
{
	struct request req = {
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

int request_validate(struct request *req)
{
	if (req->flags & REQUEST_ENDED) {
		check(req->flags & STDOUT_CLOSED, "Stream stdout not closed.");
		check(req->flags & STDERR_CLOSED, "Stream stderr not closed.");
	}
	return 0;
error:
	return -1;
}

ssize_t request_add_pkg(struct request *req,
		struct fcgi_header h,
		struct chunk_ptr cp)
{
	size_t pkg_length;

	pkg_length = sizeof(h) + h.body_len + h.body_pad;
	check(cp.len >= pkg_length, "Missing package data.");

	chunk_retain(cp.parent);
	req->cs[req->iov.iov_idx] = cp.parent;

	mk_api->iov_add_entry(&req->iov,
			(char *)cp.data + sizeof(h),
			h.body_len,
			mk_iov_none,
			0);

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

