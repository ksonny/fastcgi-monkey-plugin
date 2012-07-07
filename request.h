#ifndef __FCGI_REQUEST__
#define __FCGI_REQUEST__

#include "MKPlugin.h"
#include "protocol.h"
#include "chunk.h"

#define MAX_PACKAGES 32

enum request_state {
	AVAILABLE,
	ASSIGNED,
	REQUEST_SENT,
	STREAM_CLOSED,
	REQUEST_ENDED,
};

enum request_flags {
	HEADERS_SENT = 1,
	CHUNKED_CONX = 2,
};

struct request {
	enum request_state state;
	uint32_t flags;
	int fd;
	struct chunk **cs;
	struct mk_iov iov;
};

int request_init(struct request *req, size_t iov_size);

int request_assign(struct request *req, int fd);

int request_validate(const struct request *req);

ssize_t request_add_pkg(struct request *req,
		struct fcgi_header h,
		struct chunk_ptr cp);

void request_release_chunks(struct request *req);

void request_reset(struct request *req);

void request_free(struct request *req);

#endif // __FCGI_REQUEST__
