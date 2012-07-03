#ifndef __FCGI_REQUEST__
#define __FCGI_REQUEST__

#include "MKPlugin.h"
#include "protocol.h"
#include "chunk.h"

#define MAX_PACKAGES 32

enum request_flags {
	HEADERS_SENT  = 1,
	STDOUT_CLOSED = 2,
	STDERR_CLOSED = 4,
};

struct request {
	int fd;
	uint32_t flags;
	struct chunk **cs;
	struct mk_iov iov;
};

int request_init(struct request *req, size_t iov_size);

ssize_t request_add_pkg(struct request *req,
		struct fcgi_header h,
		struct chunk_ptr cp);

void request_release_chunks(struct request *req);

void request_reset(struct request *req);

void request_free(struct request *req);

#endif // __FCGI_REQUEST__
