#ifndef __FCGI_REQUEST__
#define __FCGI_REQUEST__

#include "mk_iov.h"

#include "protocol.h"
#include "chunk.h"

#define MAX_PACKAGES 32

enum request_state {
	REQ_AVAILABLE,
	REQ_ASSIGNED,
	REQ_SENT,
	REQ_STREAM_CLOSED,
	REQ_ENDED,
	REQ_FINISHED,
};

enum request_flags {
	HEADERS_SENT = 1,
	CHUNKED_CONX = 2,
};

struct request {
	enum request_state state;
	uint32_t flags;
	int fd;
	struct client_session *ccs;
	struct session_request *sr;
	struct chunk **cs;
	struct mk_iov iov;
};

struct request_list {
	int n;
	struct request *rs;
};

void request_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *));

int request_init(struct request *preq, size_t iov_n);

int request_assign(struct request *req,
	int fd,
	struct client_session *cs,
	struct session_request *sr);

int request_make_available(struct request *req);

ssize_t request_add_pkg(struct request *req,
		struct fcgi_header h,
		struct chunk_ptr cp);

void request_release_chunks(struct request *req);

void request_free(struct request *req);


int request_list_init(struct request_list *rl, int n);

struct request *request_list_get_available(struct request_list *rl);

struct request *request_list_get_assigned(struct request_list *rl);

struct request *request_list_get_by_fd(struct request_list *rl, int fd);

struct request *request_list_get(struct request_list *rl, uint16_t req_id);

int request_list_index_of(struct request_list *rl, struct request *r);

void request_list_free(struct request_list *rl);

#endif // __FCGI_REQUEST__
