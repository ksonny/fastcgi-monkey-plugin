#ifndef __FCGI_REQUEST__
#define __FCGI_REQUEST__

#include "protocol.h"
#include "chunk.h"

#define MAX_PACKAGES 32

enum request_state {
	REQ_AVAILABLE     = 1,
	REQ_ASSIGNED      = 2,
	REQ_SENT          = 4,
	REQ_STREAM_CLOSED = 8,
	REQ_ENDED         = 16,
	REQ_FINISHED      = 32,
	REQ_FAILED        = 64,
};

enum request_flags {
	HEADERS_SENT = 1,
	CHUNKED_CONX = 2,
};

struct request {
	enum request_state state;
	enum request_flags flags;

	int fd;
	int fcgi_fd;

	int clock_id;

	struct client_session *cs;
	struct session_request *sr;

	struct chunk_iov iov;
};

/** struct request_list - tracks list of requests
 * @n: Number of entries in list.
 * @id_offset: Substracted from req_id to get index in list.
 * @clock_hand: Used with _next_ function to implement round robin.
 */
struct request_list {
	int n;
	int id_offset;
	int clock_count;
	int *clock_hands;
	struct request *rs;
};

void request_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *));

int request_init(struct request *preq, size_t iov_n);

int request_set_state(struct request *req, enum request_state state);

int request_assign(struct request *req,
	int fd,
	int location_id,
	struct client_session *cs,
	struct session_request *sr);

void request_set_fcgi_fd(struct request *req, int fcgi_fd);

int request_recycle(struct request *req);

ssize_t request_add_pkg(struct request *req,
		struct fcgi_header h,
		struct chunk_ptr cp);

void request_free(struct request *req);


int request_list_init(struct request_list *rl,
		int clock_count,
		int id_offset,
		int n);

/*
 * Gets next available request, starting from rl->clock_hand.
 *
 * Returns NULL on failure, otherwise pointer to struct request.
 */
struct request *request_list_next_available(struct request_list *rl, int clock_id);

/*
 * Gets next assigned request, starting from .clock_hand. The clock_hand
 * will then be set to index of found request.
 *
 * Returns NULL on failure, otherwise pointer to struct request.
 */
struct request *request_list_next_assigned(struct request_list *rl, int clock_id);

struct request *request_list_get_by_fd(struct request_list *rl, int fd);

struct request *request_list_get_by_fcgi_fd(struct request_list *rl, int fd);

struct request *request_list_get(struct request_list *rl, uint16_t req_id);

int request_list_index_of(struct request_list *rl, struct request *r);

void request_list_free(struct request_list *rl);

#endif // __FCGI_REQUEST__
