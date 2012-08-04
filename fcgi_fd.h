#ifndef __FCGI_FD__
#define __FCGI_FD__

#include "chunk.h"
#include "fcgi_config.h"

enum fcgi_fd_type {
	FCGI_FD_UNIX,
	FCGI_FD_INET,
};

enum fcgi_fd_state {
	FCGI_FD_AVAILABLE = 1,
	FCGI_FD_READY     = 2,
	FCGI_FD_SENDING   = 4,
	FCGI_FD_RECEIVING = 8,
	FCGI_FD_CLOSING   = 16,
	FCGI_FD_SLEEPING  = 32,
};

struct fcgi_fd {
	enum fcgi_fd_type type;
	enum fcgi_fd_state state;
	int fd;
	int server_id;
	int location_id;

	size_t begin_req_remain;
	struct chunk_iov *begin_req;

	struct chunk *chunk;
};

struct fcgi_fd_list {
	int n;
	struct fcgi_fd *fds;
};

struct fcgi_fd_matrix {
	unsigned int server_count;
	unsigned int thread_count;
	unsigned int *thread_server_fd;
};

void fcgi_fd_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *));

void fcgi_fd_init(struct fcgi_fd *fd,
		enum fcgi_fd_type type,
		int server_id,
		int location_id);

int fcgi_fd_set_state(struct fcgi_fd *fd, enum fcgi_fd_state state);

int fcgi_fd_set_begin_req_iov(struct fcgi_fd *fd, struct chunk_iov *iov);

int fcgi_fd_set_chunk(struct fcgi_fd *fd, struct chunk *a, size_t inherit);

struct chunk *fcgi_fd_get_chunk(struct fcgi_fd *fd);

int fcgi_fd_list_init(struct fcgi_fd_list *fdl, struct fcgi_config *config);

void fcgi_fd_list_free(struct fcgi_fd_list *fdl);

struct fcgi_fd *fcgi_fd_list_get(struct fcgi_fd_list *fdl,
		enum fcgi_fd_state state,
		int location_id);

struct fcgi_fd *fcgi_fd_list_get_by_fd(struct fcgi_fd_list *fdl, int fd);


/**
 * fcgi_fd_matrix_create - Create new fd distribution matrix.
 */
struct fcgi_fd_matrix fcgi_fd_matrix_create(const struct fcgi_config *config,
		unsigned int worker_count);


void fcgi_fd_matrix_free(struct fcgi_fd_matrix *fdm);

/**
 * fcgi_fd_matrix_thread_sum - Sum of thread fds.
 */
unsigned int fcgi_fd_matrix_thread_sum(const struct fcgi_fd_matrix fdm,
		unsigned int thread_id);

/**
 * fcgi_fd_matrix_get - Return number of fds for that server on thread.
 */
unsigned int fcgi_fd_matrix_get(const struct fcgi_fd_matrix fdm,
		unsigned int thread_id,
		unsigned int server_id);

#endif // __FCGI_FD__
