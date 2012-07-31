#ifndef __FCGI_FD__
#define __FCGI_FD__

#include "chunk.h"
#include "fcgi_config.h"

enum fcgi_fd_state {
	FCGI_FD_AVAILABLE = 1,
	FCGI_FD_READY     = 2,
	FCGI_FD_RECEIVING = 4,
	FCGI_FD_CLOSING   = 8,
	FCGI_FD_SLEEPING  = 16,
};

struct fcgi_fd {
	enum fcgi_fd_state state;
	int fd;
	int server_id;
	int location_id;
	struct chunk *chunk;
};

struct fcgi_fd_list {
	int n;
	struct fcgi_fd *fds;
};

void fcgi_fd_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *));

void fcgi_fd_init(struct fcgi_fd *fd, int server_id, int location_id);

int fcgi_fd_set_state(struct fcgi_fd *fd, enum fcgi_fd_state state);

int fcgi_fd_set_chunk(struct fcgi_fd *fd, struct chunk *a, size_t inherit);

struct chunk *fcgi_fd_get_chunk(struct fcgi_fd *fd);

int fcgi_fd_list_init(struct fcgi_fd_list *fdl, struct fcgi_config *config);

void fcgi_fd_list_free(struct fcgi_fd_list *fdl);

struct fcgi_fd *fcgi_fd_list_get(struct fcgi_fd_list *fdl,
		enum fcgi_fd_state state,
		int location_id);

struct fcgi_fd *fcgi_fd_list_get_by_fd(struct fcgi_fd_list *fdl, int fd);

#endif // __FCGI_FD__
