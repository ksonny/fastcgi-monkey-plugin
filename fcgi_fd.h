#ifndef __FCGI_FD__
#define __FCGI_FD__

enum fcgi_fd_state {
	FCGI_FD_AVAILABLE = 1,
	FCGI_FD_READY     = 2,
	FCGI_FD_RECEIVING = 4,
	FCGI_FD_CLOSING   = 8,
	FCGI_FD_SLEEPING  = 16,
};

struct fcgi_fd {
	enum fcgi_fd_state state;

	int req_id;
	int fd;
};

struct fcgi_fd_list {
	int n;
	struct fcgi_fd *fds;
};

void fcgi_fd_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *));

int fcgi_fd_set_state(struct fcgi_fd *fd, enum fcgi_fd_state state);

void fcgi_fd_set_req_id(struct fcgi_fd *fd, int req_id);

int fcgi_fd_list_init(struct fcgi_fd_list *fdl, int n);

void fcgi_fd_list_free(struct fcgi_fd_list *fdl);

struct fcgi_fd *fcgi_fd_list_get_by_state(struct fcgi_fd_list *fdl,
		enum fcgi_fd_state state);

struct fcgi_fd *fcgi_fd_list_get_by_fd(struct fcgi_fd_list *fdl, int fd);

#endif // __FCGI_FD__
