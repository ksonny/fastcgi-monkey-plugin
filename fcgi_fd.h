#ifndef __FCGI_FD__
#define __FCGI_FD__

enum fcgi_fd_state {
	FCGI_FD_AVAILABLE,
	FCGI_FD_READY,
	FCGI_FD_RECEIVING,
	FCGI_FD_CLOSING,
	FCGI_FD_SLEEPING,
};

struct fcgi_fd {
	enum fcgi_fd_state state;
	int fd;
};

struct fcgi_fd_list {
	int n;
	struct fcgi_fd *fds;
};

void fcgi_fd_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *));

int fcgi_fd_list_init(struct fcgi_fd_list *fdl, int n);

void fcgi_fd_list_free(struct fcgi_fd_list *fdl);

struct fcgi_fd *fcgi_fd_list_get_by_state(struct fcgi_fd_list *fdl,
		enum fcgi_fd_state state);

struct fcgi_fd *fcgi_fd_list_get_by_fd(struct fcgi_fd_list *fdl, int fd);

#endif // __FCGI_FD__
