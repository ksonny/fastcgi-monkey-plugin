#include <stdlib.h>

#include "dbg.h"
#include "fcgi_fd.h"

static void *(*mem_alloc)(const size_t) = &malloc;
static void (*mem_free)(void *) = free;

void fcgi_fd_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *))
{
	mem_alloc = mem_alloc_p;
	mem_free  = mem_free_p;
}

int fcgi_fd_set_state(struct fcgi_fd *fd, enum fcgi_fd_state state)
{
	switch (state) {
	case FCGI_FD_AVAILABLE:
		check(fd->state & (FCGI_FD_CLOSING | FCGI_FD_SLEEPING),
			"Bad state transition.");
		break;
	case FCGI_FD_READY:
		check(fd->state & (FCGI_FD_AVAILABLE
				| FCGI_FD_RECEIVING
				| FCGI_FD_SLEEPING),
			"Bad state transition.");
		fd->state = FCGI_FD_READY;
		break;
	case FCGI_FD_RECEIVING:
		check(fd->state & (FCGI_FD_READY),
			"Bad state transition.");
		fd->state = FCGI_FD_RECEIVING;
		break;
	case FCGI_FD_CLOSING:
		check(fd->state & (FCGI_FD_RECEIVING),
			"Bad state transition.");
		fd->state = FCGI_FD_CLOSING;
		break;
	case FCGI_FD_SLEEPING:
		check(fd->state & (FCGI_FD_READY),
			"Bad state transition.");
		fd->state = FCGI_FD_SLEEPING;
		break;
	}
	return 0;
error:
	return -1;
}

void fcgi_fd_set_req_id(struct fcgi_fd *fd, int req_id)
{
	fd->req_id = req_id;
}

int fcgi_fd_list_init(struct fcgi_fd_list *fdl, int n)
{
	struct fcgi_fd *tmp = NULL;
	int i;

	tmp = mem_alloc(n * sizeof(*tmp));
	check_mem(tmp);

	for (i = 0; i < n; i++) {
		tmp[i].state = FCGI_FD_AVAILABLE;
		tmp[i].req_id = -1;
		tmp[i].fd = -1;
	}

	fdl->n   = n;
	fdl->fds = tmp;

	return 0;
error:
	if (tmp) mem_free(tmp);
	return -1;
}

void fcgi_fd_list_free(struct fcgi_fd_list *fdl)
{
	mem_free(fdl->fds);
}

struct fcgi_fd *fcgi_fd_list_get_by_state(struct fcgi_fd_list *fdl,
		enum fcgi_fd_state state)
{
	int i;

	for (i = 0; i < fdl->n; i++) {
		if (fdl->fds[i].state & state) {
			return fdl->fds + i;
		}
	}
	return NULL;
}

struct fcgi_fd *fcgi_fd_list_get_by_fd(struct fcgi_fd_list *fdl, int fd)
{
	int i;

	for (i = 0; i < fdl->n; i++) {
		if (fdl->fds[i].fd == fd) {
			return fdl->fds + i;
		}
	}
	return NULL;
}
