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

int fcgi_fd_list_init(struct fcgi_fd_list *fdl, int n)
{
	struct fcgi_fd *tmp = NULL;
	int i;

	tmp = mem_alloc(n * sizeof(*tmp));
	check_mem(tmp);

	for (i = 0; i < n; i++) {
		tmp[i].fd = -1;
		tmp[i].state = FCGI_FD_AVAILABLE;
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
		if (fdl->fds[i].state == state) {
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
