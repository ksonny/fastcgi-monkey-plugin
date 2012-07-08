#include <stdlib.h>

#include "MKPlugin.h"
#include "dbg.h"
#include "handle.h"

int handle_list_init(struct handle_list *fdl, int n)
{
	struct handle *tmp = NULL;
	int i;

	tmp = mk_api->mem_alloc(n * sizeof(*tmp));
	check_mem(tmp);

	for (i = 0; i < n; i++) {
		tmp[i].fd = -1;
		tmp[i].state = HANDLE_AVAILABLE;
	}

	fdl->n   = n;
	fdl->fds = tmp;

	return 0;
error:
	if (tmp) mk_api->mem_free(tmp);
	return -1;
}

void handle_list_free(struct handle_list *fdl)
{
	mk_api->mem_free(fdl->fds);
}

struct handle *handle_list_get_by_state(struct handle_list *fdl,
		enum handle_state state)
{
	int i;

	for (i = 0; i < fdl->n; i++) {
		if (fdl->fds[i].state == state) {
			return fdl->fds + i;
		}
	}
	return NULL;
}

struct handle *handle_list_get_by_fd(struct handle_list *fdl, int fd)
{
	int i;

	for (i = 0; i < fdl->n; i++) {
		if (fdl->fds[i].fd == fd) {
			return fdl->fds + i;
		}
	}
	return NULL;
}
