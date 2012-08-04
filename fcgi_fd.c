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

void fcgi_fd_init(struct fcgi_fd *fd,
		enum fcgi_fd_type type,
		int server_id,
		int location_id)
{
	fd->type = type;
	fd->state = FCGI_FD_AVAILABLE;
	fd->fd = -1;
	fd->server_id = server_id;
	fd->location_id = location_id;

	fd->begin_req_remain = 0;
	fd->begin_req = NULL;

	fd->chunk = NULL;
}

int fcgi_fd_set_state(struct fcgi_fd *fd, enum fcgi_fd_state state)
{
	switch (state) {
	case FCGI_FD_AVAILABLE:
		check(fd->state & (FCGI_FD_CLOSING | FCGI_FD_SLEEPING),
			"Bad state transition. (C|S) -> A");
		fd->state = FCGI_FD_AVAILABLE;
		break;
	case FCGI_FD_READY:
		check(fd->state & (FCGI_FD_AVAILABLE
				| FCGI_FD_RECEIVING
				| FCGI_FD_SLEEPING),
			"Bad state transition. (A|Re|S) -> R");
		fd->state &= ~(FCGI_FD_AVAILABLE
				| FCGI_FD_RECEIVING
				| FCGI_FD_SLEEPING);
		fd->state |= FCGI_FD_READY;
		break;
	case FCGI_FD_SENDING:
		check(fd->state & (FCGI_FD_READY),
			"Bad state transition. Re -> Se");
		fd->state &= ~FCGI_FD_READY;
		fd->state |= FCGI_FD_SENDING;
		break;
	case FCGI_FD_RECEIVING:
		check(fd->state & (FCGI_FD_SENDING),
			"Bad state transition. Se -> R, %d", fd->state);
		fd->state &= ~FCGI_FD_SENDING;
		fd->state |= FCGI_FD_RECEIVING;
		break;
	case FCGI_FD_CLOSING:
		check(fd->state & (FCGI_FD_READY | FCGI_FD_RECEIVING),
			"Bad state transition. R -> C");
		fd->state &= ~(FCGI_FD_READY | FCGI_FD_RECEIVING);
		fd->state |= FCGI_FD_CLOSING;
		break;
	case FCGI_FD_SLEEPING:
		check(fd->state & (FCGI_FD_READY),
			"Bad state transition. R -> Sl");
		fd->state &= ~FCGI_FD_READY;
		fd->state |= FCGI_FD_SLEEPING;
		break;
	}
	return 0;
error:
	return -1;
}

int fcgi_fd_set_begin_req_iov(struct fcgi_fd *fd, struct chunk_iov *iov)
{
	check(fd->state == FCGI_FD_READY,
		"[FCGI_FD %d] Please set begin_req_iov when ready.", fd->fd);

	fd->begin_req_remain = chunk_iov_length(iov);
	fd->begin_req = iov;

	return 0;
error:
	return -1;
}

/*
 * Copy inherit bytes from old chunk to new chunk and set as current
 * chunk.
 */
int fcgi_fd_set_chunk(struct fcgi_fd *fd, struct chunk *a, size_t inherit)
{
	struct chunk *b = fd->chunk;
	size_t b_pos, a_pos;
	struct chunk_ptr tmp;

	chunk_retain(a);

	if (b && inherit > 0) {
		check(b->write >= inherit,
			"Not enough used on old chunk to inherit.");
		check(a->size - a->write > inherit,
			"Not enough free space on new chunk to inherit.");

		a_pos = a->write;
		b_pos = b->write - inherit;

		memcpy(a->data + a_pos, b->data + b_pos, inherit);

		a_pos     += inherit;
		tmp.parent = a;
		tmp.len    = a->size - a_pos;
		tmp.data   = a->data + a_pos;

		check(!chunk_set_write_ptr(a, tmp),
			"Failed to set new write pointer.");
		chunk_release(b);
	} else if (b) {
		chunk_release(b);
	} else {
		check(inherit == 0, "There are no chunks to inherit from.");
	}

	fd->chunk = a;
	return 0;
error:
	if (mk_list_is_empty(&a->_head)) {
		mk_list_del(&a->_head);
	}
	return -1;
}

struct chunk *fcgi_fd_get_chunk(struct fcgi_fd *fd)
{
	return fd->chunk;
}

int fcgi_fd_list_init(struct fcgi_fd_list *fdl, struct fcgi_config *config)
{
	int i, j;
	int fd_count = 0;
	int server_location_id[config->server_count];
	ptrdiff_t srv_i;
	struct fcgi_location *locp;
	struct fcgi_server *srvp;
	struct fcgi_fd *tmp = NULL;
	enum fcgi_fd_type type;

	for (i = 0; i < config->server_count; i++) {
		server_location_id[i] = -1;
	}

	for (i = 0; i < config->location_count; i++) {
		locp = config->locations + i;

		for (j = 0; j < locp->server_count; j++) {
			srv_i = locp->server_ids[j];
			check(srv_i >= 0 && srv_i < config->server_count,
				"Location server's index out of range.");
			check(server_location_id[srv_i] == -1,
				"Location re-uses server.");
			server_location_id[srv_i] = i;
			fd_count += 1;
		}
	}

	check(fd_count > 0, "No locations configured.");

	tmp = mem_alloc(fd_count * sizeof(*tmp));
	check_mem(tmp);

	for (i = 0; i < fd_count; i++) {
		srvp = fcgi_config_get_server(config, i);
		if (srvp->path) {
			type = FCGI_FD_UNIX;
		} else {
			type = FCGI_FD_INET;
		}

		fcgi_fd_init(tmp + i, type, i, server_location_id[i]);
	}

	fdl->n   = fd_count;
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

struct fcgi_fd *fcgi_fd_list_get(struct fcgi_fd_list *fdl,
		enum fcgi_fd_state state,
		int location_id)
{
	struct fcgi_fd *fd;
	int i;

	for (i = 0; i < fdl->n; i++) {
		fd = fdl->fds + i;
		if (fd->state & state && fd->location_id == location_id) {
			return fd;
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
