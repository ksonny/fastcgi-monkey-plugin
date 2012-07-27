#include <stdlib.h>
#include <sys/uio.h>

#include "dbg.h"
#include "chunk.h"

static void *(*mem_alloc)(const size_t) = &malloc;
static void (*mem_free)(void *) = &free;

void chunk_module_init(void *(*mem_alloc_f)(const size_t),
		void (*mem_free_f)(void *))
{
	mem_alloc = mem_alloc_f;
	mem_free  = mem_free_f;
}

struct chunk *chunk_new(size_t size)
{
	struct chunk *tmp = NULL;

	tmp = mem_alloc(size);
	check_mem(tmp);

	mk_list_init(&tmp->_head);
	tmp->read  = 0;
	tmp->write = 0;
	tmp->refs  = 0;
	tmp->size  = CHUNK_SIZE(size);

	return tmp;
error:
	if (tmp) {
		mem_free(tmp);
	}
	return NULL;
}

struct chunk_ptr chunk_read_ptr(struct chunk *c)
{
	return (struct chunk_ptr){
		.parent = c,
		.len    = c->write - c->read,
		.data   = c->data + c->read,
	};
}

struct chunk_ptr chunk_write_ptr(struct chunk *c)
{
	return (struct chunk_ptr){
		.parent = c,
		.len    = c->size - c->write,
		.data   = c->data + c->write,
	};
}

int chunk_set_read_ptr(struct chunk *c, struct chunk_ptr read)
{
	check(read.parent == c,
		"Pointer not from this chunk.");
	check(read.data >= c->data && read.data <= c->data + c->size,
		"Pointer out of range for this chunk.");

	c->read = read.data - c->data;
	return 0;
error:
	return -1;
}

int chunk_set_write_ptr(struct chunk *c, struct chunk_ptr write)
{
	check(write.parent == c,
		"Pointer not from this chunk.");
	check(write.data >= c->data && write.data <= c->data + c->size,
		"Pointer out of range for this chunk.");

	c->write = write.data - c->data;
	return 0;
error:
	return -1;
}

void chunk_free(struct chunk *c)
{
	mk_list_del(&c->_head);
	mem_free(c);
}

void chunk_retain(struct chunk *c)
{
	c->refs += 1;
}

int chunk_release(struct chunk *c)
{
	c->refs -= 1;

	check_debug(c->refs > 0, "Free chunk.");

	return 0;
error:
	chunk_free(c);
	return 1;
}

void chunk_list_init(struct chunk_list *cm)
{
	mk_list_init(&cm->chunks._head);
}

struct chunk *chunk_list_current(struct chunk_list *cm)
{
	check_debug(mk_list_is_empty(&cm->chunks._head), "No managed chunks.");

	return mk_list_entry_last((&cm->chunks._head), struct chunk, _head);
error:
	return NULL;
}

/*
 * Adds chunk c to chunk manager and mark as current chunk.
 * If inherit > 0 then copy the last inherit bytes commited to old
 * current.
 */
int chunk_list_add(struct chunk_list *cm, struct chunk *a, size_t inherit)
{
	struct chunk *b = chunk_list_current(cm);
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

	mk_list_add(&a->_head, &cm->chunks._head);
	return 0;
error:
	if (mk_list_is_empty(&a->_head)) {
		mk_list_del(&a->_head);
	}
	return -1;
}

void chunk_list_stats(struct chunk_list *cm)
{
	struct mk_list *head;
	struct chunk *c;
	size_t used;
	size_t free;
	size_t total_used = 0;
	size_t total_free = 0;
	int chunks        = 0;

	log_info("# Chunk stats.");

	mk_list_foreach(head, &cm->chunks._head) {
		c = mk_list_entry(head, struct chunk, _head);
		used = c->write;
		free = c->size - used;

		log_info("Chunk: %d, S: %ld B, U: %ld B, F: %ld B, R: %d",
			chunks,
			c->size,
			used,
			free,
			c->refs);

		total_used += used;
		total_free += free;
		chunks++;
	}

	log_info("Total");
	log_info("Count: %d, Size: %ld B, Used: %ld B, Free: %ld B",
		chunks,
		total_used + total_free,
		total_used,
		total_free);

	log_info("# Chunk stats.");
}

void chunk_list_free_chunks(struct chunk_list *cm)
{
	struct mk_list *head, *tmp;
	struct chunk *c;

	if (!mk_list_is_empty(&cm->chunks._head)) {
		log_info("No chunks to free in manager.");
		return;
	}

	mk_list_foreach_safe(head, tmp, &cm->chunks._head) {
		c = mk_list_entry(head, struct chunk, _head);
		chunk_free(c);
	}
}


int chunk_iov_init(struct chunk_iov *iov, int size)
{
	iov->held_refs = mem_alloc(size * sizeof(*iov->held_refs));
	check_mem(iov->held_refs);

	iov->io = mem_alloc(size * sizeof(*iov->io));
	check_mem(iov->io);

	iov->size = size;
	iov->index = 0;

	return 0;
error:
	return -1;
}

size_t chunk_iov_length(struct chunk_iov *iov)
{
	size_t s = 0;
	int i;

	for (i = 0; i < iov->index; i++) {
		s += iov->io[i].iov_len;
	}

	return s;
}

ssize_t chunk_iov_sendv(int fd, struct chunk_iov *iov)
{
	check_debug(iov->index > 0, "Tried sending empty chunk_iov.");

	return writev(fd, iov->io, iov->index);
error:
	return 0;
}

int chunk_iov_add(struct chunk_iov *iov, struct chunk_ptr cp)
{
	struct chunk_ref *cr;
	struct iovec *io;

	check(iov->index < iov->size, "chunk_iov is full.");
	check(cp.len > 0, "tried to add empty chunk_ptr");

	cr = iov->held_refs + iov->index;
	io = iov->io + iov->index;

	iov->index += 1;

	chunk_retain(cp.parent);

	cr->t = CHUNK_REF_CHUNK;
	cr->u.chunk = cp.parent;

	io->iov_len = cp.len;
	io->iov_base = cp.data;

	return 0;
error:
	return -1;
}

int chunk_iov_add_ptr(struct chunk_iov *iov,
		void *vptr,
		size_t len,
		int do_free)
{
	struct chunk_ref *cr;
	struct iovec *io;
	uint8_t *ptr = vptr;

	check(iov->index < iov->size, "chunk_iov is full.");
	check(len > 0, "tried to add ptr with len = 0.");

	cr = iov->held_refs + iov->index;
	io = iov->io + iov->index;

	iov->index += 1;

	if (do_free) {
		cr->t = CHUNK_REF_UINT8;
		cr->u.ptr = ptr;
	} else {
		cr->t = CHUNK_REF_NULL;
	}

	io->iov_len = len;
	io->iov_base = ptr;

	return 0;
error:
	return -1;
}

static void chunk_iov_free_refs(struct chunk_iov *iov)
{
	int i;
	struct chunk_ref *cr;

	for (i = 0; i < iov->index; i++) {
		cr = iov->held_refs + i;

		if (cr->t == CHUNK_REF_CHUNK) {
			chunk_release(cr->u.chunk);
		}
		else if (cr->t == CHUNK_REF_UINT8) {
			mem_free(cr->u.ptr);
		}

		cr->t = CHUNK_REF_NULL;
	}
}

void chunk_iov_reset(struct chunk_iov *iov)
{
	chunk_iov_free_refs(iov);
	iov->index = 0;
}

void chunk_iov_free(struct chunk_iov *iov)
{
	chunk_iov_free_refs(iov);

	if (iov->io) {
		mem_free(iov->io);
		iov->io = NULL;
	}
	if (iov->held_refs) {
		mem_free(iov->held_refs);
		iov->held_refs = NULL;
	}

	iov->index = 0;
	iov->size = 0;
}
