#include <stddef.h>

#include "MKPlugin.h"
#include "dbg.h"

#include "chunk.h"

struct chunk *chunk_new(size_t size)
{
	struct chunk *tmp = NULL;

	tmp = mk_api->mem_alloc(size);
	check_mem(tmp);

	mk_list_init(&tmp->_head);
	tmp->read  = 0;
	tmp->write = 0;
	tmp->refs  = 0;
	tmp->size  = CHUNK_SIZE(size);

	return tmp;
error:
	if (tmp) {
		mk_api->mem_free(tmp);
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
	mk_api->mem_free(c);
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
