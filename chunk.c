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
	tmp->pos  = 0;
	tmp->refs = 0;
	tmp->size = CHUNK_SIZE(size);

	return tmp;
error:
	return NULL;
}

int chunk_commit(struct chunk *c, size_t bytes)
{
	check(c->size - c->pos >= bytes, "Commited more bytes then available.");

	c->pos += bytes;
	return 0;
error:
	return -1;
}

struct chunk_ptr chunk_ptr_remain(struct chunk *c)
{
	return (struct chunk_ptr){
		.parent = c,
		.len    = c->size - c->pos,
		.data   = c->data + c->pos,
	};
}

struct chunk_ptr chunk_ptr_stored(struct chunk *c)
{
	return (struct chunk_ptr){
		.parent = c,
		.len    = c->pos,
		.data   = c->data,
	};
}

struct chunk_ptr chunk_ptr_base(struct chunk *c)
{
	return (struct chunk_ptr){
		.parent = c,
		.len    = c->size,
		.data   = c->data,
	};
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

	if (c->refs <= 0) {
		log_info("Freeing chunk on release.");
		chunk_free(c);
		return 1;
	} else {
		return 0;
	}
}

void chunk_mng_init(struct chunk_mng *cm)
{
	mk_list_init(&cm->chunks._head);
}

struct chunk *chunk_mng_current(struct chunk_mng *cm)
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
int chunk_mng_add(struct chunk_mng *cm, struct chunk *c, size_t inherit)
{
	struct chunk *t = chunk_mng_current(cm);
	struct chunk_ptr p, q;
	ssize_t begin;

	if (t && inherit > 0) {
		p = chunk_ptr_remain(c);
		q = chunk_ptr_stored(t);

		begin = q.len - inherit;

		check(p.len >= inherit, "Not enough free mem to inherit.");
		check(begin > 0,        "Not enough used mem to inherit.");

		memcpy(p.data, q.data + begin, inherit);
		chunk_commit(c, inherit);
	}

	if (t) {
		chunk_release(t);
	} else {
		check(inherit == 0, "No chunks to inherit from.");
	}

	mk_list_add(&c->_head, &cm->chunks._head);
	chunk_retain(c);

	return 0;
error:
	if (mk_list_is_empty(&c->_head)) 
		mk_list_del(&c->_head);
	return -1;
}

void chunk_mng_stats(struct chunk_mng *cm)
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
		used = c->pos;
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

void chunk_mng_free_chunks(struct chunk_mng *cm)
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
