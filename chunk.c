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

/* Possibly move last package? */
int chunk_mng_add(struct chunk_mng *cm, struct chunk *c, size_t inherit)
{
	struct chunk *t = chunk_mng_current(cm);
	struct chunk_ptr p, q;

	if (t) {
		p = chunk_ptr_remain(c);
		q = chunk_ptr_stored(t);

		check(p.len >= inherit, "Not enough free space to inherit.");
		check(q.len >= inherit, "Not enough used space to inherit.");

		memcpy(p.data, q.data, inherit);
		chunk_commit(c, inherit);

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
	size_t bytes_used = 0;
	unsigned int chunks = 0;

	mk_list_foreach(head, &cm->chunks._head) {
		c = mk_list_entry(head, struct chunk, _head);
		bytes_used += c->size + offsetof(struct chunk, data);
		chunks++;
	}

	log_info("%ld bytes used by %d chunks.",
		bytes_used,
		chunks);
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
