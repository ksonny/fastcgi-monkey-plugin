#ifndef __MK_CHUNK__
#define __MK_CHUNK__

#include <stdint.h>

#include "mk_list.h"

struct chunk {
	struct mk_list _head;

	size_t  read;
	size_t  write;
	size_t  size;
	int32_t refs;

	uint8_t data[0];
};

struct chunk_ptr {
	struct chunk *parent;
	size_t   len;
	uint8_t *data;
};

struct chunk_list {
	struct chunk chunks;
};

#define CHUNK_SIZE(SIZE) (SIZE) - offsetof(struct chunk, data)

void chunk_module_init(void *(*mem_alloc_f)(const size_t),
		void (*mem_free_f)(void *));

struct chunk *chunk_new(size_t size);

struct chunk_ptr chunk_read_ptr(struct chunk *c);

struct chunk_ptr chunk_write_ptr(struct chunk *c);

int chunk_set_read_ptr(struct chunk *c, struct chunk_ptr read);

int chunk_set_write_ptr(struct chunk *c, struct chunk_ptr write);

void chunk_free(struct chunk *c);

void chunk_retain(struct chunk *c);

int chunk_release(struct chunk *c);


void chunk_list_init(struct chunk_list *cm);

struct chunk *chunk_list_current(struct chunk_list *cm);

int chunk_list_add(struct chunk_list *cm, struct chunk *a, size_t inherit);

void chunk_list_stats(struct chunk_list *cm);

void chunk_list_free_chunks(struct chunk_list *cm);

#endif // __MK_CHUNK__
