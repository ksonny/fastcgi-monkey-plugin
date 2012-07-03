#ifndef __MK_CHUNK__
#define __MK_CHUNK__

#include <sys/uio.h>
#include "mk_list.h"

#define CHUNK_SIZE(SIZE) (SIZE) - offsetof(struct chunk, data) 

struct chunk {
	struct mk_list _head;

	size_t  pos;
	size_t  size;
	int32_t refs;

	uint8_t data[0];
};

struct chunk_ptr {
	struct chunk *parent;
	size_t   len;
	uint8_t *data;
};

struct chunk_mng {
	struct chunk chunks;
};

struct chunk *chunk_new(size_t size);

int chunk_commit(struct chunk *c, size_t bytes);

struct chunk_ptr chunk_ptr_remain(struct chunk *c);

struct chunk_ptr chunk_ptr_stored(struct chunk *c);

void chunk_free(struct chunk *c);

void chunk_retain(struct chunk *c);

int chunk_release(struct chunk *c);


int chunk_mng_init(struct chunk_mng *cm);

struct chunk *chunk_mng_current(struct chunk_mng *cm);

int chunk_mng_add(struct chunk_mng *cm, struct chunk *c, size_t inherit);

void chunk_mng_stats(struct chunk_mng *cm);

void chunk_mng_free_chunks(struct chunk_mng *cm);

#endif // __MK_CHUNK__
