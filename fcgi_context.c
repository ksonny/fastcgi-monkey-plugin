#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

#include "fcgi_context.h"

#include "dbg.h"

static void *(*mem_alloc)(const size_t) = &malloc;
static void (*mem_free)(void *) = &free;

void fcgi_context_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *))
{
	mem_alloc = mem_alloc_p;
	mem_free  = mem_free_p;
}

void fcgi_context_free(struct fcgi_context *tdata)
{
	request_list_free(&tdata->rl);
	fcgi_fd_list_free(&tdata->fdl);
	chunk_list_free_chunks(&tdata->cl);
}

int fcgi_context_init(struct fcgi_context *tdata,
		struct fcgi_config *config,
		int request_capacity,
		int request_offset)
{
	check(!request_list_init(&tdata->rl,
				config->location_count,
				request_offset,
				request_capacity),
			"Failed to init request list.");
	check(!fcgi_fd_list_init(&tdata->fdl, config),
			"Failed to init fd list.");
	chunk_list_init(&tdata->cl);

	return 0;
error:
	fcgi_context_free(tdata);
	return -1;
}

void fcgi_context_list_free(struct fcgi_context_list *tdlist)
{
	int i;

	pthread_mutex_destroy(&tdlist->thread_id_counter_mutex);

	for (i = 0; i < tdlist->n; i++) {
		if (!tdlist->tds[i]) {
			continue;
		}
		fcgi_context_free(tdlist->tds[i]);
		mem_free(tdlist->tds[i]);
	}

	mem_free(tdlist->tds);
	tdlist->n = 0;
	tdlist->tds = NULL;
}

int fcgi_context_list_init(struct fcgi_context_list *tdlist,
		struct fcgi_config *config,
		int workers,
		int worker_capacity)
{
	struct fcgi_context *tdata;
	const uint16_t request_capacity = worker_capacity;
	uint16_t request_offset = 1;
	int i;

	check(request_capacity > 0, "No request capacity.");
	check(request_capacity < UINT16_MAX, "Request capacity too large.");

	tdlist->thread_id_counter = 0;
	pthread_mutex_init(&tdlist->thread_id_counter_mutex, NULL);

	tdlist->tds = mem_alloc(workers * sizeof(*tdlist->tds));
	check_mem(tdlist->tds);
	tdlist->n = workers;

	for (i = 0; i < workers; i++) {
		tdata = mem_alloc(sizeof(*tdata));
		check_mem(tdata);
		tdlist->tds[i] = tdata;

		check(!fcgi_context_init(tdata,
					config,
					request_capacity,
					request_offset),
			"Failed to init thread data %d.", i);

		request_offset += request_capacity;
	}

	check(request_offset == workers * worker_capacity + 1,
		"You can't freaking count!");

	return 0;
error:
	fcgi_context_list_free(tdlist);
	return -1;
}

int fcgi_context_list_assign_thread_id(
		struct fcgi_context_list *tdlist)
{
	int my_thread_id;

	check(tdlist->thread_id_counter < tdlist->n,
		"All thread id's have already assigned.");

	pthread_mutex_lock(&tdlist->thread_id_counter_mutex);

	my_thread_id = tdlist->thread_id_counter;
	tdlist->thread_id_counter += 1;

	pthread_mutex_unlock(&tdlist->thread_id_counter_mutex);

	return my_thread_id;
error:
	return -1;
}

struct fcgi_context *fcgi_context_list_get(
		struct fcgi_context_list *tdlist,
		int thread_id)
{
	struct fcgi_context *tdata;

	check(thread_id >= 0  && thread_id < tdlist->n,
		"Thread id %d is out of range.", thread_id);

	tdata = tdlist->tds[thread_id];
	check(tdata, "Thread data is NULL for thread id %d.", thread_id);

	return tdata;
error:
	return NULL;
}
