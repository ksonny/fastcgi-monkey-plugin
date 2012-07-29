#include <stdlib.h>

#include "dbg.h"
#include "protocol.h"

#include "request.h"

static void *(*mem_alloc)(const size_t) = &malloc;
static void (*mem_free)(void *) = free;

void request_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *))
{
	mem_alloc = mem_alloc_p;
	mem_free  = mem_free_p;
}

int request_init(struct request *req, int iov_n)
{
	*req = (struct request){
		.state = REQ_AVAILABLE,
		.flags = 0,

		.fd = -1,
		.fcgi_fd = -1,

		.clock_id = 0,
		.cs = NULL,
		.sr = NULL,

		.iov = {0},
	};

	check(!chunk_iov_init(&req->iov, iov_n), "Failed to init chunk_iov.");

	return 0;
error:
	return -1;
}

static void request_reset(struct request *req)
{
	req->state         = REQ_AVAILABLE;
	req->flags         = 0;
	req->fd            = -1;
	req->fcgi_fd       = -1;
	req->clock_id      = 0;

	chunk_iov_reset(&req->iov);
}

int request_set_state(struct request *req, enum request_state state)
{
	switch (state) {
	case REQ_AVAILABLE:
		check(req->state == REQ_FINISHED,
			"Bad state transition to REQ_AVAILABLE.");
		request_reset(req);
		break;
	case REQ_ASSIGNED:
		check(req->state == REQ_AVAILABLE ||
			req->state == REQ_FINISHED,
			"Bad state transition to REQ_ASSIGNED.");
		req->state = REQ_ASSIGNED;
		break;
	case REQ_SENT:
		check(req->state == REQ_ASSIGNED,
			"Bad state transition to REQ_SENT.");
		req->state = REQ_SENT;
		break;
	case REQ_STREAM_CLOSED:
		check(req->state == REQ_SENT,
			"Bad state transition to REQ_STREAM_CLOSED.");
		req->state = REQ_STREAM_CLOSED;
		break;
	case REQ_ENDED:
		check(req->state == REQ_STREAM_CLOSED ||
			req->state == REQ_FAILED ||
			req->state == REQ_SENT,
			"Bad state transition REQ_ENDED.");
		req->state = REQ_ENDED;
		break;
	case REQ_FINISHED:
		check(req->state == REQ_ENDED,
			"Bad state transition REQ_FINISHED.");
		req->state = REQ_FINISHED;
		break;
	case REQ_FAILED:
		req->state = REQ_FAILED;
		break;
	default:
		sentinel("Tried to set unknown request state.");
	};
	return 0;
error:
	return -1;
}


int request_assign(struct request *req,
	int fd,
	uint16_t clock_id,
	struct client_session *cs,
	struct session_request *sr)
{
	check_debug(!request_set_state(req, REQ_ASSIGNED),
		"Failed to set request state.");

	req->fd = fd;
	req->clock_id = clock_id;
	req->cs = cs;
	req->sr = sr;
	return 0;
error:
	return -1;
}

void request_set_fcgi_fd(struct request *req, int fcgi_fd)
{
	req->fcgi_fd = fcgi_fd;
}

int request_recycle(struct request *req)
{
	if (!(req->state & (REQ_FINISHED | REQ_FAILED))) {
		log_warn("Recycling still running request.");
	}

	request_reset(req);
	return 0;
}

ssize_t request_add_pkg(struct request *req,
		struct fcgi_header h,
		struct chunk_ptr cp)
{
	size_t pkg_length = sizeof(h) + h.body_len + h.body_pad;

	check(cp.len >= pkg_length, "Missing package data.");
	check(req->state == REQ_SENT, "Request not yet sent.");

	cp.data += sizeof(h);
	cp.len = h.body_len;

	check(!chunk_iov_add(&req->iov, cp),
		"Adding content to iov failed.");

	return pkg_length;
error:
	return -1;
	
}

void request_free(struct request *req)
{
	request_reset(req);
	chunk_iov_free(&req->iov);
}

int request_list_init(struct request_list *rl,
		uint16_t clock_count,
		uint16_t id_offset,
		uint16_t size)
{
	uint16_t *clock_hands = NULL;
	struct request *tmp = NULL;
	uint16_t i;

	clock_hands = mem_alloc(clock_count * sizeof(*clock_hands));
	check_mem(clock_hands);

	for (i = 0; i < clock_count; i++) {
		clock_hands[i] = 0;
	}

	tmp = mem_alloc(size * sizeof(*tmp));
	check_mem(tmp);

	for (i = 0; i < size; i++) {
		check(!request_init(tmp + i, 8),
			"Failed to init request %d", i);
	}

	rl->size = size;
	rl->id_offset = id_offset;
	rl->clock_count = clock_count;
	rl->clock_hands = clock_hands;
	rl->rs = tmp;

	return 0;
error:
	if (tmp && i > 0) {
		size = i;
		for (i = 0; i < size; i++) {
			request_free(tmp + i);
		}
	}
	if (tmp) mem_free(tmp);
	return -1;
}

static int get_clock_hand(struct request_list *rl, uint16_t clock_id)
{
	check(clock_id < rl->clock_count, "Clock index out of range.");

	return rl->clock_hands[clock_id];
error:
	return 0;
}

static void set_clock_hand(struct request_list *rl,
		uint16_t clock_id,
		uint16_t clock_hand)
{
	check(clock_id < rl->clock_count,
		"location index out of range.");

	rl->clock_hands[clock_id] = clock_hand;
error:
	return;
}

struct request *request_list_next_available(struct request_list *rl,
		uint16_t clock_id)
{
	uint16_t i, n = rl->size, clock = get_clock_hand(rl, clock_id);
	struct request *r;

	for (i = (clock + 1) % n; i != clock; i = (i + 1) % n) {
		r = rl->rs + i;
		if (r->state == REQ_AVAILABLE) {
			return r;
		}
	}
	return NULL;
}

struct request *request_list_next_assigned(struct request_list *rl,
		uint16_t clock_id)
{
	uint16_t i, n = rl->size, clock = get_clock_hand(rl, clock_id);
	struct request *r;

	for (i = (clock + 1) % n; i != clock; i = (i + 1) % n) {
		r = rl->rs + i;
		if (r->state == REQ_ASSIGNED && r->clock_id == clock_id) {
			set_clock_hand(rl, clock_id, i);
			return r;
		}
	}
	return NULL;
}

struct request *request_list_get_by_fd(struct request_list *rl, int fd)
{
	uint16_t i;
	struct request *r = NULL;

	for (i = 0; i < rl->size; i++) {
		r = rl->rs + i;
		if (r->fd == fd)
			return r;
	}
	return NULL;
}

struct request *request_list_get_by_fcgi_fd(struct request_list *rl, int fd)
{
	uint16_t i;
	struct request *r = NULL;

	for (i = 0; i < rl->size; i++) {
		r = rl->rs + i;
		if (r->fcgi_fd == fd)
			return r;
	}
	return NULL;
}

struct request *request_list_get(struct request_list *rl, uint16_t req_id)
{
	uint16_t real_req_index = req_id - rl->id_offset;
	check(req_id >= rl->id_offset,
		"Request id out of range.");
	check(real_req_index < rl->size,
		"Request id out of range.");

	return rl->rs + real_req_index;
error:
	return NULL;
}

uint16_t request_list_index_of(struct request_list *rl, struct request *r)
{
	ptrdiff_t offset = r - rl->rs;

	check(r >= rl->rs && r <= rl->rs + rl->size, "Request not part of list.");

	return rl->id_offset + offset;
error:
	return 0;

}

void request_list_free(struct request_list *rl)
{
	uint16_t i;

	if (!rl)
		return;

	for (i = 0; i < rl->size; i++) {
		request_free(rl->rs + i);
	}
	mem_free(rl->rs);
	rl->size = 0;
	rl->rs = NULL;
}
