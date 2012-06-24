#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

// #include <arpa/inet.h>
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <netdb.h>
// #include <fcntl.h>

#include "MKPlugin.h"
#include "dbg.h"
#include "protocol.h"

#define FCGI_BUFFER_SIZE 8192

const char *fcgi_msg_type_str[] = {
	[0]                      = "NULL MSG TYPE",
	[FCGI_BEGIN_REQUEST]     = "FCGI_BEGIN_REQUEST",
	[FCGI_ABORT_REQUEST]     = "FCGI_ABORT_REQUEST",
	[FCGI_END_REQUEST]       = "FCGI_END_REQUEST",
	[FCGI_PARAMS]            = "FCGI_PARAMS",
	[FCGI_STDIN]             = "FCGI_STDIN",
	[FCGI_STDOUT]            = "FCGI_STDOUT",
	[FCGI_STDERR]            = "FCGI_STDERR",
	[FCGI_DATA]              = "FCGI_DATA",
	[FCGI_GET_VALUES]        = "FCGI_GET_VALUES",
	[FCGI_GET_VALUES_RESULT] = "FCGI_GET_VALUES_RESULT",
	[FCGI_UNKNOWN_TYPE]      = "FCGI_UNKNOWN_TYPE",
};

const char *fcgi_role_str[] = {
	[0]               = "NULL ROLE",
	[FCGI_RESPONDER]  = "FCGI_RESPONDER",
	[FCGI_AUTHORIZER] = "FCGI_AUTHORIZER",
	[FCGI_FILTER]     = "FCGI_FILTER",
};

void
fcgi_read_header(uint8_t *p, struct fcgi_header *h)
{
	uint16_t x;

	h->version  = p[0];
	h->type     = p[1];
	memcpy(&x, p + 2, sizeof(x));
	h->req_id   = ntohs(x);
	memcpy(&x, p + 4, sizeof(x));
	h->body_len = ntohs(x);
	h->body_pad = p[6];
}

void
fcgi_write_header(uint8_t *p, const struct fcgi_header *h)
{
	uint16_t x;

	p[0] = h->version;
	p[1] = h->type;
	x    = htons(h->req_id);
	memcpy(p + 2, &x, sizeof(x));
	x    = htons(h->body_len);
	memcpy(p + 4, &x, sizeof(x));
	p[6] = h->body_pad;
	p[7] = 0;
}

void
fcgi_write_begin_req_body(uint8_t *p,
		const struct fcgi_begin_req_body *b)
{
	uint16_t x;

	x    = htons(b->role);
	memcpy(p + 0, &x, sizeof(x));
	p[2] = b->flags;
	memset(p + 3, 0, 5);
}

int
fcgi_write_begin_req(mk_pointer p,
		const uint16_t req_id,
		const enum fcgi_role role,
		const uint8_t flags)
{
	struct fcgi_header h = {
		.version  = FCGI_VERSION_1,
		.type     = FCGI_BEGIN_REQUEST,
		.req_id   = req_id,
		.body_len = FCGI_BEGIN_REQ_LEN - FCGI_HEADER_LEN,
		.body_pad = 0,
	};
	struct fcgi_begin_req_body b = {
		.role     = role,
		.flags    = flags,
	};

	if (p.len >= FCGI_BEGIN_REQ_LEN) {
		PLUGIN_TRACE("Buffer is not FCGI_BEGIN_REQ_LEN.");
		goto exit;
	}

	fcgi_write_header((uint8_t *)p.data + 0, &h);
	fcgi_write_begin_req_body((uint8_t *)p.data + FCGI_HEADER_LEN, &b);

	return 0;
exit:
	return -1;
}
