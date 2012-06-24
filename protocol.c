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

int
fcgi_validate_struct_sizes(void)
{
	struct fcgi_header header;
	struct fcgi_begin_req_body begin_body;
	struct fcgi_end_req_body end_body;

	check(FCGI_HEADER_LEN == sizeof(header),
		"sizeof(header) does not match FCGI_HEADER_LEN.");
	check(FCGI_BEGIN_BODY_LEN == sizeof(begin_body),
		"sizeof(begin_body) does not match FCGI_BEGIN_BODY_LEN.");
	check(FCGI_END_BODY_LEN == sizeof(end_body),
		"sizeof(end_body) does not match FCGI_END_BODY_LEN.");

	return 0;
error:
	return -1;
}

size_t
fcgi_read_header(uint8_t *p, struct fcgi_header *h)
{
	h->version  = p[0];
	h->type     = p[1];
	h->req_id   = (p[2] << 8) + p[3];
	h->body_len = (p[4] << 8) + p[5];
	h->body_pad = p[6];

	return sizeof(*h);
}

size_t
fcgi_write_header(uint8_t *p, const struct fcgi_header *h)
{
	p[0] = h->version;
	p[1] = h->type;
	p[2] = (h->req_id >> 8)   & 0xff;
	p[3] = (h->req_id)        & 0xff;
	p[4] = (h->body_len >> 8) & 0xff;
	p[5] = (h->body_len)      & 0xff;
	p[6] = h->body_pad;
	p[7] = 0;

	return sizeof(*h);
}

size_t
fcgi_write_begin_req_body(uint8_t *p, const struct fcgi_begin_req_body *b)
{
	p[0] = (b->role >> 8) & 0xff;
	p[1] = (b->role)      & 0xff;
	p[2] = b->flags;
	bzero(p + 3, 5);

	return sizeof(*b);
}

size_t
fcgi_write_begin_req(uint8_t *p,
		const uint16_t req_id,
		const enum fcgi_role role,
		const uint8_t flags)
{
	struct fcgi_begin_req_body b = {
		.role     = role,
		.flags    = flags,
	};
	struct fcgi_header h = {
		.version  = FCGI_VERSION_1,
		.type     = FCGI_BEGIN_REQUEST,
		.req_id   = req_id,
		.body_len = sizeof(b),
		.body_pad = 0,
	};
	size_t bytes = 0;

	bytes += fcgi_write_header(p, &h);
	bytes += fcgi_write_begin_req_body(p, &b);

	return bytes;
}
