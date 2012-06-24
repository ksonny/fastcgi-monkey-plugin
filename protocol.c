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

void
fcgi_read_header(struct pkg_stream *s, struct fcgi_header *h)
{
	uint8_t *p;
	assert(stream_rem(s) >= FCGI_HEADER_LEN);

	p = stream_ptr(s);

	h->version  = p[0];
	h->type     = p[1];
	h->req_id   = (p[2] << 8) + p[3];
	h->body_len = (p[4] << 8) + p[5];
	h->body_pad = p[6];

	stream_commit(s, FCGI_HEADER_LEN);
}

int
fcgi_write_header(struct pkg_stream *s, const struct fcgi_header *h)
{
	uint8_t p[8];

	check(stream_rem(s) > sizeof(p),
		"Not enough space on stream. Rem: %ld, Size: %ld",
		stream_rem(s), sizeof(p));

	p[0] = h->version;
	p[1] = h->type;
	p[2] = (h->req_id >> 8)   & 0xff;
	p[3] = (h->req_id)        & 0xff;
	p[4] = (h->body_len >> 8) & 0xff;
	p[5] = (h->body_len)      & 0xff;
	p[6] = h->body_pad;
	p[7] = 0;

	stream_write(s, p, sizeof(p));

	return 0;
error:
	return -1;
}

int
fcgi_write_begin_req_body(struct pkg_stream *s,
		const struct fcgi_begin_req_body *b)
{
	uint8_t p[8];

	assert(stream_rem(s) > sizeof(p));

	p[0] = (b->role >> 8) & 0xff;
	p[1] = (b->role)      & 0xff;
	p[2] = b->flags;
	bzero(p + 3, 5);

	stream_write(s, p, sizeof(p));

	return 0;
}

int
fcgi_write_begin_req(struct pkg_stream *s,
		const uint16_t req_id,
		const enum fcgi_role role,
		const uint8_t flags)
{
	struct fcgi_header h = {
		.version  = FCGI_VERSION_1,
		.type     = FCGI_BEGIN_REQUEST,
		.req_id   = req_id,
		.body_len = 8,
		.body_pad = 0,
	};
	struct fcgi_begin_req_body b = {
		.role     = role,
		.flags    = flags,
	};

	check(stream_rem(s) > 16, "Buffer is not FCGI_BEGIN_REQ_LEN.");

	fcgi_write_header(s, &h);
	fcgi_write_begin_req_body(s, &b);
	stream_pkg_mark_end(s);

	return 0;
error:
	return -1;
}
