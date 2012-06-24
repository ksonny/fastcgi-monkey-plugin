#ifndef MK_FASTCGI_PROTOCOL
#define MK_FASTCGI_PROTOCOL

#include <stdint.h>

#include "stream.h"

#define FCGI_MAX_LENGTH 0xffff
#define FCGI_HEADER_LEN 8
#define FCGI_VERSION_1 1

enum fcgi_msg_type {
	FCGI_BEGIN_REQUEST	= 1,
	FCGI_ABORT_REQUEST	= 2,
	FCGI_END_REQUEST	= 3,
	FCGI_PARAMS		= 4,
	FCGI_STDIN              = 5,
	FCGI_STDOUT             = 6,
	FCGI_STDERR             = 7,
	FCGI_DATA               = 8,
	FCGI_GET_VALUES         = 9,
	FCGI_GET_VALUES_RESULT	= 10,
	FCGI_UNKNOWN_TYPE	= 11,
};

enum fcgi_role {
	FCGI_RESPONDER  = 1,
	FCGI_AUTHORIZER = 2,
	FCGI_FILTER     = 3,
};

struct fcgi_header {
	uint8_t  version;
	uint8_t  type;
	uint16_t req_id;
	uint16_t body_len;
	uint8_t  body_pad;
	uint8_t reserved[1];
};

struct fcgi_begin_req_body {
	uint16_t role;
	uint8_t  flags;
	uint8_t reserved[5];
};

struct fcgi_end_req_body {
	uint32_t application_status;
	uint8_t  protocol_status;
	uint8_t  reserved[3];
};

extern const char *fcgi_msg_type_str[];

extern const char *fcgi_role_str[];

void
fcgi_read_header(struct pkg_stream *s, struct fcgi_header *h);

int
fcgi_write_header(struct pkg_stream *s, const struct fcgi_header *h);

int
fcgi_write_begin_req(struct pkg_stream *s,
		const uint16_t req_id,
		const enum fcgi_role role,
		const uint8_t flags);

void
fcgi_print_pkg_names(struct pkg_stream *s);

#endif // MK_FASTCGI_PROTOCOL
