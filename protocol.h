#ifndef MK_FASTCGI_PROTOCOL
#define MK_FASTCGI_PROTOCOL

#include <stdint.h>

#define FCGI_MAX_LENGTH 0xffff
#define FCGI_VERSION_1 1

#define FCGI_HEADER_LEN 8
#define FCGI_BEGIN_BODY_LEN 8
#define FCGI_END_BODY_LEN 8

#define FCGI_MSG_TYPE_STR(type) \
	((type) < 11 ? fcgi_msg_type_str[(type)] : fcgi_msg_type_str[11])

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

int
fcgi_validate_struct_sizes(void);

size_t
fcgi_read_header(uint8_t *p, struct fcgi_header *h);

size_t
fcgi_write_header(uint8_t *p, const struct fcgi_header *h);

size_t
fcgi_read_end_req_body(uint8_t *p, struct fcgi_end_req_body *b);

size_t
fcgi_write_begin_req_body(uint8_t *p, const struct fcgi_begin_req_body *b);

size_t
fcgi_param_read_length(uint8_t *p);

size_t
fcgi_param_write(uint8_t *p,
	mk_pointer key,
	mk_pointer value);


#endif // MK_FASTCGI_PROTOCOL
