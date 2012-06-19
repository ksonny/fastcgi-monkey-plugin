#include "MKPlugin.h"
#include "dbg.h"
#include "mk_stream.h"

int
mk_stream_init(struct pkg_stream *s, int fd, size_t buffer_size)
{
	unsigned char *buffer;
	buffer = mk_api->mem_alloc(buffer_size);
	check_mem(buffer);

	s->fd = fd;
	s->size = buffer_size;
	s->buffer = buffer;

	stream_reset(s);

	return 0;
error:
	if (buffer) free(buffer);
	return -1;
}

void
mk_stream_destroy(struct pkg_stream *s)
{
}

ssize_t
mk_stream_refill(struct pkg_stream *s)
{
	size_t  buffer_remain;
	ssize_t bytes_read;

	if (stream_rem(s) == 0) {
		s->body_end   = MIN(0, s->body_end - s->end);
		s->pos        = 0;
		s->end        = 0;
		buffer_remain = s->size;
	} else {
		buffer_remain = s->size - s->end;
	}

	bytes_read = mk_api->socket_read(s->fd, s->buffer, buffer_remain);
	check(bytes_read > -1, "Error on socket.");

	s->end += bytes_read;

	return bytes_read;
error:
	return -1;
}

ssize_t
mk_stream_flush(struct pkg_stream *s)
{
	ssize_t ret;

	check(s->pos > 0, "Buffer is empty.");
	check(s->body_end == s->pos - s->body_pad,
		"Some data not encapsulated.");

	ret = mk_api->socket_send(s->fd, s->buffer, s->pos + s->body_pad);
	check(ret != -1, "Error on socket.");
	check((size_t)ret == s->pos + s->body_pad, "Failed to flush stream.");

	stream_reset(s);

	return ret;
error:
	return -1;
}
