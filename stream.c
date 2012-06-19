#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h> /* read, write, fcntl */

#include "dbg.h"
#include "stream.h"

/*
 * Remaining bytes in stream.
 */
size_t
stream_rem(struct pkg_stream *s)
{
	assert(s->end >= s->pos);
	return (s->end - s->pos);
}

/*
 * Remaining bytes on body.
 */
size_t
stream_body_rem(struct pkg_stream *s)
{
	if (s->body_end >= s->pos)
		return (s->body_end - s->pos);
	else
		return 0;
}

/*
 * Set pkg counters.
 *
 * This function simply sets the counters inside of the stream so
 * stream_body_rem will report correct length. No effort is made to
 * prevent reading beyond a body.
 *
 * These counters are inside the stream to ease interactions with
 * protocols that sends packages with header and body.
 *
 * Note: Body may extend beyond current buffer.
 * Note: body_len should not include space for the header nor padding.
 */
void
stream_set_pkg(struct pkg_stream *s,
	size_t head_len,
	size_t body_len,
	size_t body_pad)
{
	s->body_end += head_len + body_len;
	s->body_pad  = body_pad;
}

/**
 * stream_get_pkg_end - offset of last byte used by pkg
 */
size_t
stream_get_pkg_end(struct pkg_stream *s)
{
	return (s->body_end + s->body_pad);
}

/*
 * Get current position in stream.
 */
unsigned char *
stream_pos(struct pkg_stream *s)
{
	assert(s->pos < s->end);
	assert(s->pos < s->size);
	return (s->buffer + s->pos);
}

size_t
stream_get_pos(struct pkg_stream *s)
{
	return s->pos;
}

/*
 * Set current position in stream.
 */
void
stream_set_pos(struct pkg_stream *s, size_t pos)
{
	assert(pos <= s->size);
	s->pos = pos;
}

/*
 * Forward stream position.
 */
void
stream_commit(struct pkg_stream *s, size_t nbytes)
{
	assert(nbytes <= stream_rem(s));
	s->pos += nbytes;
}

/*
 * Reset stream counters.
 *
 * Note: Stream state is not reset.
 */
void
stream_reset(struct pkg_stream *s)
{
	s->body_end = 0;
	s->body_pad = 0;
	s->pos      = 0;
	s->end      = 0;
}

/*
 * Initiate a new stream structure.
 */
int
stream_init(struct pkg_stream *s,
		int fd,
		size_t buffer_size)
{
	unsigned char *buffer;

	buffer = malloc(buffer_size);
	check_mem(buffer);

	s->fd     = fd;
	s->size   = buffer_size;
	s->buffer = buffer;

	stream_reset(s);

	return 0;
error:
	if (buffer) free(buffer);
	return -1;
}

void
stream_destroy(struct pkg_stream *s)
{
	stream_reset(s);
	stream_close(s);

	if (s->fd >= 0) {
		close(s->fd);
		s->fd = -1;
	}

	if (s->buffer) {
		free(s->buffer);
		s->buffer = NULL;
	}
}

/*
 * Refill stream with data.
 *
 * Reset stream counters and read new data.
 */
ssize_t
stream_refill(struct pkg_stream *s)
{
	ssize_t cnt;

	check_debug(stream_rem(s) == 0,
		"Unread data remain in buffer.");

	cnt = read(s->fd, s->buffer, s->size);
	check(cnt != -1, "Error on socket.");

	s->body_end = MIN(0, s->body_end - s->end);
	s->pos = 0;
	s->end = cnt;

	return cnt;
error:
	return -1;
}

/*
 * Flush data on stream.
 *
 * Write stream data and reset counters.
 */
ssize_t
stream_flush(struct pkg_stream *s)
{
	ssize_t ret;

	check(s->pos > 0, "Buffer is empty.");
	check(s->body_end == s->pos - s->body_pad,
		"Some data not encapsulated.");

	ret = write(s->fd, s->buffer, s->pos + s->body_pad);
	check(ret != -1, "Error on socket.");
	check((size_t)ret == s->pos + s->body_pad, "Failed to flush stream.");

	stream_reset(s);

	return 0;
error:
	return -1;
}

/*
 * Sets the next nbyte bytes of buffer in stream to the specific
 * value.
 *
 * Return number of bytes set.
 */
size_t
stream_memset(struct pkg_stream *s, int v, size_t nbyte)
{
	size_t cnt = MIN(stream_rem(s), nbyte);
	memset(s->buffer, v, cnt);
	stream_commit(s, cnt);
	return cnt;
}

/**
 * stream_skip - skip input on stream
 */
ssize_t
stream_skip(struct pkg_stream *s, const size_t nbyte)
{
	size_t len, cnt = 0;

	assert(s != NULL);

	do {
		if (stream_rem(s) == 0) {
			check(stream_refill(s) != -1, "Socket error.");
		}

		len = MIN(stream_rem(s), nbyte);
		stream_commit(s, len);

		cnt += len;
	} while (nbyte - cnt > 0);

	return cnt;
error:
	return -1;
}

/*
 * Write data on stream if enough space remain.
 */
size_t
stream_write(struct pkg_stream *s, const void *buf, const size_t nbyte)
{
	size_t fill;

	assert(s != NULL);
	assert(buf != NULL);

	fill = MIN(stream_rem(s), nbyte);

	check_debug(fill > 0, "Stream is full.");

	memcpy(stream_pos(s), buf, fill);
	stream_commit(s, fill);

	return fill;
error:
	return 0;
}

/*
 * Read data from stream if enough until end of stream or end of buffer.
 */
size_t
stream_read(struct pkg_stream *s, void *buf, const size_t nbyte)
{
	size_t rem;
	size_t fill;

	assert(s != NULL);
	assert(buf != NULL);

	rem = stream_rem(s);
	check_debug(rem > 0, "Stream is empty.");
	fill = MIN(rem, nbyte);

	memcpy(buf, stream_pos(s), fill);
	stream_commit(s, fill);

	return fill;
error:
	return 0;
}

/*
 * Read data from stream until end of stream or until socket is
 * closed.
 */
ssize_t
stream_refill_read(struct pkg_stream *s, void *buf, const size_t nbyte)
{
	ssize_t cnt;
	size_t rem;

	cnt = stream_read(s, buf, nbyte);

	if ((size_t)cnt == nbyte)
		return cnt;

	rem = nbyte - cnt;

	cnt = read(s->fd, (unsigned char *)buf + cnt, rem);
	check(cnt != -1, "Error on socket.");

	s->body_end = s->body_end - MIN(s->body_end, (size_t)cnt);

	return cnt;
error:
	return -1;
}
