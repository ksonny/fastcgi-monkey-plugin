#ifndef __STREAM__H
#define __STREAM__H

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct pkg_stream {
	int fd;                  /* Stream file descriptor. */
	size_t body_end;         /* End of body in buffer.
				  * In output stream, end of last
				  * encapsulated body. */
	size_t body_pad;         /* Length of body padding.
				  * In output stream, padding of last
				  * encapsulated body. */
	size_t end;              /* End of buffer content.
				  * Unused in output stream. */
	size_t pos;              /* Position in buffer. */
	size_t size;             /* Size of buffer. */
	unsigned char *buffer;   /* Stream buffer array. */
};

size_t
stream_rem(struct pkg_stream *s);

size_t
stream_body_rem(struct pkg_stream *s);

void
stream_set_pkg(struct pkg_stream *s,
	size_t head_len,
	size_t body_len,
	size_t body_pad);
size_t
stream_get_pkg_end(struct pkg_stream *s);

unsigned char *
stream_pos(struct pkg_stream *s);

size_t
stream_get_pos(struct pkg_stream *s);

void
stream_set_pos(struct pkg_stream *s, size_t pos);

void
stream_commit(struct pkg_stream *s, size_t nbytes);

void
stream_reset(struct pkg_stream *s);

void
stream_close(struct pkg_stream *s);

void
stream_open(struct pkg_stream *s);

int
stream_init(struct pkg_stream *s, int fd, size_t buffer_size);

void
stream_destroy(struct pkg_stream *s);

ssize_t
stream_refill(struct pkg_stream *s);

ssize_t
stream_flush(struct pkg_stream *s);

size_t
stream_memset(struct pkg_stream *s, int v, size_t nbyte);

ssize_t
stream_skip(struct pkg_stream *s, const size_t nbyte);

size_t
stream_write(struct pkg_stream *s, const void *buf, const size_t nbyte);

size_t
stream_read(struct pkg_stream *s, void *buf, const size_t nbyte);

ssize_t
stream_refill_read(struct pkg_stream *s, void *buf, const size_t nbyte);

#endif /* __STREAM__H */
