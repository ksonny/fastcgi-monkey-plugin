#ifndef __STREAM__H
#define __STREAM__H

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct pkg_stream {
	int fd;
	ssize_t pkg_start;
	ssize_t pkg_end;
	size_t  pkg_pad;
	size_t  end;
	size_t  pos;
	size_t  size;
	uint8_t *buffer;
};

size_t
stream_get_pos(struct pkg_stream *s);

uint8_t *
stream_ptr(struct pkg_stream *s);

size_t
stream_rem(struct pkg_stream *s);

void
stream_commit(struct pkg_stream *s, size_t nbytes);

void
stream_reset(struct pkg_stream *s);

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

size_t
stream_pkg_rem(struct pkg_stream *s);

size_t
stream_pkg_mark_end(struct pkg_stream *s);

int
stream_pkg_pad(struct pkg_stream *s, size_t pad);

int
stream_pkg_goto_start(struct pkg_stream *s);

int
stream_pkg_goto_end(struct pkg_stream *s);

#endif /* __STREAM__H */
