#ifndef __MK_PKG_STREAM__
#define __MK_PKG_STREAM__

#include "stream.h"

int
mk_stream_init(struct pkg_stream *s, int fd, size_t buffer_size);

void
mk_stream_destroy(struct pkg_stream *s);

ssize_t
mk_stream_refill(struct pkg_stream *s);

ssize_t
mk_stream_flush(struct pkg_stream *s);

#endif // __MK_PKG_STREAM__
