/* $Id$ */

/*-
 * Copyright 2010  Morgan Stanley and Co. Incorporated
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


/*
 *
 */

struct knc_stream;
struct knc_ctx;

/*
 * The various constructors:
 */

struct knc_ctx		*knc_ctx_init(void);
struct knc_ctx		*knc_initiate(const char *, const char *);
struct knc_ctx		*knc_init_fd(const char *, const char *, int);
struct knc_ctx		*knc_connect(const char *, const char *, const char *);
struct knc_ctx		*knc_connect_parse(const char *, int);
struct knc_ctx		*knc_accept(const char *, const char *);
struct knc_ctx		*knc_accept_fd(const char *, const char *, int);
void			 knc_ctx_close(struct knc_ctx *);

int			 knc_get_fd(struct knc_ctx *);

void			 knc_set_debug(struct knc_ctx *, int);

struct knc_stream	*knc_init_stream(void);

int			 knc_error(struct knc_ctx *);
const char		*knc_errstr(struct knc_ctx *);

/*
 * The simple(?) interface
 */


void	knc_set_local_fd(struct knc_ctx *, int);
int	knc_get_local_fd(struct knc_ctx *);
void	knc_set_net_fd(struct knc_ctx *, int);
int	knc_get_net_fd(struct knc_ctx *);
ssize_t	knc_read(struct knc_ctx *, void *, size_t);
ssize_t	knc_write(struct knc_ctx *, const void *, size_t);
int	knc_fill(struct knc_ctx *, int);
int	knc_flush(struct knc_ctx *, int);
void	knc_garbage_collect(struct knc_ctx *);

/*
 * The buffer interface allows programmers to use KNC as a simple byte
 * stream without worrying about file descriptors.
 */

#define KNC_DIR_RECV	0x1
#define KNC_DIR_SEND	0x2

int	knc_put_buf(struct knc_ctx *, int, const void *,  size_t);
int	knc_get_ibuf(struct knc_ctx *, int, void **, size_t);
int	knc_get_obuf(struct knc_ctx *, int, void **, size_t);
int	knc_get_obufv(struct knc_ctx *, int dir, struct iovec **, size_t *);
int	knc_drain_buf(struct knc_ctx *, int, int);
int	knc_fill_buf(struct knc_ctx *, int, int);
int	knc_avail_buf(struct knc_ctx *, int);


