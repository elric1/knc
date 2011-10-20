/* */

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

#include "config.h"

#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#if HAVE_GSSAPI_H
#include <gssapi.h>
#else 
#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#else
#include <gssapi/gssapi_krb5.h>
#endif
#endif

#include "libknc.h"

struct knc_stream_bit {
	void			*buf;
	gss_buffer_desc		 gssbuf;
	struct knc_stream_bit	*next;
	size_t			 len;
	size_t			 allocated;
};

struct knc_stream_gc {
	void			*ptr;
	struct knc_stream_gc	*next;
};

struct knc_stream {
	struct knc_stream_bit	*head;
	struct knc_stream_bit	*cur;
	struct knc_stream_bit	*tail;
	struct knc_stream_gc	*garbage;
	size_t			 bufpos;
	size_t			 avail;
};

struct knc_ctx {
	gss_ctx_id_t		 gssctx;
	gss_name_t		 client;	/* only set for an acceptor */
	gss_name_t		 server;	/* only set for an initiator */
	int			 state;
#define STATE_UNKNOWN	0x0
#define STATE_ACCEPT	0x1
#define STATE_INIT	0x2
#define STATE_SESSION	0x3
	int			 net_fd;
	int			 local_fd;
	int			 error;
	int			 debug;
#define KNC_ERROR_GSS	0x1
#define KNC_ERROR_PROTO	0x2
#define KNC_ERROR_RST	0x3
#define KNC_ERROR_PIPE	0x4
	char			*errstr;
	struct knc_stream	 raw_recv;
	struct knc_stream	 cooked_recv;
	struct knc_stream	 raw_send;
	struct knc_stream	 cooked_send;

	/*
	 * These are the read/write/close functions, they will be executed
	 * at the correct time by the code if they are defined.  If they
	 * are not defined, they will not be executed.
	 */

	ssize_t	(*netread)(int, void *, size_t);
	ssize_t	(*netwritev)(int, const struct iovec *, int);
	int	(*netclose)(int);

	ssize_t	(*localread)(int, void *, size_t);
	ssize_t	(*localwritev)(int, const struct iovec *, int);
	int	(*localclose)(int);
};

/* mmm, macros. */

#define KNC_GSS_ERROR(_ctx, _maj, _min, _ret, _str) do {		\
		if (GSS_ERROR((_maj))) {				\
			knc_gss_error((_ctx), (_maj), (_min), (_str));	\
			return (_ret);					\
		}							\
	} while (0)

#define MIN(a, b)	((a)<(b)?(a):(b))

#define KNC_MAXPACKETCONTENTS	65536

static int debug = 0;
#define DEBUG(x) do {				\
		if (debug) {			\
			debug_printf x ;	\
		}				\
	} while (0)

/* Local function declarations */

static void	debug_printf(const char *, ...)
    __attribute__((__format__(__printf__, 1, 2)));

static void	knc_syscall_error(struct knc_ctx *, int);
static void	knc_gss_error(struct knc_ctx *, int, int, const char *);

static struct knc_stream_bit	*knc_alloc_stream_bit(size_t);
static size_t			 knc_append_stream_bit(struct knc_stream *,
				    struct knc_stream_bit *);

static int	knc_put_stream(struct knc_stream *, const void *, size_t);
static int	knc_put_stream_gssbuf(struct knc_stream *, gss_buffer_t);
static int	knc_get_istream(struct knc_stream *, void **, size_t);
static ssize_t	knc_get_ostream(struct knc_stream *, void **, size_t);
static ssize_t	knc_get_ostreamv(struct knc_stream *, struct iovec **, size_t *);
static int	knc_stream_put_trash(struct knc_stream *, void *);
static ssize_t	knc_get_ostream_contig(struct knc_stream *, void **, size_t);
static ssize_t	knc_stream_drain(struct knc_stream *, size_t);
static ssize_t	knc_stream_fill(struct knc_stream *, size_t);
static size_t	knc_stream_avail(struct knc_stream *);
static void	knc_stream_garbage_collect(struct knc_stream *);

static ssize_t	read_packet(struct knc_stream *, void **b);
static ssize_t	put_packet(struct knc_stream *, gss_buffer_t);

static int	knc_state_init(struct knc_ctx *, void *, size_t);
static int	knc_state_accept(struct knc_ctx *, void *, size_t);
static int	knc_state_session(struct knc_ctx *, void *, size_t);
static int	knc_state_process_in(struct knc_ctx *);
static int	knc_state_process_out(struct knc_ctx *);
static int	knc_state_process(struct knc_ctx *);

static struct knc_stream *knc_find_buf(struct knc_ctx *, int, int);

/* And, ta da: the code */

void
debug_printf(const char *fmt, ...)
{
	va_list ap;
	char	buf[16384];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fprintf(stderr, "%d: %s", getpid(), buf);
}

static void
knc_destroy_stream(struct knc_stream *s)
{

	if (!s)
		return;

	s->cur = NULL;
	knc_stream_garbage_collect(s);
}

static size_t
knc_append_stream_bit(struct knc_stream *s, struct knc_stream_bit *b)
{

	b->next   = NULL;

	s->avail += b->len;
	if (s->head == NULL) {
		s->head = s->cur = s->tail = b;
		s->bufpos = 0;
	} else {
		s->tail->next = b;
		s->tail = b;
	}

	if (!s->cur)
		s->cur = s->tail;

	return b->len;
}

static struct knc_stream_bit *
knc_alloc_stream_bit(size_t len)
{
	struct knc_stream_bit	*bit;
	char			*tmpbuf;

	bit = calloc(1, sizeof(*bit));
	if (!bit)
		return NULL;

	tmpbuf = calloc(len, 1);
	if (!tmpbuf) {
		free(bit);
		return NULL;
	}

	bit->buf       = tmpbuf;
	bit->len       = 0;
	bit->allocated = len;

	return bit;
}

static int
knc_put_stream(struct knc_stream *s, const void *buf, size_t len)
{
	struct knc_stream_bit	*bit;

	bit = knc_alloc_stream_bit(len);
	if (!bit)
		return -1;

	memcpy(bit->buf, buf, len);
	bit->len = len;

	return knc_append_stream_bit(s, bit);
}

static int
knc_put_stream_gssbuf(struct knc_stream *s, gss_buffer_t buf)
{
	struct knc_stream_bit	*bit;

	bit = calloc(1, sizeof(*bit));
	if (!bit)
		return -1;

	bit->buf           = buf->value;
	bit->len           = buf->length;

	/*
	 * XXXrcd: cheesy, we populate a gss buffer so that we can
	 *         later deallocate it...
	 */

	bit->gssbuf.value  = buf->value;
	bit->gssbuf.length = buf->length;

	return knc_append_stream_bit(s, bit);
}

static int
knc_get_istream(struct knc_stream *s, void **buf, size_t len)
{
	struct knc_stream_bit	*tmp;

	if (!s) {
		/* XXXrcd: better errors... */
		return -1;
	}

	tmp = knc_alloc_stream_bit(len);
	if (!tmp)
		return -1;

	knc_append_stream_bit(s, tmp);

	*buf = tmp->buf;
	return tmp->allocated;
}

/*
 * knc_get_ostream specifically only returns a single knc_stream_bit.
 * knc_get_ostream returns a ptr into its data structure, the caller
 * may not modify it.  This allows the caller to construct an iovec
 * for writing.
 */

static ssize_t
knc_get_ostream(struct knc_stream *s, void **buf, size_t len)
{

	if (!s || !s->cur) {
		/* XXXrcd: better errors... */
		return -1;
	}

	DEBUG(("knc_get_ostream: s->cur = %p\n", s->cur));

	/* XXXrcd: hmmm, what if bufpos moves us beyond the stream? */

	*buf = (char *)s->cur->buf + s->bufpos;
	if (s->cur->len >= s->bufpos)
		len = MIN(len, s->cur->len - s->bufpos);

	return len;
}

static ssize_t
knc_get_ostreamv(struct knc_stream *s, struct iovec **vec, size_t *count)
{
	struct knc_stream_bit	*cur;
	size_t			 i;
	size_t			 len;

	if (!s || !s->cur) {
		/* XXXrcd: better errors... */
		return -1;
	}

	/* First we count the bits. */

	i = 0;
	for (cur = s->cur; cur; cur = cur->next)
		/* XXXrcd: test length and all of that? */
		i++;

	*vec = malloc(i * sizeof(**vec));
	if (!*vec) {
		/* XXXrcd: better errors... */
		return -2;
	}

	i = 0;
	len = 0;
	cur = s->cur;

	(*vec)[i  ].iov_base = (char *)cur->buf + s->bufpos;
	(*vec)[i++].iov_len  = cur->len - s->bufpos;
	len += cur->len - s->bufpos;
	DEBUG(("creating iovec element of length %zu, total %zu\n",
	    len, len));

	for (cur = cur->next; cur; cur = cur->next) {
		(*vec)[i  ].iov_base = cur->buf;
		(*vec)[i++].iov_len  = cur->len;
		len += cur->len;
		DEBUG(("creating iovec element of length %zu, "
		    "total %zu\n", cur->len, len));
	}

	*count = i;
	knc_stream_put_trash(s, *vec);

	return len;
}

/*
 * knc_get_ostream_contig() will fetch an entire contiguous newly allocated
 * buffer of the desired length, if it exists.  This may involve copying, but
 * it may not.  The caller is still not allowed to either modify or free(3)
 * the returned buffer.
 */

static ssize_t
knc_get_ostream_contig(struct knc_stream *s, void **buf, size_t len)
{
	struct knc_stream_bit	*cur;
	size_t			 retlen;
	size_t			 tmplen;

	/* We only bother if we're going to return the requested amount. */

	if (knc_stream_avail(s) < len)
		return -1;

	/* First, let's see if we have a single bit that fills this up. */

	tmplen = knc_get_ostream(s, buf, len);
	if (tmplen == len)
		return len;

	/* Okay, we're going to have to allocate here. */

	*buf = malloc(len);
	if (*buf == NULL)
		return -1;
	knc_stream_put_trash(s, *buf);

	retlen = 0;
	cur = s->cur;

	retlen = cur->len - s->bufpos;
	memcpy(*buf, (char *)cur->buf + s->bufpos, retlen);
	cur = cur->next;

	while (retlen < len) {
		tmplen = MIN(len - retlen, cur->len);
		memcpy((char *)*buf + retlen, cur->buf, tmplen);

		cur = cur->next;
		retlen += tmplen;
	}

	return retlen;
}

static ssize_t
knc_stream_drain(struct knc_stream *s, size_t len)
{

	DEBUG(("knc_stream_drain called with %zu\n", len));

	if (!s->cur)
		return -1;

	/* XXXrcd: sanity */
	DEBUG(("knc_stream_drain(%zu) start: s->cur=%p, avail=%zu bufpos=%zu\n",
	    len, s->cur, s->avail, s->bufpos));

	s->avail  -= len;
	s->bufpos += len;

	while (s->bufpos >= s->cur->len) {
		s->bufpos -= s->cur->len;
		s->cur = s->cur->next;

		if (!s->cur) {
			s->avail = 0;
			s->bufpos = 0;
			break;
		}
	}

	DEBUG(("knc_stream_drain end: s->cur = %p\n", s->cur));

	return len;
}

static ssize_t
knc_stream_fill(struct knc_stream *s, size_t len)
{

	/* XXXrcd: perform sanity */

	if (!s->cur || !s->tail)
		return -1;

	/* We do not have room. */
	if (s->tail->allocated < s->tail->len + len)
		/* XXXrcd: better errors here! */
		return -1;

	s->avail     += len;
	s->tail->len += len;

	return len;
}

static size_t
knc_stream_avail(struct knc_stream *s)
{

	return s->avail;
}

static int
knc_stream_put_trash(struct knc_stream *s, void *ptr)
{
	struct knc_stream_gc	*tmp;

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		/* XXXrcd: ??? */
		return -1;

	tmp->ptr = ptr;
	tmp->next = s->garbage;
	s->garbage = tmp;

	return 0;
}

/*
 * knc_stream_garbage_collect is provided because knc_get_ostream does
 * not actually deallocate the memory that is associated with it.
 * knc_clean_buf() will deallocate all memory between head and cur.
 */

static void
knc_stream_garbage_collect(struct knc_stream *s)
{
	struct knc_stream_bit	*tmpbit;
	struct knc_stream_gc	*gc;
	struct knc_stream_gc	*tmpgc;
	OM_uint32		 min;

	if (!s)
		return;

	while (s->head && s->head != s->cur) {
		tmpbit = s->head->next;

		if (s->head->gssbuf.value)
			gss_release_buffer(&min, &s->head->gssbuf);
		else
			free(s->head->buf);

		free(s->head);
		s->head = tmpbit;
	}

	if (!s->head)
		s->tail = s->cur = NULL;

	/* Clean up the refuse that has been allocated */

	for (gc = s->garbage; gc; ) {
		tmpgc = gc;
		gc = gc->next;
		free(tmpgc->ptr);
		free(tmpgc);
	}

	s->garbage = NULL;
}

static ssize_t
read_packet(struct knc_stream *s, void **buf)
{
	uint32_t len;
	void	*tmp;

	DEBUG(("read_packet: enter\n"));
	if (knc_stream_avail(s) < 4)
		return -1;

	DEBUG(("read_packet: 4 bytes are available\n"));
	knc_get_ostream_contig(s, &tmp, 4);
	len = ntohl(*((uint32_t *)tmp));

	DEBUG(("read_packet: got len = %u\n", len));
	if (knc_stream_avail(s) < (size_t)len + 4)
		return -1;

	knc_stream_drain(s, 4);

	/* Okay, now we know that we've got an entire packet */

	DEBUG(("read_packet: getting %u bytes\n", len));
	len = knc_get_ostream_contig(s, buf, len);
	knc_stream_drain(s, len);

	/* XXXrcd: broken, I think. */

	return len;
}

static ssize_t
put_packet(struct knc_stream *s, gss_buffer_t buf)
{
	uint32_t	netlen;

	netlen = htonl((uint32_t)buf->length);
	knc_put_stream(s, &netlen, 4);
	knc_put_stream_gssbuf(s, buf);

	/* XXXrcd: useful to return this?  What about errors? */
	return 0;
}

struct knc_ctx *
knc_ctx_init(void)
{

	return calloc(1, sizeof(struct knc_ctx));
}

void
knc_set_debug(struct knc_ctx *ctx, int setting)
{

	/* XXXrcd: Arg, global var. */
	debug = setting;
}

void
knc_ctx_close(struct knc_ctx *ctx)
{
	OM_uint32	min;

	if (ctx->gssctx)
		gss_delete_sec_context(&min, &ctx->gssctx, GSS_C_NO_BUFFER);

	/*
	 * XXXrcd: memory leaks:
	 *	ctx->client
	 *	ctx->server
	 */

	free(ctx->errstr);

	knc_destroy_stream(&ctx->raw_recv);
	knc_destroy_stream(&ctx->cooked_recv);
	knc_destroy_stream(&ctx->raw_send);
	knc_destroy_stream(&ctx->cooked_send);

	free(ctx);
}

int
knc_error(struct knc_ctx *ctx)
{

	return ctx->error;
}

const char *
knc_errstr(struct knc_ctx *ctx)
{

	if (!ctx->error)
		return NULL;

	if (ctx->errstr)
		return ctx->errstr;

	return "Could not allocate memory to report error, malloc(3) failed.";
}

struct knc_ctx *
knc_accept(const char *service, const char *hostname)
{
	struct knc_ctx	*ctx;

	ctx = knc_ctx_init();
	if (!ctx)
		return NULL;

	ctx->gssctx = GSS_C_NO_CONTEXT;
	ctx->state  = STATE_ACCEPT;

	return ctx;
}

struct knc_ctx *
knc_accept_fd(const char *service, const char *hostname, int fd)
{
	struct knc_ctx	*ctx;

	ctx = knc_accept(service, hostname);
	if (!ctx)
		return NULL;

	ctx->netread   = read;
	ctx->netwritev = writev;
	ctx->netclose  = close;
	ctx->net_fd    = fd;

	return ctx;
}

static int
knc_state_init(struct knc_ctx *ctx, void *buf, size_t len)
{
	gss_buffer_desc	in;
	gss_buffer_desc	out;
	OM_uint32	maj;
	OM_uint32	min;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	DEBUG(("knc_state_init: enter\n"));
	maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx->gssctx,
	    ctx->server, GSS_C_NO_OID,
	    GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG, 0,
	    GSS_C_NO_CHANNEL_BINDINGS, &in, NULL, &out, NULL, NULL);

	/* XXXrcd: better error handling... */
	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_init_sec_context");

	if (out.length > 0) {
		/* XXXrcd: memory management? */
		put_packet(&ctx->cooked_send, &out);
	}

	if (!(maj & GSS_S_CONTINUE_NEEDED))
		ctx->state = STATE_SESSION;

	return 0;
}

static int
knc_state_accept(struct knc_ctx *ctx, void *buf, size_t len)
{
	gss_buffer_desc	 in;
	gss_buffer_desc	 out;
	OM_uint32	 maj;
	OM_uint32	 min;

	/* Sanity, probably unnecessary */
	if (ctx->state != STATE_ACCEPT)
		return -1;

	DEBUG(("knc_state_accept: enter\n"));
	/* XXXrcd: ERRORS! */

	out.length = 0;

	in.value  = buf;
	in.length = len;

	maj = gss_accept_sec_context(&min, &ctx->gssctx, GSS_C_NO_CREDENTIAL,
	    &in, GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, NULL, &out, NULL,
	    NULL, NULL);

	/* XXXrcd: better error handling... */
	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_accept_sec_context");

	if (out.length) {
		/*
		 * XXXrcd: cheesy, knc will later free out.value which is
		 * actually acceptable in MIT krb5...  But the code is not
		 * correct as we should not assume that out.value has been
		 * allocated in a particular way.  We save a copy this way,
		 * though.
		 */
		put_packet(&ctx->cooked_send, &out);
		/* XXXrcd: ERRORS?!? */
	}

	if (!(maj & GSS_S_CONTINUE_NEEDED))
		ctx->state = STATE_SESSION;

	/* XXXrcd: free our buffer... */

	return 0;	/* XXXrcd: ERRORS */
}

static int
knc_state_session(struct knc_ctx *ctx, void *buf, size_t len)
{
	gss_buffer_desc	in;
	gss_buffer_desc	out;
	OM_uint32	maj;
	OM_uint32	min;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	DEBUG(("knc_state_session: enter\n"));
	maj = gss_unwrap(&min, ctx->gssctx, &in, &out, NULL, NULL);

	/* XXXrcd: better error handling... */
	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_unwrap");

	knc_put_stream_gssbuf(&ctx->cooked_recv, &out);

	return 0;
}

static int
knc_state_process_in(struct knc_ctx *ctx)
{
	void	*buf;
	ssize_t	 len;
	int	 ret;

	DEBUG(("knc_state_process_in: enter\n"));

	/*
	 * We have two main flows in which we are interested, input
	 * and output.  So, we check to see what is on each queue and
	 * if we can make progress.
	 *
	 * First we process the read side.  Let's see if we have a
	 * packet.
	 */

	for (;;) {
		len = read_packet(&ctx->raw_recv, &buf);

		DEBUG(("read_packet returned %zd\n", len));

		if (len < 1)	/* XXXrcd: How about 0? */
			return 0;

		switch (ctx->state) {
		case STATE_ACCEPT:
			ret = knc_state_accept(ctx, buf, len);
			break;
		case STATE_INIT:
			ret = knc_state_init(ctx, buf, len);
			break;
		case STATE_SESSION:
			ret = knc_state_session(ctx, buf, len);
			break;
		default:		
			ret = -1;
			break;
		}

		/* XXXrcd: errors and the like? */

	}

	return 0;
}

static int
knc_state_process_out(struct knc_ctx *ctx)
{
	gss_buffer_desc	 in;
	gss_buffer_desc	 out;
	OM_uint32	 maj;
	OM_uint32	 min;
	ssize_t		 len;
	void		*buf;

	DEBUG(("knc_state_process_out: enter\n"));

	/*
	 * We only process our out buffer if we have established the
	 * GSSAPI connexion because the handshake routines write directly
	 * to ctx->cooked_send.
	 */

	if (ctx->state != STATE_SESSION)
		return 0;

	for (;;) {

		/*
		 * We clip the length at KNC_MAXPACKETCONTENTS to make
		 * the job of the receiver easier.
		 */

		len = knc_get_ostream(&ctx->raw_send, &buf,
		    KNC_MAXPACKETCONTENTS);

		if (len < 1) {
			/* XXXrcd: ERRORS? Maybe there aren't any...? */
			return 0;
		}

		in.length = len;
		in.value  = buf;
		maj = gss_wrap(&min, ctx->gssctx, 1, GSS_C_QOP_DEFAULT,
		    &in, NULL, &out);

		/* XXXrcd: deal with this... */
		KNC_GSS_ERROR(ctx, maj, min, -1, "gss_wrap");

		/* XXXrcd: memory allocation? */
		put_packet(&ctx->cooked_send, &out);

		knc_stream_drain(&ctx->raw_send, len);


		/* XXXrcd: should we continue? */
	}

	DEBUG(("knc_state_process_out: leave\n"));

	return 0;
}

/*
 * State session simply moves things between the streams as much as
 * possible.
 */

static int
knc_state_process(struct knc_ctx *ctx)
{

	DEBUG(("knc_state_process: enter\n"));

	knc_state_process_in(ctx);
	knc_state_process_out(ctx);

	DEBUG(("knc_state_process: leave\n"));

	return 0;
}

#define KNC_SIDE_IN	0x100
#define KNC_SIDE_OUT	0x200

static struct knc_stream *
knc_find_buf(struct knc_ctx *ctx, int side, int dir)
{
	struct knc_stream	*s;

	switch (side | dir) {
	case KNC_DIR_RECV|KNC_SIDE_OUT:
		s = &ctx->cooked_recv;
		break;
	case KNC_DIR_RECV|KNC_SIDE_IN:
		s = &ctx->raw_recv;
		break;
	case KNC_DIR_SEND|KNC_SIDE_OUT:
		s = &ctx->cooked_send;
		break;
	case KNC_DIR_SEND|KNC_SIDE_IN:
		s = &ctx->raw_send;
		break;
	default:
		/* XXXrcd: huh? Maybe this should be abort()? */
		s = NULL;
		break;
	}

	return s;
}

int
knc_put_buf(struct knc_ctx *ctx, int dir, const void *buf, size_t len)
{

	return knc_put_stream(knc_find_buf(ctx, KNC_SIDE_IN, dir), buf, len);
}

int
knc_get_ibuf(struct knc_ctx *ctx, int dir, void **buf, size_t len)
{

	return knc_get_istream(knc_find_buf(ctx, KNC_SIDE_IN, dir) , buf, len);
}

int
knc_get_obuf(struct knc_ctx *ctx, int dir, void **buf, size_t len)
{

	return knc_get_ostream(knc_find_buf(ctx, KNC_SIDE_OUT, dir) , buf, len);
}

int
knc_get_obufv(struct knc_ctx *ctx, int dir, struct iovec **vec, size_t *count)
{

	return knc_get_ostreamv(knc_find_buf(ctx,KNC_SIDE_OUT,dir), vec, count);
}

int
knc_drain_buf(struct knc_ctx *ctx, int dir, int len)
{

	return knc_stream_drain(knc_find_buf(ctx, KNC_SIDE_OUT, dir), len);
}

int
knc_fill_buf(struct knc_ctx *ctx, int dir, int len)
{

	return knc_stream_fill(knc_find_buf(ctx, KNC_SIDE_IN, dir), len);
}

int
knc_avail_buf(struct knc_ctx *ctx, int dir)
{
	int	ret;

//	if (ctx->state != STATE_SESSION)
//		return 0;

	ret  = knc_stream_avail(knc_find_buf(ctx, KNC_SIDE_OUT, dir));
	ret += knc_stream_avail(knc_find_buf(ctx, KNC_SIDE_IN,  dir));

	return ret;
}

struct knc_ctx *
knc_initiate(const char *service, const char *hostname)
{
	struct knc_ctx	*ctx;
	gss_buffer_desc	 name;
	gss_name_t	 server;
	OM_uint32	 maj, min;
	char		 tmp[] = "";

	/*
	 * XXXrcd: we should reorganise the whole thing a bit to ease cleanup.
	 */

	ctx = knc_ctx_init();
	/* XXXrcd: errors... */

	name.length = strlen(service) + strlen(hostname) + 1;
	name.value = malloc(name.length + 1);
	if (!name.value) {
		/* XXXrcd: destroy my context? */
		return NULL;
	}

	snprintf(name.value, name.length + 1, "%s@%s", service, hostname);

	DEBUG(("going to get tickets for: %s", (char *)name.value));

	maj = gss_import_name(&min, &name, GSS_C_NT_HOSTBASED_SERVICE, &server);

	/* XXXrcd: L4M3! */
	KNC_GSS_ERROR(ctx, maj, min, NULL, "gss_import_name");

	ctx->gssctx = GSS_C_NO_CONTEXT;
	ctx->server = server;
	ctx->state  = STATE_INIT;

	/* Do we have to run init here?  Probably, we do... */
	knc_state_init(ctx, tmp, 0);

	return ctx;
}


static int
connect_host(const char *domain, const char *service)
{
	struct	addrinfo ai, *res, *res0;
	int	ret;
	int	s = -1;

	DEBUG(("connecting to (%s, %s)", service, domain));
	memset(&ai, 0x0, sizeof(ai));
	ai.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(domain, service, &ai, &res0);
	if (ret) {
		DEBUG(("getaddrinfo: (%s,%s) %s", domain, service,
		    gai_strerror(ret)));
		return -1;
	}
	for (res=res0; res; res=res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			DEBUG(("connect: %s", strerror(errno)));
			continue;
		}
		ret = connect(s, res->ai_addr, res->ai_addrlen);
		if (ret != -1)
			break;
		close(s);
		s = -1;
		DEBUG(("connect: %s", strerror(errno)));
	}

	freeaddrinfo(res0);
	return s;
}

/* The Easy Interfaces */

void
knc_garbage_collect(struct knc_ctx *ctx)
{

	if (!ctx)
		return;

	knc_stream_garbage_collect(&ctx->raw_recv);
	knc_stream_garbage_collect(&ctx->raw_send);
	knc_stream_garbage_collect(&ctx->cooked_recv);
	knc_stream_garbage_collect(&ctx->cooked_send);
}

int
knc_get_net_fd(struct knc_ctx *ctx)
{

	return ctx->net_fd;
}

int
knc_get_local_fd(struct knc_ctx *ctx)
{

	return ctx->local_fd;
}

struct knc_ctx *
knc_init_fd(const char *service, const char *hostname, int fd)
{
	struct knc_ctx	*ctx;

	ctx = knc_initiate(service, hostname);

	ctx->netread   = read;
	ctx->netwritev = writev;
	ctx->netclose  = close;
	ctx->net_fd    = fd;

	return ctx;
}

void
knc_set_local_fd(struct knc_ctx *ctx, int fd)
{

	ctx->localread   = read;
	ctx->localwritev = writev;
	ctx->localclose  = close;

	ctx->local_fd = fd;
}

struct knc_ctx *
knc_connect(const char *service, const char *hostname, const char *port)
{
	int		 fd;

	fd = connect_host(hostname, port);
	if (fd == -1)
		return NULL;

	return knc_init_fd(service, hostname, fd);
}

/*
 * The full requirement here is service@host:port.  We provide no defaults
 * as of yet...
 *
 * XXXrcd: provide defaults.
 */

struct knc_ctx *
knc_connect_parse(const char *hostservice, int opts)
{
	char	*host;
	char	*service;
	char	*port;

	service = strdup(hostservice);
	if (!service)
		return NULL;

	host = strchr(service, '@');
	if (!host)
		goto out;
	*host++ = '\0';

	port = strchr(host, ':');
	if (!port)
		goto out;
	*port++ = '\0';

	free(service);
	return knc_connect(service, host, port);
out:
	errno = EINVAL;
	free(service);
	return NULL;
}

int
knc_fill(struct knc_ctx *ctx, int dir)
{
	ssize_t	 ret;
	void	*tmpbuf;

	/* XXXrcd: deal properly with EOF */
	if (ctx->net_fd == -1)
		return -1;

	/* XXXrcd: hardcoded constant */
	ret = knc_get_ibuf(ctx, dir, &tmpbuf, 128 * 1024);

	DEBUG(("knc_fill: about to read %zd bytes.\n", ret));

	if (dir == KNC_DIR_RECV)
		ret = (ctx->netread)(ctx->net_fd, tmpbuf, ret);
	else
		ret = (ctx->localread)(ctx->local_fd, tmpbuf, ret);

	if (ret == -1) {
		DEBUG(("read error: %s\n", strerror(errno)));
		/* XXXrcd: errors... */

		if (errno == EINTR || errno == EAGAIN) {
			return -1;
		}

		/*
		 * XXXrcd: Other possible errors:
		 *
		 *	EPIPE
		 *	ECONNRESET
		 *	ENETRESET
		 *	ECONNABORTED
		 *	ENOBUFS
		 *
		 * These should be considered.
		 *
		 * For now, we simply bail on anything that we do not
		 * explicitly recognise.
		 */

		ctx->net_fd = -1;
		knc_syscall_error(ctx, errno);

		return -1;
	}

	if (ret == 0) {
		/* XXXrcd: EOF, hmmmm.... */
		DEBUG(("knc_fill: got EOF\n"));
		ctx->net_fd = -1;
	}

	if (ret > 0) {
		DEBUG(("Read %zd bytes\n", ret));
		knc_fill_buf(ctx, dir, ret);
	}

	return knc_state_process(ctx);
}

ssize_t
knc_read(struct knc_ctx *ctx, void *buf, size_t len)
{
	ssize_t	 ret;
	void	*tmpbuf;

	DEBUG(("knc_read: about to read.\n"));

	knc_fill(ctx, KNC_DIR_RECV);

	ret = knc_get_obuf(ctx, KNC_DIR_RECV, &tmpbuf, len);
	if (ret > 0) {
		memcpy(buf, tmpbuf, ret);
		knc_drain_buf(ctx, KNC_DIR_RECV, ret);
		return ret;
	}

	return ret;
}

/* XXXrcd: USE THE WRITEV INTERFACE, IT IS MORE EFFICIENT */
#if 0
int
knc_flush(struct knc_ctx *ctx, int dir)
{
	struct iovec	*vec;
	int		 count;
	int		 len;
	int		 ret;

	len = knc_get_obufv(ctx, dir, &vec, &count);

	DEBUG(("knc_flush: knc_get_obufv returned %d bytes.\n", len));

	/* XXXrcd: deal with errors */
	if (len < 1)
		return 0;

	ret = (ctx->netwritev)(ctx->net_fd, vec, count);

	/* XXXrcd: errors */

	DEBUG(("knc_flush: wrote %d bytes, attempted %d bytes.\n",
	    ret, len));

	if (ret < 1)
		return ret;

	knc_drain_buf(ctx, dir, ret);
}

#else
int
knc_flush(struct knc_ctx *ctx, int dir)
{
	ssize_t		 len;
	void		*buf;

//	for (;;) {
		len = knc_get_obuf(ctx, KNC_DIR_SEND, &buf, 16384);
		if (len <= 0)
			return 0;
//			break;
		DEBUG(("knc_flush: about to write %zu bytes.\n", len));

#if 0
		vec[0].iov_base = buf;
		vec[0].iov_len  = len;

		len = (ctx->netwritev)(ctx->net_fd, vec, 1);
#else
		len = write(ctx->net_fd, buf, len);
#endif

		if (len < 0) {
			DEBUG(("write error: %s\n", strerror(errno)));

			if (errno == EINTR || errno == EAGAIN) {
				return -1;
			}

			/*
			 * XXXrcd: Other possible errors:
			 *
			 *	EPIPE
			 *	ECONNRESET
			 *	ENETRESET
			 *	ECONNABORTED
			 *	ENOBUFS
			 *
			 * These should be considered.
			 *
			 * For now, we simply bail on anything that we do not
			 * explicitly recognise.
			 */

			ctx->net_fd = -1;
			knc_syscall_error(ctx, errno);

			return -1;
		}

		DEBUG(("knc_flush: wrote %zd bytes.\n", len));
		knc_drain_buf(ctx, KNC_DIR_SEND, len);
//	}

	/* XXXrcd: ERRORS??!? */

	return 0;
}
#endif

ssize_t
knc_write(struct knc_ctx *ctx, const void *buf, size_t len)
{
	ssize_t	ret;

	ret = knc_put_buf(ctx, KNC_DIR_SEND, buf, len);
	knc_state_process(ctx);

	knc_flush(ctx, KNC_DIR_SEND);

	return ret;
}


/* XXXrcd: review this code against gssstdio.c! */

static int
knc_errstring(char **str, int min_stat)
{
	gss_buffer_desc	 status;
	OM_uint32	 new_stat;
	OM_uint32	 msg_ctx = 0;
	OM_uint32	 ret;
	int		 len = 0;
	char		*tmp;
	char		*statstr;

	/* XXXrcd this is not correct yet */
	/* XXXwps ...and now it is. */

	if (!str)
		return -1;

	*str = NULL;
	tmp = NULL;

	do {
		ret = gss_display_status(&new_stat, min_stat,
		    GSS_C_MECH_CODE, GSS_C_NO_OID, &msg_ctx,
		    &status);

		/* GSSAPI strings are not NUL terminated */
		if ((statstr = (char *)malloc(status.length + 1)) == NULL) {
			DEBUG(("unable to malloc status string of length %ld",
			    status.length));
			gss_release_buffer(&new_stat, &status);
			free(statstr);
			free(tmp);
			return 0;
		}

		memcpy(statstr, status.value, status.length);
		statstr[status.length] = '\0';

		if (GSS_ERROR(ret)) {
			free(statstr);
			free(tmp);
			break;
		}

		if (*str) {
/* XXXrcd: memory leak? */
			if ((*str = malloc(strlen(*str) + status.length +
					   3)) == NULL) {
				DEBUG(("unable to malloc error string"));
				gss_release_buffer(&new_stat, &status);
				free(statstr);
				free(tmp);
				return 0;
			}

			len = sprintf(*str, "%s, %s", tmp, statstr);
		} else {
			*str = malloc(status.length + 1);
			len = sprintf(*str, "%s", (char *)statstr);
		}

		gss_release_buffer(&new_stat, &status);
		free(statstr);
		free(tmp);

		tmp = *str;
	} while (msg_ctx != 0);

	return len;
}

static void
knc_syscall_error(struct knc_ctx *ctx, int errorno)
{

	/* XXXrcd: wrong type */
	ctx->error = KNC_ERROR_GSS;
	ctx->errstr = strdup(strerror(errorno));
}

static void
knc_gss_error(struct knc_ctx *ctx, int maj_stat, int min_stat, const char *s)
{

	ctx->error = KNC_ERROR_GSS;
	if (knc_errstring(&ctx->errstr, min_stat) < 1) {
		ctx->errstr = strdup("Failed to construct GSS error");
	}
	DEBUG(("knc_gss_error: %s\n", ctx->errstr));
}
