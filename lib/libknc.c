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

#include <sys/mman.h>
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
	void			 *buf;
	void			(*free)(void *, void *);
	void			 *cookie;
	struct knc_stream_bit	 *next;
	size_t			  len;
	size_t			  allocated;
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
	gss_cred_id_t		 cred;		/* both */
	gss_channel_bindings_t	 cb;		/* both */
	gss_OID			 req_mech;	/* request mech (initiator) */
	gss_OID			 ret_mech;	/* returned mech (both) */
	gss_name_t		 client;	/* only set for an acceptor */
	gss_name_t		 service;	/* only set for an initiator */
	OM_uint32		 req_flags;	/* initiator */
	OM_uint32		 ret_flags;	/* both */
	OM_uint32		 time_req;	/* initiator */
	OM_uint32		 time_rec;	/* both */
	gss_cred_id_t		 deleg_cred;	/* acceptor */
	int			 open;
#define OPEN_READ	0x10
#define OPEN_WRITE	0x20
	int			 state;
#define STATE_UNKNOWN	0x0
#define STATE_ACCEPT	0x1
#define STATE_INIT	0x2
#define STATE_SESSION	0x3
#define STATE_COMMAND	0x4
	int			 error;
	int			 debug;
#define KNC_ERROR_GSS	0x1
#define KNC_ERROR_PROTO	0x2
#define KNC_ERROR_RST	0x3
#define KNC_ERROR_PIPE	0x4
	char			*errstr;

	size_t			 recvinbufsiz;
	size_t			 sendinbufsiz;
	struct knc_stream	 raw_recv;
	struct knc_stream	 cooked_recv;
	struct knc_stream	 raw_send;
	struct knc_stream	 cooked_send;

	/*
	 * These are the read/write/close functions, they will be executed
	 * at the correct time by the code if they are defined.  If they
	 * are not defined, they will not be executed.
	 */

	int	  net_uses_fd;
	int	  net_is_open;
	void	 *netcookie;
	ssize_t	(*netread)(void *, void *, size_t);
	ssize_t	(*netwritev)(void *, const struct iovec *, int);
	int	(*netclose)(void *);

	int	  local_uses_fd;
	int	  local_is_open;
	void	 *localcookie;
	ssize_t	(*localread)(void *, void *, size_t);
	ssize_t	(*localwritev)(void *, const struct iovec *, int);
	int	(*localclose)(void *);
};

struct fd_cookie {
	int	mine;
	int	rfd;
	int	wfd;
};

/* mmm, macros. */

#define KNC_GSS_ERROR(_ctx, _maj, _min, _ret, _str) do {		\
		if (GSS_ERROR((_maj))) {				\
			knc_gss_error((_ctx), (_maj), (_min), (_str));	\
			return _ret;					\
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

static void	knc_generic_error(knc_ctx, const char *);
static void	knc_syscall_error(knc_ctx, const char *, int);
static void	knc_gss_error(knc_ctx, OM_uint32, OM_uint32, const char *);

static struct knc_stream_bit	*knc_alloc_stream_bit(size_t);
static size_t			 knc_append_stream_bit(struct knc_stream *,
				    struct knc_stream_bit *);

static int	knc_put_stream(struct knc_stream *, const void *, size_t);
static int	knc_put_stream_gssbuf(struct knc_stream *, gss_buffer_t);
static int	knc_get_istream(struct knc_stream *, void **, size_t);
static ssize_t	knc_get_ostream(struct knc_stream *, void **, size_t);
static ssize_t	knc_get_ostreamv(struct knc_stream *, struct iovec **, int *);
static int	knc_stream_put_trash(struct knc_stream *, void *);
static ssize_t	knc_get_ostream_contig(struct knc_stream *, void **, size_t);
static ssize_t	knc_stream_drain(struct knc_stream *, size_t);
static ssize_t	knc_stream_fill(struct knc_stream *, size_t);
static size_t	knc_stream_avail(struct knc_stream *);
static void	knc_stream_garbage_collect(struct knc_stream *);

static ssize_t	read_packet(struct knc_stream *, void **b);
static ssize_t	put_packet(struct knc_stream *, gss_buffer_t);

static int	knc_state_init(knc_ctx, void *, size_t);
static int	knc_state_accept(knc_ctx, void *, size_t);
static int	knc_state_session(knc_ctx, void *, size_t);
static int	knc_state_command(knc_ctx, void *, size_t);
static int	knc_state_process_in(knc_ctx);
static int	knc_state_process_out(knc_ctx);
static int	knc_state_process(knc_ctx);

static struct knc_stream *knc_find_buf(knc_ctx, int, int);

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

#define STREAM_BIT_ALLOC_UNIT	(64 * 1024)

static struct knc_stream_bit *
knc_alloc_stream_bit(size_t len)
{
	struct knc_stream_bit	*bit;
	char			*tmpbuf;

	len  = len / STREAM_BIT_ALLOC_UNIT + (len % STREAM_BIT_ALLOC_UNIT)?1:0;
	len *= STREAM_BIT_ALLOC_UNIT;
	len  = MIN((2 * STREAM_BIT_ALLOC_UNIT), len);

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
knc_put_stream_userbuf(struct knc_stream *s, void *buf, size_t len,
		       void (*callback)(void *, void *), void *cookie)
{
	struct knc_stream_bit	*bit;

	bit = calloc(1, sizeof(*bit));
	if (!bit)
		return -1;

	bit->buf	= buf;
	bit->len	= len;
	bit->free	= callback;
	bit->cookie	= cookie;

	return knc_append_stream_bit(s, bit);
}

static void
free_gssbuf(void *buf, void *cookie)
{
	OM_uint32	maj;
	OM_uint32	min;

	maj = gss_release_buffer(&min, cookie);
	free(cookie);
}

static int
knc_put_stream_gssbuf(struct knc_stream *s, gss_buffer_t inbuf)
{
	gss_buffer_t	buf;

	buf = calloc(1, sizeof(*buf));
	if (!buf)
		return -1;

	buf->value  = inbuf->value;
	buf->length = inbuf->length;

	return knc_put_stream_userbuf(s, buf->value, buf->length, free_gssbuf,
	    buf);
}

struct mmapregion {
	void	*buf;
	size_t	 len;
};

static void
free_mmapbuf(void *buf, void *cookie)
{
	struct mmapregion	*r = cookie;

	munmap(r->buf, r->len);
	free(r);
}

static int
knc_put_stream_mmapbuf(struct knc_stream *s, size_t len, int flags, int fd,
		       off_t offset)
{
	struct mmapregion	*r;
	char			*buf;

	r = calloc(1, sizeof(*r));
	if (!r)
		return -1;

	r->buf = mmap(NULL, len, PROT_READ, flags, fd, offset);;
	r->len = len;

	if (!buf)
		return -1;

	return knc_put_stream_userbuf(s, r->buf, r->len, free_mmapbuf, r);
}

static int
knc_get_istream(struct knc_stream *s, void **buf, size_t len)
{
	struct knc_stream_bit	*tmp;

	if (!s) {
		/* XXXrcd: better errors... */
		return -1;
	}

	if (s->tail && s->tail->allocated - s->tail->len > len) {
		*buf = (void *)((char *)s->tail->buf + s->tail->len);
		return s->tail->allocated - s->tail->len;
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
knc_get_ostreamv(struct knc_stream *s, struct iovec **vec, int *count)
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

	if (!s)
		return;

	while (s->head && s->head != s->cur) {
		tmpbit = s->head->next;

		if (s->head->free)
			s->head->free(s->head->buf, s->head->cookie);
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

knc_ctx
knc_ctx_init(void)
{
	knc_ctx	ret;

	ret = calloc(1, sizeof(*ret));

	/* Set some reasonable defaults */

	ret->gssctx	= GSS_C_NO_CONTEXT;
	ret->client	= GSS_C_NO_NAME;
	ret->cred	= GSS_C_NO_CREDENTIAL;
	ret->cb		= GSS_C_NO_CHANNEL_BINDINGS;
	ret->req_mech   = GSS_C_NO_OID;
	ret->ret_mech   = GSS_C_NO_OID;
	ret->req_flags  = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;
	ret->deleg_cred = GSS_C_NO_CREDENTIAL;

	ret->open = OPEN_READ|OPEN_WRITE;

	ret->recvinbufsiz = 16384;
	ret->sendinbufsiz = 16384;

	return ret;
}

void
knc_set_debug(knc_ctx ctx, int setting)
{

	/* XXXrcd: Arg, global var. */
	debug = setting;
}

void
knc_ctx_close(knc_ctx ctx)
{
	OM_uint32	min;

	if (ctx->cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&min, &ctx->cred);

	if (ctx->deleg_cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&min, &ctx->deleg_cred);

	if (ctx->service != GSS_C_NO_NAME)
		gss_release_name(&min, &ctx->service);

	if (ctx->gssctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &ctx->gssctx, GSS_C_NO_BUFFER);

#if 0
	if (ctx->cb != GSS_C_NO_CHANNEL_BINDINGS) {
		/* XXXrcd: hmmm, caller deals with this? */
	}
#endif

	if (ctx->net_is_open && ctx->netclose)
		(ctx->netclose)(ctx->netcookie);

	if (ctx->local_is_open && ctx->localclose)
		(ctx->localclose)(ctx->localcookie);

	/* XXXrcd: memory leaks?  */

	free(ctx->errstr);

	knc_destroy_stream(&ctx->raw_recv);
	knc_destroy_stream(&ctx->cooked_recv);
	knc_destroy_stream(&ctx->raw_send);
	knc_destroy_stream(&ctx->cooked_send);

	free(ctx);
}

int
knc_error(knc_ctx ctx)
{

	return ctx->error;
}

const char *
knc_errstr(knc_ctx ctx)
{

	if (!ctx->error)
		return NULL;

	if (ctx->errstr)
		return ctx->errstr;

	return "Could not allocate memory to report error, malloc(3) failed.";
}

int
knc_is_authenticated(knc_ctx ctx)
{

	return ctx->state == STATE_SESSION || ctx->state == STATE_COMMAND;
}

void
knc_set_cred(knc_ctx ctx, gss_cred_id_t cred)
{
	OM_uint32	min;

	if (ctx->cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&min, &ctx->cred);

	ctx->cred = cred;
}

void
knc_set_service(knc_ctx ctx, gss_name_t service)
{

	/* XXXrcd: sanity?  check if we are an initiator? */

	if (!ctx)
		return;

#if 0
	if (ctx->service)
		gss_release_name(...);	XXXrcd
#endif

	ctx->service = service;
}

void
knc_import_set_service(knc_ctx ctx, const char *service, const gss_OID nametype)
{
	gss_buffer_desc	 name;
	OM_uint32	 maj, min;

	/* XXXrcd: sanity?  check if we are an initiator? */

	name.length = strlen(service);
	name.value  = strdup(service);	/* strdup to avoid const lossage */

	if (!name.value) {
		knc_generic_error(ctx, "out of memory");
		return;
	}

	maj = gss_import_name(&min, &name, nametype, &ctx->service);

	free(name.value);

	/* ??? XXXrcd: L4M3! */
	KNC_GSS_ERROR(ctx, maj, min,, "gss_import_name");
}

void
knc_import_set_hb_service(knc_ctx ctx, const char *hostservice,
			  const char *defservice)
{
	char	*hbservice;
	char	*tmp;

	tmp = strchr(hostservice, '@');
	if (tmp) {
		knc_import_set_service(ctx, hostservice,
		    GSS_C_NT_HOSTBASED_SERVICE);
		return;
	}

	hbservice = malloc(strlen(hostservice) + strlen(defservice) + 2);
	if (!hbservice) {
		knc_generic_error(ctx, "out of memory");
		return;
	}

	sprintf(hbservice, "%s@%s", defservice, hostservice);

	knc_import_set_service(ctx, hbservice, GSS_C_NT_HOSTBASED_SERVICE);
	free(hbservice);
}

void
knc_set_cb(knc_ctx ctx, gss_channel_bindings_t cb)
{

	/* XXXrcd: caller frees? */

	ctx->cb = cb;
}

void
knc_set_req_mech(knc_ctx ctx, gss_OID req_mech)
{

	/* XXXrcd: memory management?? */

	ctx->req_mech = req_mech;
}

gss_OID
knc_get_ret_mech(knc_ctx ctx)
{
	/* XXXrcd: sanity */

	return ctx->ret_mech;
}

void
knc_set_req_flags(knc_ctx ctx, OM_uint32 req_flags)
{
	/* XXXrcd: sanity */

	ctx->req_flags = req_flags;
}

OM_uint32
knc_get_ret_flags(knc_ctx ctx)
{
	/* XXXrcd: sanity */

	return ctx->ret_flags;
}

void
knc_set_time_req(knc_ctx ctx, OM_uint32 time_req)
{
	/* XXXrcd: sanity */

	ctx->time_req = time_req;
}

OM_uint32
knc_get_time_rec(knc_ctx ctx)
{
	/* XXXrcd: sanity */

	return ctx->time_rec;
}

gss_name_t
knc_get_client(knc_ctx ctx)
{
	/* XXXrcd: sanity */

	return ctx->client;
}

gss_cred_id_t
knc_get_deleg_cred(knc_ctx ctx)
{
	/* XXXrcd: sanity */

	return ctx->deleg_cred;
}

/* XXXrcd: deal with all the flags */

void
knc_accept(knc_ctx ctx)
{

	/* XXXrcd: sanity! */

	ctx->gssctx = GSS_C_NO_CONTEXT;
	ctx->state  = STATE_ACCEPT;
}

static int
knc_state_init(knc_ctx ctx, void *buf, size_t len)
{
	gss_buffer_desc	in;
	gss_buffer_desc	out;
	OM_uint32	maj;
	OM_uint32	min;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	DEBUG(("knc_state_init: enter\n"));
	maj = gss_init_sec_context(&min, ctx->cred, &ctx->gssctx,
	    ctx->service, ctx->req_mech, ctx->req_flags, ctx->time_req,
	    ctx->cb, &in, &ctx->ret_mech, &out, &ctx->ret_flags,
	    &ctx->time_rec);

	if (out.length > 0) {
		/* XXXrcd: memory management? */
		put_packet(&ctx->cooked_send, &out);
	}

	/* XXXrcd: better error handling... */
	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_init_sec_context");

	if (!(maj & GSS_S_CONTINUE_NEEDED))
		ctx->state = STATE_SESSION;

	return 0;
}

static int
knc_state_accept(knc_ctx ctx, void *buf, size_t len)
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

	maj = gss_accept_sec_context(&min, &ctx->gssctx, ctx->cred, &in,
	    ctx->cb, &ctx->client, &ctx->ret_mech, &out,
	    &ctx->ret_flags, &ctx->time_rec, &ctx->deleg_cred);

	if (out.length) {
		put_packet(&ctx->cooked_send, &out);
		/* XXXrcd: ERRORS?!? */
	}

	/* XXXrcd: better error handling... */
	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_accept_sec_context");

	if (!(maj & GSS_S_CONTINUE_NEEDED))
		ctx->state = STATE_SESSION;

	/* XXXrcd: free our buffer... */

	return 0;	/* XXXrcd: ERRORS */
}

static int
knc_state_session(knc_ctx ctx, void *buf, size_t len)
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
	if (maj != GSS_S_COMPLETE) {
		knc_gss_error(ctx, maj, min, "gss_unwrap");
		return -1;
	}

	if (out.length == 0) {
		ctx->state = STATE_COMMAND;
		return 0;
	}

	knc_put_stream_gssbuf(&ctx->cooked_recv, &out);

	return 0;
}

static int
knc_state_command(knc_ctx ctx, void *buf, size_t len)
{
	gss_buffer_desc	in;
	gss_buffer_desc	out;
	OM_uint32	maj;
	OM_uint32	min;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	DEBUG(("knc_state_command: enter\n"));
	maj = gss_unwrap(&min, ctx->gssctx, &in, &out, NULL, NULL);

	/* XXXrcd: better error handling... */
	if (maj != GSS_S_COMPLETE) {
		knc_gss_error(ctx, maj, min, "gss_unwrap");
		return -1;
	}

	if (out.length == 0) {
		/* Close the stream for reading... */
		ctx->open &= ~(OPEN_READ|OPEN_WRITE);
	}

	/* XXXrcd: unknown command.  should we continue?  yes, for now. */

	ctx->state = STATE_SESSION;
	return 0;
}

static int
knc_state_process_in(knc_ctx ctx)
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
		case STATE_COMMAND:
			ret = knc_state_command(ctx, buf, len);
			break;
		default:
			ret = -1;
			break;
		}

		/* XXXrcd: errors and the like? */

	}

	return ret;
}

static int
knc_state_process_out(knc_ctx ctx)
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
knc_state_process(knc_ctx ctx)
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
knc_find_buf(knc_ctx ctx, int side, int dir)
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
knc_put_buf(knc_ctx ctx, int dir, const void *buf, size_t len)
{

	return knc_put_stream(knc_find_buf(ctx, KNC_SIDE_IN, dir), buf, len);
}

int
knc_put_ubuf(knc_ctx ctx, int dir, void *buf, size_t len,
	     void (*callback)(void *, void *), void *cookie)
{

	return knc_put_stream_userbuf(knc_find_buf(ctx, KNC_SIDE_IN, dir),
	    buf, len, callback, cookie);
}

int
knc_put_mmapbuf(knc_ctx ctx, int dir, size_t len, int flags, int fd,
		off_t offset)
{

	return knc_put_stream_mmapbuf(knc_find_buf(ctx, KNC_SIDE_IN, dir),
	    len, flags, fd, offset);
}

int
knc_get_ibuf(knc_ctx ctx, int dir, void **buf, size_t len)
{

	return knc_get_istream(knc_find_buf(ctx, KNC_SIDE_IN, dir), buf, len);
}

int
knc_get_obuf(knc_ctx ctx, int dir, void **buf, size_t len)
{

	return knc_get_ostream(knc_find_buf(ctx, KNC_SIDE_OUT, dir), buf, len);
}

int
knc_get_obufv(knc_ctx ctx, int dir, struct iovec **vec, int *count)
{

	return knc_get_ostreamv(knc_find_buf(ctx,KNC_SIDE_OUT,dir), vec, count);
}

int
knc_drain_buf(knc_ctx ctx, int dir, int len)
{

	return knc_stream_drain(knc_find_buf(ctx, KNC_SIDE_OUT, dir), len);
}

int
knc_fill_buf(knc_ctx ctx, int dir, int len)
{

	return knc_stream_fill(knc_find_buf(ctx, KNC_SIDE_IN, dir), len);
}

size_t
knc_pending(knc_ctx ctx, int dir)
{
	int	ret;

//	if (ctx->state != STATE_SESSION)
//		return 0;

	ret  = knc_stream_avail(knc_find_buf(ctx, KNC_SIDE_OUT, dir));
	ret += knc_stream_avail(knc_find_buf(ctx, KNC_SIDE_IN,  dir));

	return ret;
}

void
knc_initiate(knc_ctx ctx)
{
	char		 tmp[] = "";

	/* XXXrcd: sanity! */

#if 0	/* XXXrcd: this should go somewhere... */
	DEBUG(("going to get tickets for: %s", (char *)name.value));
#endif

	ctx->gssctx = GSS_C_NO_CONTEXT;
	ctx->state  = STATE_INIT;

	/* XXXrcd: Do we have to run init here?  Probably, we do... */
	knc_state_init(ctx, tmp, 0);
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
knc_garbage_collect(knc_ctx ctx)
{

	if (!ctx)
		return;

	knc_stream_garbage_collect(&ctx->raw_recv);
	knc_stream_garbage_collect(&ctx->raw_send);
	knc_stream_garbage_collect(&ctx->cooked_recv);
	knc_stream_garbage_collect(&ctx->cooked_send);
}

static ssize_t
fdread(void *cookie, void *buf, size_t len)
{
	int	fd = ((struct fd_cookie *)cookie)->rfd;

	return read(fd, buf, len);
}

static ssize_t
fdwritev(void *cookie, const struct iovec *iov, int iovcnt)
{
	int	fd = ((struct fd_cookie *)cookie)->wfd;

	return writev(fd, iov, iovcnt);
}

static int
fdclose(void *cookie)
{
	struct fd_cookie	*fdc = cookie;
	int			 rfd = fdc->rfd;
	int			 wfd = fdc->wfd;

	if (!fdc->mine)
		return 0;

	if (rfd != wfd)
		close(wfd);

	return close(rfd);
}

void
knc_set_net_fds(knc_ctx ctx, int rfd, int wfd)
{
	struct fd_cookie	*cookie;

	/* XXXrcd: should we look for existing read/writev/close? */

	cookie = malloc(sizeof(*cookie));
	/* XXXrcd: errors! */

	cookie->mine = 0;
	cookie->rfd  = rfd;
	cookie->wfd  = wfd;

	ctx->net_uses_fd = 1;
	ctx->net_is_open = 1;

	ctx->netcookie = cookie;
	ctx->netread   = fdread;
	ctx->netwritev = fdwritev;
	ctx->netclose  = fdclose;
}

void
knc_set_net_fd(knc_ctx ctx, int fd)
{

	knc_set_net_fds(ctx, fd, fd);
}

int
knc_get_net_rfd(knc_ctx ctx)
{

	if (ctx->net_uses_fd)
		return ((struct fd_cookie *)ctx->netcookie)->rfd;

	return -1;
}

int
knc_get_net_wfd(knc_ctx ctx)
{

	if (ctx->net_uses_fd)
		return ((struct fd_cookie *)ctx->netcookie)->wfd;

	return -1;
}

int
knc_net_is_open(knc_ctx ctx)
{

	return ctx->net_uses_fd && ctx->net_is_open;
}

void
knc_set_local_fds(knc_ctx ctx, int rfd, int wfd)
{
	struct fd_cookie	*cookie;

	/* XXXrcd: should we look for existing read/writev/close? */

	cookie = malloc(sizeof(*cookie));
	/* XXXrcd: errors! */

	cookie->mine = 0;
	cookie->rfd  = rfd;
	cookie->wfd  = wfd;

	ctx->local_uses_fd = 1;
	ctx->local_is_open = 1;

	ctx->localcookie = cookie;
	ctx->localread   = fdread;
	ctx->localwritev = fdwritev;
	ctx->localclose  = fdclose;
}

void
knc_set_local_fd(knc_ctx ctx, int fd)
{

	knc_set_local_fds(ctx, fd, fd);
}

int
knc_get_local_rfd(knc_ctx ctx)
{

	if (ctx->local_uses_fd)
		return ((struct fd_cookie *)ctx->localcookie)->rfd;

	return -1;
}

int
knc_get_local_wfd(knc_ctx ctx)
{

	if (ctx->local_uses_fd)
		return ((struct fd_cookie *)ctx->localcookie)->wfd;

	return -1;
}

int
knc_local_is_open(knc_ctx ctx)
{

	return ctx->local_uses_fd && ctx->local_is_open;
}

static void _fill_recv(knc_ctx ctx)  { knc_fill(ctx, KNC_DIR_RECV); }
static void _fill_send(knc_ctx ctx)  { knc_fill(ctx, KNC_DIR_SEND); }
static void _flush_send(knc_ctx ctx) { knc_flush(ctx, KNC_DIR_SEND, 0); }
static void _flush_recv(knc_ctx ctx) { knc_flush(ctx, KNC_DIR_RECV, 0); }

/* XXXrcd: bad macro, should be a parameter, eh? */
#define READBUFSIZEROOBOB	16384

nfds_t
knc_get_pollfds(knc_ctx ctx, struct pollfd *fds, knc_callback *cbs, nfds_t nfds)
{
	nfds_t	i = 0;

	if (ctx->net_uses_fd && ctx->net_is_open) {
		/* XXXrcd: check fd validity? */
		if (knc_pending(ctx, KNC_DIR_RECV) < ctx->recvinbufsiz) {
			cbs[i]		= _fill_recv;
			fds[i].fd	= knc_get_net_rfd(ctx);
			fds[i++].events	= POLLIN;
			if (i >= nfds)
				return -1;
		}

		/* XXXrcd: check fd validity? */
		if (knc_pending(ctx, KNC_DIR_SEND) > 0) {
			cbs[i]		= _flush_send;
			fds[i].fd	= knc_get_net_wfd(ctx);
			fds[i++].events = POLLOUT;
			if (i >= nfds)
				return -1;
		}
	}

	if (ctx->local_uses_fd && ctx->local_is_open) {
		/* XXXrcd: check fd validity? */
		if (knc_pending(ctx, KNC_DIR_SEND) < ctx->sendinbufsiz) {
			cbs[i]		= _fill_send;
			fds[i].fd	 = knc_get_local_rfd(ctx);
			fds[i++].events	 = POLLIN;
			if (i >= nfds)
				return -1;
		}

		/* XXXrcd: check fd validity? */
		if (knc_pending(ctx, KNC_DIR_RECV) > 0) {
			cbs[i]		= _flush_recv;
			fds[i].fd	 = knc_get_local_wfd(ctx);
			fds[i++].events	 = POLLOUT;
		}
	}

	return i;
}

void
knc_service_pollfds(knc_ctx ctx, struct pollfd *fds, knc_callback *cbs,
		    nfds_t nfds)
{
	size_t	i;

	for (i=0; i < nfds; i++) {
		short	revents = fds[i].revents;

		if (revents & (POLLIN|POLLOUT))
			cbs[i](ctx);

	}
}

/*
 * The full requirement here is service@host:port.  We provide no defaults
 * as of yet...
 *
 * XXXrcd: provide defaults.
 */

knc_ctx
knc_connect(knc_ctx ctx, const char *hostservice,
	    const char *defservice, const char *defport,
	    int opts)
{
	char		*buf;
	char		*tmp;
	const char	*service;
	const char	*host;
	const char	*port;
	int		 fd;

	if (!ctx)
		ctx = knc_ctx_init();

	if (!ctx)
		return NULL;

	buf = strdup(hostservice);
	if (!buf) {
		knc_generic_error(ctx, "out of memory");
		return ctx;
	}

	tmp = strchr(buf, '@');
	if (tmp) {
		service = buf;
		*tmp++ = '\0';
		host = tmp;
	} else {
		service = defservice;
		host = buf;
	}

	tmp = strchr(host, ':');
	if (tmp) {
		*tmp++ = '\0';
		port = tmp;
	} else {
		port = defport;
	}

	if (!port)
		port = service;

	/* XXXrcd: Hell's Bells, the above needs to be fixed. */

	knc_import_set_hb_service(ctx, host, service);

	fd = connect_host(host, port);
	if (fd == -1) {
		knc_syscall_error(ctx, "connect_host", errno);
		goto out;
	}

	knc_set_net_fd(ctx, fd);
	((struct fd_cookie *)ctx->netcookie)->mine = 1;
	knc_initiate(ctx);

out:
	free(buf);
	return ctx;
}

int
knc_fill(knc_ctx ctx, int dir)
{
	ssize_t	  ret;
	void	 *tmpbuf;
	int	(*process)(knc_ctx);	
	ssize_t	(*ourread)(void *, void *, size_t);
	void	 *ourcookie;
	int	 *is_open;

	/*
	 * We must be much more careful about when we process these
	 * packets.  This is not good, yet.
	 */
	process   = knc_state_process;

	if (dir == KNC_DIR_SEND) {
		ourread   =  ctx->localread;
		ourcookie =  ctx->localcookie;
		is_open   = &ctx->local_is_open;
	} else {
		ourread   = ctx->netread;
		ourcookie = ctx->netcookie;
		is_open   = &ctx->net_is_open;
	}

	/* XXXrcd: deal properly with EOF */
	/* XXXrcd: looping? */
	/* XXXrcd: hmmm! */

	if (!ourread || !ourcookie)
		return -1;

	/* XXXrcd: hardcoded constant */
	ret = knc_get_ibuf(ctx, dir, &tmpbuf, 128 * 1024);

	DEBUG(("knc_fill: about to read %zd bytes.\n", ret));

	ret = ourread(ourcookie, tmpbuf, ret);

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

		/* XXXrcd: hmmm! */
		/* XXXrcd: need to do something a little more than this... */
		knc_syscall_error(ctx, "I/O", errno);

		return -1;
	}

	if (ret == 0) {
		*is_open = 0;
		DEBUG(("knc_fill: got EOF\n"));
		/* XXXrcd: must handle this case... */
	}

	if (ret > 0) {
		DEBUG(("Read %zd bytes\n", ret));
		knc_fill_buf(ctx, dir, ret);
	}

	return process(ctx);
}

int
knc_flush(knc_ctx ctx, int dir, size_t flushlen)
{
	struct iovec	*vec;
	int		 iovcnt;
	size_t		 completelen = 0;
	ssize_t		 len;
	int		(*process)(knc_ctx);	
	ssize_t		(*ourwritev)(void *, const struct iovec *, int);
	void		 *ourcookie;

	if (dir == KNC_DIR_SEND) {
		process   = knc_state_process_out;
		ourwritev = ctx->netwritev;
		ourcookie = ctx->netcookie;
	} else {
		process   = knc_state_process_in;
		ourwritev = ctx->localwritev;
		ourcookie = ctx->localcookie;
	}

	/*
	 * XXXrcd: should we process in the loop?  I think that might
	 *         very well be a good plan, innit?
	 */

	process(ctx);

	for (;;) {
		len = knc_get_obufv(ctx, dir, &vec, &iovcnt);
		if (len <= 0)
			break;
		DEBUG(("knc_flush: about to write %zu bytes.\n", len));

		len = ourwritev(ourcookie, vec, iovcnt);

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

			/* XXXrcd: probably should do a little more here... */
			knc_syscall_error(ctx, "I/O", errno);

			return -1;
		}

		DEBUG(("knc_flush: wrote %zd bytes.\n", len));
		knc_drain_buf(ctx, dir, len);

		completelen += len;
		if (completelen > flushlen)
			break;
	}

	/* XXXrcd: ERRORS??!? */

	return 0;
}

void
knc_authenticate(knc_ctx ctx)
{
	knc_callback	cbs[4];
	struct pollfd	fds[4];
	nfds_t		nfds;
	int		ret;

	while (!knc_is_authenticated(ctx)) {
		nfds = knc_get_pollfds(ctx, fds, cbs, 4);
                ret = poll(fds, nfds, -1);
                if (ret == -1) {
			knc_syscall_error(ctx, "poll", errno);
                        break;
                }
                knc_service_pollfds(ctx, fds, cbs, nfds);
                knc_garbage_collect(ctx);
	}
}

ssize_t
knc_read(knc_ctx ctx, void *buf, size_t len)
{
	ssize_t	 ret;
	void	*tmpbuf;

	DEBUG(("knc_read: about to read.\n"));

	knc_fill(ctx, KNC_DIR_RECV);

	ret = knc_get_obuf(ctx, KNC_DIR_RECV, &tmpbuf, len);
	if (ret > 0) {
		memcpy(buf, tmpbuf, ret);
		knc_drain_buf(ctx, KNC_DIR_RECV, ret);
	}

	return ret;
}

ssize_t
knc_write(knc_ctx ctx, const void *buf, size_t len)
{
	ssize_t	ret;

	ret = knc_put_buf(ctx, KNC_DIR_SEND, buf, len);
	knc_state_process(ctx);

	knc_flush(ctx, KNC_DIR_SEND, -1);

	return ret;
}


/* XXXrcd: review this code against gssstdio.c! */

static char *
knc_errstring(OM_uint32 maj_stat, OM_uint32 min_stat)
{
	gss_buffer_desc	 status;
	OM_uint32	 new_stat;
	OM_uint32	 cur_stat;
	OM_uint32	 msg_ctx = 0;
	OM_uint32	 ret;
	int		 type;
	int		 newlen;
	char		*str = NULL;
	char		*tmp = NULL;

	cur_stat =maj_stat;
	type = GSS_C_GSS_CODE;

	for (;;) {

		/*
		 * GSS_S_FAILURE produces a rather unhelpful message, so
		 * we skip straight to the mech specific error in this case.
		 */

		if (type == GSS_C_GSS_CODE && cur_stat == GSS_S_FAILURE) {
			type = GSS_C_MECH_CODE;
			cur_stat = min_stat;
		}

		ret = gss_display_status(&new_stat, cur_stat, type,
		    GSS_C_NO_OID, &msg_ctx, &status);

		if (GSS_ERROR(ret))
			return str;	/* XXXrcd: hmmm, not quite?? */

		newlen = (str?strlen(str):0) + status.length + 3;

		tmp = str;
		str = malloc(newlen);

		if (!str) {
			gss_release_buffer(&new_stat, &status);
			return tmp;	/* XXXrcd: hmmm, not quite?? */
		}

		snprintf(str, newlen, "%s%s%.*s", tmp?tmp:"", tmp?", ":"",
		    (int)status.length, (char *)status.value);

		gss_release_buffer(&new_stat, &status);
		free(tmp);

		/*
		 * If we are finished processing for maj_stat, then
		 * move onto min_stat.
		 */

		if (msg_ctx == 0 && type == GSS_C_GSS_CODE && min_stat != 0) {
			type = GSS_C_MECH_CODE;
			cur_stat = min_stat;
			continue;
		}

		if (msg_ctx == 0)
			break;
	}

	return str;
}

static void
knc_generic_error(knc_ctx ctx, const char *str)
{

	/* XXXrcd: wrong type */
	ctx->error  = KNC_ERROR_GSS;
	ctx->errstr = strdup(str);
}

static void
knc_syscall_error(knc_ctx ctx, const char *str, int errorno)
{
	char	*err;
	char	*tmp;

	/* XXXrcd: wrong type */
	ctx->error = KNC_ERROR_GSS;

	err = strerror(errno);
	tmp = malloc(strlen(str) + strlen(err) + 3);

	if (tmp)
		sprintf(tmp, "%s: %s", str, err);

	ctx->errstr = tmp;
}

static void
knc_gss_error(knc_ctx ctx, OM_uint32 maj_stat, OM_uint32 min_stat,
	      const char *s)
{

	ctx->error = KNC_ERROR_GSS;
	ctx->errstr = knc_errstring(maj_stat, min_stat);
	if (!ctx->errstr)
		ctx->errstr = strdup("Failed to construct GSS error");
	DEBUG(("knc_gss_error: %s\n", ctx->errstr));
}
