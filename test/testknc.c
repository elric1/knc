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



#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>


#include <sys/select.h>

#include <errno.h>
#include <stdio.h>

#include <libknc.h>

#define READBUFSIZ	(256 * 1024)
#define WRITEBUFSIZ	(256 * 1024)

int
main(int argc, char **argv)
{
	knc_ctx	 ctx;
	int	 ret;
	char	*buf;

	if (argc < 2) {
		fprintf(stderr, "Usage: knc [<service>@]host[:port]\n");
		exit(1);
	}

	ctx = knc_connect(NULL, *++argv, "host", NULL, 0);

	if (!ctx) {
		/* XXXrcd: better? */
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

//	knc_set_debug(ctx, 1);

	for (;;) {
		fd_set	rd, wr;
		int	fd;

		if (knc_error(ctx))
			break;

		fd = knc_get_net_fd(ctx);

		if (fd == -1)
			break;

		/* XXXrcd: Set non-blocking? */

		FD_ZERO(&rd);
		FD_ZERO(&wr);

		/*
		 * For the write buffers, we only check for select(2)ability
		 * if we have pending data.  For incoming data, we expect it
		 * at any time.
		 */

		if (knc_pending(ctx, KNC_DIR_SEND) < WRITEBUFSIZ)
			FD_SET(0, &rd);

		if (fd != -1 && knc_pending(ctx, KNC_DIR_RECV) < READBUFSIZ)
			FD_SET(fd, &rd);

		if (knc_pending(ctx, KNC_DIR_RECV) > 0)
			FD_SET(1, &wr);

		if (fd != -1 && knc_pending(ctx, KNC_DIR_SEND) > 0)
			FD_SET(fd, &wr);

		ret = select(fd+1, &rd, &wr, NULL, NULL);
		if (ret < 0) {
			fprintf(stderr, "select: %s\n", strerror(errno));
			break;
		}

		if (FD_ISSET(fd, &wr))
			knc_flush(ctx, KNC_DIR_SEND, 0);

		if (FD_ISSET(fd, &rd)) {
			knc_fill(ctx, KNC_DIR_RECV);
			// continue;
		}

		if (FD_ISSET(0, &rd)) {
			ret = knc_get_ibuf(ctx, KNC_DIR_SEND, (void**)&buf,
			    16384);
			if (ret == -1) {
				/* XXXrcd: error handling... */
			}

			ret = read(0, buf, ret);

			if (ret == -1) {
				/* XXXrcd: error handling! */
				fprintf(stderr, "read: %s\n", strerror(errno));
			}

			knc_fill_buf(ctx, KNC_DIR_SEND, ret);
		}

		if (FD_ISSET(1, &wr)) {
			struct iovec	*vec;
			size_t		 count;

			ret = knc_get_obufv(ctx, KNC_DIR_RECV, &vec, &count);

			if (ret < 1)
				continue;	/* XXXrcd: bad. */

			ret = writev(1, vec, count);

			if (ret == -1)
				fprintf(stderr, "write: %s\n", strerror(errno));

			if (ret > 0)
				knc_drain_buf(ctx, KNC_DIR_RECV, ret);
		}

		knc_garbage_collect(ctx);
	}

	ret = 0;
	if (knc_error(ctx)) {
		fprintf(stderr, "KNC ERROR: %s\n", knc_errstr(ctx));
		ret = 1;
	}

	knc_ctx_close(ctx);
	return ret;
}
