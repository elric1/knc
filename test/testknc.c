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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libknc.h>

/*
 * On linux, you have to prepend + to optstring to cause sane argument
 * processing to occur.  We hardcode this here rather than rely on the
 * user to set POSIXLY_CORRECT because for programs with a syntax that
 * accepts another program which has arguments, the GNU convention is
 * particularly stupid.
 */
#ifdef linux
#define POS "+"
#else
#define POS
#endif

static void
usage(void)
{

	fprintf(stderr, "Usage: knc [-d] [<service>@]host[:port]\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	knc_ctx	ctx;
	int	ret;
	int	debug = 0;
	int	c;
 
        /* process arguments */
	while ((c = getopt(argc, argv, POS "d")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	ctx = knc_ctx_init();
	knc_set_debug(ctx, debug);
	knc_connect(ctx, *argv, "host", NULL, 0);
	knc_set_local_fds(ctx, STDIN_FILENO, STDOUT_FILENO);

	for (;;) {
		knc_callback	cbs[4];
		struct pollfd	fds[4];
		nfds_t		nfds;

		/*
		 * XXXrcd: knc_eof() should really be something like
		 *         ``knc_io_complete()'' because EOF is done via
		 *         packets and whatnot...
		 */

		if (knc_eof(ctx) || knc_error(ctx))
			break;

		if (knc_eof(ctx))
			break;

		nfds = knc_get_pollfds(ctx, fds, cbs, 4);

		ret = poll(fds, nfds, 0);
		if (ret < 0) {
			fprintf(stderr, "poll: %s\n", strerror(errno));
			break;
		}

		knc_service_pollfds(ctx, fds, cbs, nfds);
	}

	ret = 0;
	if (knc_error(ctx)) {
		fprintf(stderr, "KNC ERROR: %s\n", knc_errstr(ctx));
		ret = 1;
	}

	knc_ctx_close(ctx);
	return ret;
}
