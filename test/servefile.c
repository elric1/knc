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

#include <sys/stat.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libknc.h>

static void
serve_file(int nfd, const char *fn)
{
	struct stat	sb;
	knc_ctx		ctx;
	int		fd;
	int		ret;

	fd = open(fn, O_RDONLY, 0);
	if (fd == -1) {
		fprintf(stderr, "open: %s\n", strerror(errno));
		exit(1);
	}

	ret = fstat(fd, &sb);
	if (ret == -1) {
		fprintf(stderr, "stat: %s\n", strerror(errno));
		exit(1);
	}

	ctx = knc_ctx_init();

	if (!ctx) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

	knc_set_net_fd(ctx, nfd);

	knc_accept(ctx);

	knc_authenticate(ctx);

	/* XXXrcd: st_size is an off_t, but we take a size_t there.  punt. */
	knc_put_mmapbuf(ctx, KNC_DIR_SEND, sb.st_size, MAP_PRIVATE, fd, 0);
	close(fd);

	knc_flush(ctx, KNC_DIR_SEND, -1);

	if (knc_error(ctx))
		fprintf(stderr, "KNC ERROR: %s\n", knc_errstr(ctx));

	knc_ctx_close(ctx);
	return;
}

static int
setup_listener(unsigned short port)
{
	struct sockaddr_in	addr;
	int			fd;
	int			ret;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port   = ntohs(port);

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		fprintf(stderr, "bind: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	ret = listen(fd, 5);
	if (ret == -1) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int
main(int argc, char **argv)
{
	int	fd;
	int	nfd;
	int	ret;

	if (argc < 3) {
		fprintf(stderr, "Usage: servefile port file\n");
		exit(1);
	}

	fd = setup_listener(atoi(*++argv));
	if (fd == -1)
		exit(1);

	/* don't bother reaping, this is a test program... */
	signal(SIGCHLD, SIG_IGN);

	argv++;
	for (;;) {
		pid_t	kid;
		int	status;

		nfd = accept(fd, NULL, NULL);

		kid = fork();
		switch (kid) {
		case -1:
			/* XXXrcd: error. */
			close(nfd);
			fprintf(stderr, "fork: %s\n", strerror(errno));
			break;
		case 0:
			close(fd);
			serve_file(nfd, *argv);
			exit(0);
		default:
			close(nfd);
			break;
		}
	}
}
