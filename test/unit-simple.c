/* */

/*-
 * Copyright 2011 Roland C. Dowdeswell
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


#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libknc.h>

int runserver(int);
int runclient(int, char *, char *);
int knc_loop(knc_ctx, int);

/*
 * unitknc: a simple test of the libknc.
 *
 * The idea here is that we fork and the child assumes the role of a
 * KNC server whilst the parent assumes the role of a KNC client connecting
 * to it.  We construct a reasonable test of passing data back and forth
 * while checking for memory leaks in the library.
 */

int
main(int argc, char **argv)
{
	pid_t	pid;
	int	fds[2];
	int	kidret;
	int	ret;

	srandom(time(NULL));

	if (argc != 3) {
		fprintf(stderr, "Usage: unitknc service hostname\n");
		exit(1);
	}

	ret = socketpair(PF_LOCAL, SOCK_STREAM, 0, fds);
	if (ret == -1) {
		perror("socketpair");
		exit(1);
	}

	pid = fork();
	switch (pid) {
	case  0:
		close(fds[0]);
		ret = runserver(fds[1]);
		fprintf(stderr, "Child exiting.\n");
		exit(ret);
	case -1:
		perror("fork");
		exit(1);
	default:
		close(fds[1]);
		ret = runclient(fds[0], argv[1], argv[2]);
		break;
	}

	if (wait(&kidret) == -1) {
		perror("wait");
		kidret = 1;
	}

	if (ret)
		fprintf(stderr, "Parent failed.\n");

	if (kidret)
		fprintf(stderr, "Child failed.\n");

	fprintf(stderr, "Parent exiting.\n");

	if (ret || kidret)
		return 1;

	return 0;
}

int
runserver(int fd)
{
	knc_ctx		ctx;
	uint32_t	offset;
	uint32_t	len;
	char		byte;

	fprintf(stderr, "runserver(), pid == %d\n", getpid());

	ctx = knc_ctx_init();

//knc_set_debug(ctx, 1);

	knc_set_net_fd(ctx, fd);
	knc_accept(ctx);

	knc_authenticate(ctx);

	if (knc_error(ctx)) {
		fprintf(stderr, "knc_authenticate: %s\n", knc_errstr(ctx));
		exit(1);
	}

	for (;;) {
		knc_fullread(ctx, &byte, 1);
		knc_fullread(ctx, &offset, 4);
		knc_fullread(ctx, &len, 4);

		if (knc_error(ctx)) {
			fprintf(stderr, "knc_fullread: %s\n", knc_errstr(ctx));
			exit(1);
		}

#if 0
		while (len > 0) {
			char    buf[32768];
			int     ret;

			ret = knc_fullread(ctx, buf,
			    (sizeof(buf) < len)?sizeof(buf):len);

			if (knc_error(ctx)) {
				fprintf(stderr, "knc_read: %s\n",
					knc_errstr(ctx));
				exit(1);
			}

			len -= ret;    /* consuming input... */
		}
#else
		{
			char	*buf;
			int	 ret;

			buf = malloc(len);
			/* XXXrcd: errors */
			ret = knc_fullread(ctx, buf, len);
		}
#endif

		byte = 0;
		knc_write(ctx, &byte, 1);
	}

	close(fd);
	knc_ctx_close(ctx);
	return 0;
}

int
runclient(int fd, char *service, char *hostname)
{
	knc_ctx ctx;
	int	i;

	fprintf(stderr, "runclient(), pid == %d\n", getpid());

	ctx = knc_ctx_init();

	knc_import_set_hb_service(ctx, hostname, service);
	knc_set_net_fd(ctx, fd);
	knc_initiate(ctx);

//knc_set_debug(ctx, 1);

	knc_authenticate(ctx);

	if (knc_error(ctx)) {
		fprintf(stderr, "knc_authenticate: %s\n", knc_errstr(ctx));
		exit(1);
	}

	for (i=0; i < 256; i++) {
		uint32_t	 offset;
		uint32_t	 len;
		int		 j;
		int		 ret;
		char		 byte;
		char		*buf;

		if (knc_error(ctx))
			fprintf(stderr, "client: %s\n", knc_errstr(ctx));

		offset = random() % 140000;
		len    = random() %  70000;

		fprintf(stderr, "Sending blob %d of len %u\n", i, len);

		knc_write(ctx, &byte, 1);
		knc_write(ctx, &offset, 4);
		knc_write(ctx, &len, 4);

		buf = malloc(len);
		if (!buf)
			perror("malloc");

		for (j=0; j < len; j++)
			buf[j] = j % 255;

		knc_write(ctx, buf, len);

		free(buf);

		knc_flush(ctx, KNC_DIR_SEND, -1);

		ret = knc_fullread(ctx, &byte, 1);

		if (ret != 1)
			fprintf(stderr, "knc_fullread() = %d: %s\n", ret,
			    strerror(errno));
	}

	close(fd);
	knc_ctx_close(ctx);
	return 0;
}
