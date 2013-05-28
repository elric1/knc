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
	knc_ctx	ctx;

	fprintf(stderr, "runserver(), pid == %d\n", getpid());

	ctx = knc_ctx_init();

	knc_set_net_fd(ctx, fd);
	knc_accept(ctx);

	return knc_loop(ctx, 1);
}

int
runclient(int fd, char *service, char *hostname)
{
	knc_ctx ctx;

	fprintf(stderr, "runclient(), pid == %d\n", getpid());

	ctx = knc_ctx_init();

	knc_import_set_hb_service(ctx, hostname, service);
	knc_set_net_fd(ctx, fd);
	knc_initiate(ctx);

	return knc_loop(ctx, 0);
}

#define TEST_SIZE	(1024 * 1024)
#define UNIT_BUFSIZ	(75 * 1024)

int
knc_loop(knc_ctx ctx, int server)
{
	int	 i;
	int	 loopcount = 0;
	int	 ret;
	int	 do_recv = 1;
	int	 do_send = 1;
	int	 valrecv = 0;
	int	 valsend = 0;
	char	*buf;

	knc_set_opt(ctx, KNC_SOCK_NONBLOCK, 1);

	for (;;) {
		knc_callback	cbs[2];
		struct pollfd	fds[4];
		nfds_t		nfds;

		fprintf(stderr, "%s: loop start (% 6d), "
		    "R=% 9d %s S=% 9d %s ToSend=% 9d\n", server?"S":"C",
		    ++loopcount, valrecv, do_recv?"    ":"done", valsend,
		    do_send?"    ":"done", knc_pending(ctx, KNC_DIR_SEND));

		if (knc_error(ctx))
			break;

		if (!knc_net_is_open(ctx)) {
			fprintf(stderr, "Other end unexpectedly closed.\n");
			break;
		}

		/*
		 * The data that we are sending and receiving is a simple
		 * steam of incrementing single byte integers modulo 11.
		 * Both sides send the same data, so it can be validated.
		 */

		if (do_send && knc_pending(ctx, KNC_DIR_SEND) < UNIT_BUFSIZ) {
			ret = knc_get_ibuf(ctx, KNC_DIR_SEND,
			    (void **)&buf, 8192);
			if (ret == -1)
				fprintf(stderr, "%d: ret == -1 for sending\n",
				    getpid());

			for (i=0; i < ret; i++)
				buf[i] = valsend++ % 11;

			if (ret > 0)
				knc_fill_buf(ctx, KNC_DIR_SEND, ret);
		}

		while (knc_pending(ctx, KNC_DIR_RECV) > 0) {
			ret = knc_get_obuf(ctx, KNC_DIR_RECV,
			    (void **)&buf, 8192);
			if (ret <= 0)
				break;

			for (i=0; i < ret; i++) {
				if (buf[i] != valrecv++ % 11) {
					fprintf(stderr, "Malformed input\n");
					return -1;
				}
			}

			knc_drain_buf(ctx, KNC_DIR_RECV, ret);
		}

		if (valrecv >= TEST_SIZE)
			do_recv = 0;

		if (valsend >= TEST_SIZE)
			do_send = 0;


		nfds = knc_get_pollfds(ctx, fds, cbs, 4);

		ret = poll(fds, nfds, 0);
		if (ret < 0) {
			fprintf(stderr, "poll: %s\n", strerror(errno));
			break;
		}

		knc_service_pollfds(ctx, fds, cbs, nfds);
		
		knc_garbage_collect(ctx);

		if (!do_send && !do_recv && !knc_pending(ctx, KNC_DIR_SEND))
			break;
	}

	fprintf(stderr, "%s: loop done  (% 6d), "
	    "R=% 9d %s S=% 9d %s ToSend=% 9d\n", server?"S":"C",
	    ++loopcount, valrecv, do_recv?"    ":"done", valsend,
	    do_send?"    ":"done", knc_pending(ctx, KNC_DIR_SEND));

	ret = 0;
	if (knc_error(ctx)) {
		fprintf(stderr, "KNC UNIT TEST ERROR: %s\n", knc_errstr(ctx));
		ret = 1;
	}

	knc_ctx_close(ctx);
	return ret;
}
