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


#include <stdio.h>

#include "knclib.h"

#define TEST_STRING	"0123456789abcdefghijklmnopqrstuvwxyz\n"

int
putnum(struct knc_stream *s, int i)
{
	char	*tmp = malloc(256);

	snprintf(tmp, 256, "%d\n", i);
	knc_put_stream(s, tmp, strlen(tmp));
}

int
main(int argc, char **argv)
{
	struct knc_stream	*s;
	int			 i;
	int			 len;
	char			*buf;
	char			*tmp;

	s = knc_init_stream();
	buf = malloc(1024);

	strncpy(buf, TEST_STRING, strlen(TEST_STRING));

	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));
	knc_put_stream(s, buf, strlen(TEST_STRING));

	for (i=0; i < 1024; i++)
		putnum(s, i);

	for (;;) {

		len = knc_get_ostream_contig(s, &tmp, 77);
		if (len == -1)
			break;
		write(1, tmp, len);

		knc_stream_drain(s, len);
	}

	len = knc_get_ostream(s, &tmp, 1024);
	if (len > 0)
		write(1, tmp, len);
	return 0;
}

