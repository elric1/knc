#
# The Makefile...

CFLAGS += -DKNC_VERSION_STRING=\"1.6\"
CFLAGS += -DHEIMDAL

LDADD = -lgssapi -lkrb5

knc: knc.o gssstdio.o
	cc -o $@ $> $(LDADD)

clean:
	rm -f knc knc.o gssstdio.o
