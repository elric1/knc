#
# The Makefile...

CFLAGS += -DKNC_VERSION_STRING=\"1.6\"

#
# For Heimdal uncomment:
CFLAGS += -DHEIMDAL
LDADD = -lgssapi -lkrb5

#
# For MIT krb5 uncomment:
#
# LDADD = -lgssapi_krb5

knc: knc.o gssstdio.o
	cc -o $@ $> $(LDADD)

clean:
	rm -f knc knc.o gssstdio.o

install:
	install -c -m 755 knc $(DESTDIR)/$(PREFIX)/bin
