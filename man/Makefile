#
# Makefile

all: knc.0 libknc.0

knc.0: knc.1
	nroff -mandoc knc.1 > knc.0

libknc.0: libknc.3
	nroff -mandoc libknc.3 > libknc.0

clean:
	rm knc.0
	rm libknc.0

install:
	install -c -m644 knc.1    $(DESTDIR)/$(PREFIX)/man/man1/
	install -c -m644 knc.0    $(DESTDIR)/$(PREFIX)/man/cat1/
	install -c -m644 libknc.3 $(DESTDIR)/$(PREFIX)/man/man3/
	install -c -m644 libknc.0 $(DESTDIR)/$(PREFIX)/man/cat3/
