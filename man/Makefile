#
# Makefile

knc.0: knc.1
	nroff -mandoc knc.1 > knc.0

clean:
	rm knc.0

install:
	install -c -m644 knc.1 $(DESTDIR)/$(PREFIX)/man/man1/
	install -c -m644 knc.0 $(DESTDIR)/$(PREFIX)/man/cat1/
