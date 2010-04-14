
knc.0: knc.1
	nroff -mandoc knc.1 > knc.0

clean:
	rm knc.0

install:
	install -c -m644 knc.1 /usr/pkg/man/man1/
	install -c -m644 knc.0 /usr/pkg/man/cat1/
