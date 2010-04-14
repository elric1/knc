#
# main Makefile

PREFIX ?= /usr/local

all:
	( cd bin && make PREFIX=$(PREFIX) )
	( cd man && make PREFIX=$(PREFIX) )

clean:
	( cd bin && make PREFIX=$(PREFIX) clean )
	( cd man && make PREFIX=$(PREFIX) clean )

install:
	( cd bin && make PREFIX=$(PREFIX) install )
	( cd man && make PREFIX=$(PREFIX) install )
