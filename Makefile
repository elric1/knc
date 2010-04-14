#
# main Makefile

PREFIX ?= /usr/local

#
# To compile with Heimdal pass in:
#
#	CFLAGS += -DHEIMDAL
#	LDADD = -lgssapi -lkrb5
#
# For MIT krb5 pass in:
#
#	LDADD = -lgssapi_krb5


all:
	( cd bin && make PREFIX=$(PREFIX) )
	( cd man && make PREFIX=$(PREFIX) )

clean:
	( cd bin && make PREFIX=$(PREFIX) clean )
	( cd man && make PREFIX=$(PREFIX) clean )

install:
	( cd bin && make CFLAGS=$(CFLAGS) PREFIX=$(PREFIX) install )
	( cd man && make CFLAGS=$(CFLAGS) PREFIX=$(PREFIX) install )
