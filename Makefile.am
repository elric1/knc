
ACLOCAL_AMFLAGS = -I cf

SUBDIRS  = bin lib test

.PHONY: check-knc-exec
check-knc-exec:
	$(MAKE) all
	$(MAKE) -C test check-knc-exec
