#

lib_LTLIBRARIES	= libknc.la
man_MANS	= libknc.3
include_HEADERS	= libknc.h

libknc_la_SOURCES = libknc.c simple.c
libknc_la_LIBADD  = $(GSSAPI_LIBS)

#
# Let's be a tad more aggressive about warnings:

libknc_la_CPPFLAGS  = $(WFLAGS) $(GSSAPI_CFLAGS)
