

lib_LTLIBRARIES = libknc.la

libknc_la_SOURCES = libknc.c

#
# Let's be a tad more aggressive about warnings:

libknc_la_CPPFLAGS += -Werror
libknc_la_CPPFLAGS += -Wall -Wstrict-prototypes -Wmissing-prototypes
libknc_la_CPPFLAGS += -Wpointer-arith -Wno-sign-compare
libknc_la_CPPFLAGS += -Wno-traditional -Wreturn-type -Wswitch
libknc_la_CPPFLAGS += -Wno-shadow -Wcast-qual -Wwrite-strings
libknc_la_CPPFLAGS += -Wextra -Wno-unused-parameter -Wsign-compare

man_MANS = libknc.3
