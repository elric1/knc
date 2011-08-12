#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([knc], [2.0], [elric@imrryr.org])
AC_CONFIG_SRCDIR([bin/gssstdio.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([cf])

AM_INIT_AUTOMAKE([foreign 1.10.3])
AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_LIBTOOL

LT_PREREQ([2.2])
LT_INIT([shared static win32-dll])

AM_CONDITIONAL(ENABLE_SHARED, test "$enable_shared" = "yes")

AC_ARG_WITH([gss-dir],
	    [AC_HELP_STRING([--with-gss-dir=<DIR>],
			    [choose the GSSAPI dir])],
	    [gssdir=$withval],
	    [gssdir=/usr])

if test -d ${gssdir}; then
	CPPFLAGS="$CPPFLAGS -I$gssdir/include"
	LDFLAGS="$LDFLAGS -L$gssdir/lib"
fi

AC_CHECK_HEADERS([gssapi/gssapi_krb5.h gssapi/gssapi.h gssapi.h ], break,,)

AC_SEARCH_LIBS(gss_init_sec_context, [gssapi gssapi_krb5],,,)

AC_CHECK_DECLS(GSS_KRB5_NT_PRINCIPAL_NAME,,,[
#if HAVE_GSSAPI_H
#include <gssapi.h>
#else 
#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#else
#include <gssapi/gssapi_krb5.h>
#endif
#endif
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK

AC_CONFIG_FILES([Makefile bin/Makefile lib/Makefile])
AC_OUTPUT
