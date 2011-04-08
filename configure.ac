#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
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

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h malloc.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([dup2 gethostbyname inet_ntoa memset putenv select socket strchr strdup strerror strpbrk])

AC_CONFIG_FILES([Makefile bin/Makefile lib/Makefile])
AC_OUTPUT
