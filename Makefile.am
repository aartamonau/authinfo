ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = $(VISIBILITY) -Wall -Werror
AM_CPPFLAGS = -I$(top_srcdir)/include/

noinst_HEADERS = $(top_srcdir)/include/netrc_internal.h
include_HEADERS = $(top_srcdir)/include/netrc.h

noinst_LTLIBRARIES = libnetrc_impl.la
libnetrc_impl_la_SOURCES = $(top_srcdir)/src/netrc.c

lib_LTLIBRARIES = libnetrc.la
libnetrc_la_SOURCES =
libnetrc_la_LIBADD = libnetrc_impl.la

bin_PROGRAMS = netrc
netrc_SOURCES = $(top_srcdir)/src/main.c
netrc_LDADD = libnetrc_impl.la
