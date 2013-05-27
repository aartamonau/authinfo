ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = $(VISIBILITY) -Wall -Werror
AM_CPPFLAGS = -I$(top_srcdir)/include/

noinst_HEADERS = $(top_srcdir)/include/authinfo_internal.h
include_HEADERS = $(top_srcdir)/include/authinfo.h

noinst_LTLIBRARIES = libauthinfo_impl.la
libauthinfo_impl_la_SOURCES = $(top_srcdir)/src/authinfo.c

lib_LTLIBRARIES = libauthinfo.la
libauthinfo_la_SOURCES =
libauthinfo_la_LIBADD = libauthinfo_impl.la

bin_PROGRAMS = authinfo
authinfo_SOURCES = $(top_srcdir)/src/main.c
authinfo_LDADD = libauthinfo_impl.la
