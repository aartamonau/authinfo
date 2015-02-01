# -*- mode: makefile-automake; -*-
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = docs

if DEBUG
DEBUG_CPPFLAGS = -DDEBUG
endif

AM_CFLAGS = $(GCC_CFLAGS) $(GPGME_PTHREAD_CFLAGS) $(LIBASSUAN_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/include/ $(DEBUG_CPPFLAGS)
AM_LDFLAGS = $(GPGME_PTHREAD_LIBS) $(LIBASSUAN_LIBS)

EXTRA_DIST = $(top_srcdir)/config.site/coverage \
             $(top_srcdir)/tests/files/gpg_tests/public.key \
             $(top_srcdir)/tests/files/gpg_tests/private.key \
             $(top_srcdir)/tests/files/gpg_tests/read_file \
             $(top_srcdir)/tests/files/gpg_tests/read_file.gpg \
             $(top_srcdir)/tests/files/gpg_tests/gpged_password \
             $(top_srcdir)/tests/files/gpg_tests/gpged_password_bad

pkginclude_HEADERS = include/authinfo.h

noinst_LTLIBRARIES = libauthinfo_impl.la
libauthinfo_impl_la_SOURCES = src/utils.h    \
                              src/utils.c    \
                              src/base64.h   \
                              src/base64.c   \
                              src/authinfo.c

lib_LTLIBRARIES = libauthinfo.la
libauthinfo_la_SOURCES =
libauthinfo_la_LIBADD = libauthinfo_impl.la
libauthinfo_la_LDFLAGS = -version-info $(LIBAUTHINFO_VERSION_INFO)

if BUILD_CLI
AUTHINFO = authinfo
endif

bin_PROGRAMS = $(AUTHINFO)
authinfo_SOURCES = src/cli.c
authinfo_LDADD = libauthinfo_impl.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = authinfo.pc

if HAVE_CHECK
check_PROGRAMS = authinfo_parsing_tests authinfo_gpg_tests
else
check_PROGRAMS =
endif

TESTS = $(check_PROGRAMS)

authinfo_parsing_tests_SOURCES = tests/authinfo_parsing_tests.c
authinfo_parsing_tests_LDADD = $(CHECK_LIBS) libauthinfo_impl.la
authinfo_parsing_tests_CFLAGS = $(CHECK_CFLAGS) $(AM_CFLAGS)

authinfo_gpg_tests_SOURCES = tests/authinfo_gpg_tests.c
authinfo_gpg_tests_LDADD = $(CHECK_LIBS) libauthinfo_impl.la
authinfo_gpg_tests_CFLAGS = $(CHECK_CFLAGS) $(AM_CFLAGS)
authinfo_gpg_tests_CPPFLAGS = -DTOP_SRCDIR='"$(top_srcdir)"' $(AM_CPPFLAGS)

if ENABLE_PYTHON
pkgpython_PYTHON = python/__init__.py python/authinfo.py
endif

clean-local:
	find . \( -name "*.gcda" -o -name "*.gcno" -o -name "*.gcov" \) -delete
	rm -rf lcov.info lcov

.PHONY: lcov
if HAVE_LCOV
lcov:
	lcov --capture --directory . --output-file lcov.info
	genhtml lcov.info --output-directory lcov/

	@echo "lcov report is ready: $$(pwd)/lcov/index.html"
if HAVE_XDG_OPEN
	xdg-open lcov/index.html
endif

else
lcov:
	@echo "lcov not installed"
endif
