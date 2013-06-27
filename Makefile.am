ACLOCAL_AMFLAGS = -I m4

SUBDIRS = docs

if DEBUG
DEBUG_CPPFLAGS = -DDEBUG
endif

AM_CFLAGS = $(GCC_CFLAGS) $(GPGME_PTHREAD_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/include/ $(DEBUG_CPPFLAGS)
AM_LDFLAGS = $(GPGME_PTHREAD_LIBS)

noinst_DATA = $(top_srcdir)/config.site/coverage

include_HEADERS = include/authinfo.h

noinst_LTLIBRARIES = libauthinfo_impl.la
libauthinfo_impl_la_SOURCES = src/authinfo_internal.h \
                              src/base64.h \
                              src/authinfo.c \
                              src/base64.c

lib_LTLIBRARIES = libauthinfo.la
libauthinfo_la_SOURCES =
libauthinfo_la_LIBADD = libauthinfo_impl.la
libauthinfo_la_LDFLAGS = -version-info $(LIBAUTHINFO_VERSION_INFO)

if BUILD_AUTHINFO_TOOL
AUTHINFO = authinfo
endif

bin_PROGRAMS = $(AUTHINFO)
authinfo_SOURCES = src/main.c
authinfo_LDADD = libauthinfo_impl.la

if HAVE_CHECK
check_PROGRAMS = authinfo_parsing_tests
else
check_PROGRAMS =
endif

TESTS = $(check_PROGRAMS)

authinfo_parsing_tests_SOURCES = tests/authinfo_parsing_tests.c
authinfo_parsing_tests_LDADD = $(CHECK_LIBS) libauthinfo_impl.la
authinfo_parsing_tests_CFLAGS = $(CHECK_CFLAGS) $(AM_CFLAGS)

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
