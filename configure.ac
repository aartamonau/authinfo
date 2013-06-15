AC_PREREQ([2.69])

AC_INIT([libauthinfo], [0.1], [https://github.com/aartamonau/libauthinfo/issues])
AM_INIT_AUTOMAKE
LT_INIT([static])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_FILES([Makefile docs/Makefile docs/Doxyfile])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC_C99

if test "x${ac_cv_prog_cc_c99}" = xno; then
  AC_MSG_ERROR([A compiler supporting c99 is required])
fi

AC_CHECK_DECL([__GNUC__], [GCC=yes], [GCC=no])

if test "x${GCC}" = xyes; then
  GCC_CFLAGS="-fvisibility=hidden -Wall -Werror"
fi

AC_SUBST([GCC_CFLAGS], ${GCC_CFLAGS})

AC_DEFINE_DIR([SYSCONF_DIR], [sysconfdir],
  [System configuration directory (typically /etc).])

AM_PROG_CC_C_O

PKG_CHECK_MODULES([CHECK], [check >= 0.9.0], [have_check=yes], [have_check=no])
AM_CONDITIONAL([HAVE_CHECK], [test x$have_check = xyes])

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug],
          [enable debug build @<:@default=no@:>@])],
  [enable_debug="$enableval"],
  [enable_debug="no"])
AM_CONDITIONAL([DEBUG], [test x$enable_debug = xyes])

AC_CHECK_PROG([have_lcov], [lcov], [yes])
AM_CONDITIONAL([HAVE_LCOV], [test x$have_lcov = xyes])

AC_CHECK_PROG([have_xdg_open], [xdg-open], [yes])
AM_CONDITIONAL([HAVE_XDG_OPEN], [test x$have_xdg_open = xyes])

AC_CHECK_PROG([have_doxygen], [doxygen], [yes])
AM_CONDITIONAL([HAVE_DOXYGEN], [test x$have_doxygen = xyes])

if test x$have_doxygen != xyes; then
   AC_MSG_WARN(
     [Doxygen not found. API documentation won't be generated])
fi

AC_ARG_ENABLE([gpg],
  [AS_HELP_STRING([--enable-gpg],
          [enable gpg support @<:@default=yes@:>@])],
  [enable_gpg="$enableval"],
  [enable_gpg="yes"])

if test x$enable_gpg = xyes; then
dnl TODO: refine version restriction
   AM_PATH_GPGME_PTHREAD([1.4.0], [have_gpgme=yes], [have_gpgme=no])

   if test x$have_gpgme = xno; then
      AC_MSG_WARN(
        [GPGME library has not been found. GPG support will be disabled])
   fi
fi

if test x$have_gpgme = xyes; then
   AC_DEFINE([HAVE_GPGME], [1], [Define to 1 if you want GPG support])
fi

AC_OUTPUT
