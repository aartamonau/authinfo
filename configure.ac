AC_PREREQ([2.69])

AC_INIT([libauthinfo], [0.1], [https://github.com/aartamonau/libauthinfo/issues])
AM_INIT_AUTOMAKE
LT_INIT([static])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC_C99

if test "x${ac_cv_prog_cc_c99}" = xno; then
  AC_MSG_ERROR([A compiler supporting c99 is required])
fi

AC_CHECK_DECL([__GNUC__], [GCC=yes], [GCC=no])

if test "x${GCC}" = xyes; then
  VISIBILITY="-fvisibility=hidden"
  EXPORT_FUNCTION="__attribute__((visibility(\"default\")))"
fi

AC_SUBST(VISIBILITY, ${VISIBILITY})
AC_DEFINE_UNQUOTED(EXPORT_FUNCTION, [${EXPORT_FUNCTION}],
  [How to declare exported function.])

AC_DEFINE_DIR(SYSCONF_DIR, sysconfdir,
  [System configuration directory (typically /etc).])

AM_PROG_CC_C_O

PKG_CHECK_MODULES([CHECK], [check >= 0.9.0], [have_check=yes], [have_check=no])
AM_CONDITIONAL(HAVE_CHECK, [test x$have_check = xyes])

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug],
          [Enable debug build. @<:@default=off@:>@])],
  [enable_debug="yes"],
  [enable_debug="no"])
AM_CONDITIONAL(DEBUG, [test x$enable_debug = xyes])

AC_OUTPUT
