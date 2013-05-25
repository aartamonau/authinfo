AC_PREREQ([2.69])

AC_INIT([libnetrc], [0.1], [https://github.com/aartamonau/libnetrc/issues])
AM_INIT_AUTOMAKE
LT_INIT([static])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC

AC_CHECK_DECL([__GNUC__], [GCC=yes], [GCC=no])

if test "x${GCC}" = xyes; then
  VISIBILITY="-fvisibility=hidden"
  EXPORT_FUNCTION="__attribute__((visibility(\"default\")))"
fi

AC_SUBST(VISIBILITY, ${VISIBILITY})
AC_DEFINE_UNQUOTED(EXPORT_FUNCTION, [${EXPORT_FUNCTION}],
  [How to declare exported function.])

AC_OUTPUT
