#ifndef _AUTHINFO_INTERNAL_H_
#define _AUTHINFO_INTERNAL_H_

#include <stdio.h>

#ifdef DEBUG
#  define STRINGIFY(exp) STRINGIFY_HELPER(exp)
#  define STRINGIFY_HELPER(exp) #exp
#  define TRACE(...) \
  fprintf(stderr, \
          "TRACE: " __FILE__  ":" STRINGIFY(__LINE__) ":    "  __VA_ARGS__)
#else
#  define TRACE(...)
#endif

#endif /* _AUTHINFO_INTERNAL_H_ */
