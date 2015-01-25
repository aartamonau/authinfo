/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

/*
 * Copyright (C) 2013 Aliaksey Artamonau <aliaksiej.artamonau@gmail.com>
 *
 * This file is part of authinfo.
 *
 * Authinfo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Authinfo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with authinfo.  If not, see <http://www.gnu.org/licenses/>.
 */

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
