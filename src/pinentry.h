/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

/*
 * Copyright (C) 2015 Aliaksey Artamonau <aliaksiej.artamonau@gmail.com>
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

#ifndef _PINENTRY_H_
#define _PINENTRY_H_

#include <assuan.h>

#include "authinfo.h"

struct pinentry_settings_t {
    const char *lc_ctype;
    const char *lc_messages;

    int timeout;

    const char *title;
    const char *description;
    const char *prompt;
};

struct pinentry_t {
    assuan_context_t ctx;
};

enum authinfo_result_t
pinentry_new(const struct pinentry_settings_t *settings,
             struct pinentry_t *pinentry);

void
pinentry_release(struct pinentry_t *pinentry);

enum authinfo_result_t
pinentry_set_error(struct pinentry_t *pinentry, const char *error);

#endif /* _PINENTRY_H_ */
