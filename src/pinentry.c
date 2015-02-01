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

#include "pinentry.h"
#include "utils.h"

enum authinfo_result_t
pinentry_start(const struct pinentry_settings_t *settings,
               struct pinentry_t *pinentry)
{
    gpg_error_t ret;

    ret = assuan_new(&pinentry->ctx);
    if (ret != GPG_ERR_NO_ERROR) {
        return authinfo_gpg_error2result(ret);
    }

    return AUTHINFO_OK;
}
