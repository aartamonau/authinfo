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

#include "utils.h"

enum authinfo_result_t
authinfo_gpg_error2result(gpg_error_t error)
{
    if (error == GPG_ERR_NO_ERROR) {
        return AUTHINFO_OK;
    }

    switch (gpg_err_code(error)) {
    case GPG_ERR_DECRYPT_FAILED:
        return AUTHINFO_EGPG_DECRYPT_FAILED;
    case GPG_ERR_BAD_PASSPHRASE:
        return AUTHINFO_EGPG_BAD_PASSPHRASE;
    case GPG_ERR_ENOMEM:
        return AUTHINFO_ENOMEM;
    default:
        return AUTHINFO_EGPG;
    }
}
