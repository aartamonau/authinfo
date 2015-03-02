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

#include <string.h>
#include <stdarg.h>

#include "pinentry.h"
#include "utils.h"

#ifdef __GNUC__
#define FORMAT_ATTR(type, fmt, args) \
    __attribute__((format (type, fmt, args)))
#else
#define FORMAT_ATTR(type, fmt, args)
#endif

typedef gpg_error_t (*assuan_data_cb_t)(void *, const void *, size_t);

static enum authinfo_result_t
pinentry_command(struct pinentry_t *pinentry,
                 assuan_data_cb_t data_cb, void *arg,
                 const char *fmt, ...)
    FORMAT_ATTR(printf, 4, 5);

enum authinfo_result_t
pinentry_new(const struct pinentry_settings_t *settings,
               struct pinentry_t *pinentry)
{
    gpg_error_t gpg_ret;
    enum authinfo_result_t ret;

    /* TODO: search for pinentry in PATH */
    const char *argv[2] = {"/usr/bin/pinentry", NULL};

    gpg_ret = assuan_new(&pinentry->ctx);
    if (gpg_ret != GPG_ERR_NO_ERROR) {
        TRACE_GPG_ERROR("Couldn't create assuan context", gpg_ret);
        return authinfo_gpg_error2result(gpg_ret);
    }

    gpg_ret = assuan_pipe_connect(pinentry->ctx, argv[0], argv,
                                  NULL, NULL, NULL, ASSUAN_PIPE_CONNECT_DETACHED);
    if (gpg_ret != GPG_ERR_NO_ERROR) {
        TRACE_GPG_ERROR("Couldn't start pinentry", gpg_ret);
        ret = authinfo_gpg_error2result(gpg_ret);
        goto pinentry_start_release_context;
    }

#define cmd(...)                                                \
    ret = pinentry_command(pinentry, NULL, NULL, __VA_ARGS__);  \
    if (ret != AUTHINFO_OK) {                                   \
        goto pinentry_start_release_context;                    \
    }

    cmd("OPTION lc-ctype=%s", settings->lc_ctype);
    cmd("OPTION lc-messages=%s", settings->lc_messages);
    cmd("OPTION grab");
    cmd("SETTITLE %s", settings->title);
    cmd("SETDESC %s", settings->description);
    cmd("SETPROMPT %s", settings->prompt);
    cmd("GETPIN", settings->prompt);

#undef cmd

    return AUTHINFO_OK;

pinentry_start_release_context:
    assuan_release(pinentry->ctx);

    return ret;
}

void
pinentry_release(struct pinentry_t *pinentry)
{
    assuan_release(pinentry->ctx);
}

enum authinfo_result_t
pinentry_set_error(struct pinentry_t *pinentry, const char *error)
{
    return pinentry_command(pinentry, NULL, NULL, "SETERROR %s", error);
}

static enum authinfo_result_t
pinentry_command(struct pinentry_t *pinentry,
                 assuan_data_cb_t data_cb, void *arg,
                 const char *fmt, ...)
{
    va_list ap;
    char command[1024];

    gpg_error_t ret;

    va_start(ap, fmt);
    vsnprintf(command, sizeof(command), fmt, ap);

    TRACE("Sending '%s' to pinentry\n", command);

    ret = assuan_transact(pinentry->ctx, command,
                          data_cb, arg, NULL, NULL, NULL, NULL);
    if (ret != GPG_ERR_NO_ERROR) {
        TRACE_GPG_ERROR("Pinentry command failed", ret);
        return authinfo_gpg_error2result(ret);
    }

    return AUTHINFO_OK;
}
