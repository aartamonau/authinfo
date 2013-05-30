/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

/**
 * @file   authinfo.h
 * @author Aliaksey Artamonau <aliaksiej.artamonau@gmail.com>
 *
 * @brief  libauthinfo public interface
 *
 *
 */

#ifndef _AUTHINFO_H_
#define _AUTHINFO_H_

#include <stdbool.h>
#include "config.h"

/// Indicates if certain call completed successfully
enum authinfo_result_t {
    AUTHINFO_OK,                /**< Everything went fine. */
    AUTHINFO_EACCESS,           /**< Couldn't access some path. */
    AUTHINFO_ENOENT,            /**< Path does not exist.  */
    AUTHINFO_ENOMEM,            /**< Not enough memory. */
    AUTHINFO_TOOBIG,            /**< Authinfo file is too big. */
    AUTHINFO_EUNKNOWN,          /**< Some unexpected condition happened. */
    AUTHINFO_RESULT_MAX
};

/**
 * Return a human readable description for a status code.
 *
 * @param status status to describe
 *
 * @return description
 */
EXPORT_FUNCTION const char *authinfo_strerror(enum authinfo_result_t status);

/**
 * Find a authinfo file to use.
 *
 * @param[out] path Return authinfo file path here. Must be freed by the caller.
 *
 * @return status
 */
EXPORT_FUNCTION enum authinfo_result_t authinfo_find_file(char **path);

/**
 * Read file contents into a buffer
 *
 * @param path file path
 * @param buffer buffer to read the file into
 * @param size buffer size
 *
 * @return status
 */
EXPORT_FUNCTION enum authinfo_result_t
authinfo_read_file(const char *path, char *buffer, size_t size);

/// TODO
struct authinfo_parse_entry_t {
    const char *host;
    const char *protocol;
    const char *user;
    const char *password;
    bool force;
};

/// TODO
typedef bool
(*authinfo_parse_entry_cb_t)(const struct authinfo_parse_entry_t *, void *);

/// TODO
enum authinfo_parse_error_type_t {
    AUTHINFO_PET_MISSING_HOST,
    AUTHINFO_PET_MISSING_VALUE,
    AUTHINFO_PET_VALUE_TOO_LONG,
    AUTHINFO_PET_BAD_VALUE,
    AUTHINFO_PET_BAD_KEYWORD,
    AUTHINFO_PET_DUPLICATED_KEYWORD,
    AUTHINFO_PET_MAX
};

/// TODO
EXPORT_FUNCTION const char *
authinfo_parse_strerror(enum authinfo_parse_error_type_t error);

/// TODO
typedef bool
(*authinfo_parse_error_cb_t)(enum authinfo_parse_error_type_t,
                             unsigned int line, unsigned int column, void *);

/// TODO
EXPORT_FUNCTION void authinfo_parse(const char *data, void *arg,
                                    authinfo_parse_entry_cb_t entry_callback,
                                    authinfo_parse_error_cb_t error_callback);

#endif /* _AUTHINFO_H_ */
