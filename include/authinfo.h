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

#endif /* _AUTHINFO_H_ */
