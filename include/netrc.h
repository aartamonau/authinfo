/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

/**
 * @file   netrc.h
 * @author Aliaksey Artamonau <aliaksiej.artamonau@gmail.com>
 *
 * @brief  libnetrc public interface
 *
 *
 */

#ifndef _NETRC_H_
#define _NETRC_H_

#include "config.h"

/// Indicates if certain call completed successfully
enum netrc_result_t {
    NETRC_OK,                   /**< Everything went fine. */
    NETRC_EACCESS,              /**< Couldn't access some path. */
    NETRC_ENOENT,               /**< Path does not exist.  */
    NETRC_ENOMEM,               /**< Not enough memory. */
    NETRC_EUNKNOWN,             /**< Some unexpected condition happened. */
    NETRC_RESULT_MAX
};

/**
 * Return a human readable description for a status code.
 *
 * @param status status to describe
 *
 * @return description
 */
EXPORT_FUNCTION const char *netrc_strerror(enum netrc_result_t status);

/**
 * Find a netrc file to use.
 *
 * @param[out] path Return netrc file path here. Must be freed by the caller.
 *
 * @return status
 */
EXPORT_FUNCTION enum netrc_result_t netrc_find_file(char **path);

#endif /* _NETRC_H_ */
