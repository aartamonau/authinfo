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

#ifdef __GNUC__
#define EXPORT_FUNCTION __attribute__((visibility("default")))
#else
#define EXPORT_FUNCTION
#endif

/// Indicates if certain call completed successfully
enum authinfo_result_t {
    AUTHINFO_OK,                /**< Everything went fine. */
    AUTHINFO_EACCESS,           /**< Couldn't access some path. */
    AUTHINFO_ENOENT,            /**< Path does not exist.  */
    AUTHINFO_ENOMEM,            /**< Not enough memory. */
    AUTHINFO_ETOOBIG,           /**< Authinfo file is too big. */
    AUTHINFO_EUNKNOWN,          /**< Some unexpected condition happened. */
    AUTHINFO_EGPGME,            /**< Generic GPGME error. */
    AUTHINFO_ENOGPGME,          /**< Library compiled without GPG support */
    AUTHINFO_RESULT_MAX
};

/**
 * Initialize authinfo library. Should be called before any other function in
 * the library. And if your program is multithreaded, it must be called in a
 * single thread.
 *
 * @return result
 */
EXPORT_FUNCTION enum authinfo_result_t authinfo_init(void);

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

/// Opaque representation of a password.
struct authinfo_password_t;

/// Represents an entry in authinfo file.
struct authinfo_parse_entry_t {
    const char *host;           /**< Host. Empty for the "default" entry. */
    const char *protocol;       /**< Protocol. NULL if omitted. */
    const char *user;           /**< User. NULL if omitted. */
    struct authinfo_password_t *password; /**< Password. NULL if omitted. */
    bool force;                 /**< Force. 'false' by default. */
};

/// A callback that is called for every entry in the file. The callback takes
/// a parsed entry and an arbitrary argument passed to authinfo_parse(). The
/// callback should return a boolean value that indicates if parsing should be
/// stopped or continued.
typedef bool
(*authinfo_parse_entry_cb_t)(const struct authinfo_parse_entry_t *, void *);

/// Possible parsing error.
enum authinfo_parse_error_type_t {
    AUTHINFO_PET_MISSING_HOST,  /**< Host name was not specified. */
    AUTHINFO_PET_MISSING_VALUE, /**< Expected a value but got nothing. */
    AUTHINFO_PET_VALUE_TOO_LONG, /**< Value is too long to be handled. */
    AUTHINFO_PET_BAD_VALUE,     /**< Invalid value. */
    AUTHINFO_PET_BAD_KEYWORD,   /**< Encountered unknown keyword. */
    AUTHINFO_PET_DUPLICATED_KEYWORD, /**< Encountered duplicate or synonymous
                                      * keyword */
    AUTHINFO_PET_UNTERMINATED_QUOTED_TOKEN, /**< Quoted token ends
                                             * unexpectedly. */
    AUTHINFO_PET_UNSUPPORTED_ESCAPE, /**< Unsupported escape sequence found. */
    AUTHINFO_PET_MAX
};

/**
 * Convert parse error to a human readable description.
 *
 * @param error parse error to describe
 *
 * @return description
 */
EXPORT_FUNCTION const char *
authinfo_parse_strerror(enum authinfo_parse_error_type_t error);

/// A structure representing parsing error.
struct authinfo_parse_error_t {
    unsigned int line;          /**< Line number. */
    unsigned int column;        /**< Column number. */
    enum authinfo_parse_error_type_t type; /**< Error type. */
};

/// A callback that is called for every parsing error. The callback takes
/// error type, line, column and arbitrary argument passed to
/// authinfo_parse(). The callback should return a boolean value that
/// indicates if parsing should be stopped or continued.
typedef bool
(*authinfo_parse_error_cb_t)(const struct authinfo_parse_error_t *, void *);

/**
 * Parse authinfo file.
 *
 * @param data authinfo file as a C string
 * @param arg arbitrary argument that will be passed to callbacks
 * @param entry_callback a callback to be called for every parsed entry
 * @param error_callback a callback to be called for every parsing error
 */
EXPORT_FUNCTION void authinfo_parse(const char *data, void *arg,
                                    authinfo_parse_entry_cb_t entry_callback,
                                    authinfo_parse_error_cb_t error_callback);

/**
 * Extracts a password from #authinfo_password_t structure. Extracted password
 * is returned in @em data. Note that it is valid only during entry callback
 * execution. It should be copied, if longer lifetime is required.
 *
 * @param password #authinfo_password_t structure to extract password from
 * @param[out] data extracted password is returned here
 *
 * @return status
 */
EXPORT_FUNCTION enum authinfo_result_t
authinfo_password_extract(struct authinfo_password_t *password,
                          const char **data);

#endif /* _AUTHINFO_H_ */
