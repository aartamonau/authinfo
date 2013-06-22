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

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif  /* __cplusplus */

/// Indicates if certain call completed successfully
enum authinfo_result_t {
    AUTHINFO_OK,                /**< Everything went fine. */
    AUTHINFO_EACCESS,           /**< Couldn't access some path. */
    AUTHINFO_ENOENT,            /**< Path does not exist.  */
    AUTHINFO_ENOMEM,            /**< Not enough memory. */
    AUTHINFO_ETOOBIG,           /**< Authinfo file is too big. */
    AUTHINFO_EUNKNOWN,          /**< Some unexpected condition happened. */
    AUTHINFO_EGPGME,            /**< Generic GPGME error. */
    AUTHINFO_EGPGME_DECRYPT_FAILED, /**< Decryption failed. */
    AUTHINFO_EGPGME_BAD_PASSPHRASE, /**< Invalid passphrase supplied. */
    AUTHINFO_EGPGME_BAD_BASE64, /**< Malformed base64-encoded password. */
    AUTHINFO_ENOGPGME,          /**< Library compiled without GPG support */
    AUTHINFO_ENOMATCH,          /**< No matching entry was found. */
    AUTHINFO_EPARSE,            /**< Parse error. */
    AUTHINFO_RESULT_MAX
};

/**
 * Initialize authinfo library. Should be called before any other function in
 * the library. And if your program is multithreaded, it must be called in a
 * single thread.
 *
 * Among other things this function will query current locale to set up GPG
 * accordingly. So you might want to call setlocale to set it to the desired
 * value.
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
 * Find an authinfo file to use.
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
 * @param[in,out] size buffer size; after authinfo_read_file() completes
 *                     successfully the size of the actual data is returned
 *                     via this parameter
 *
 * @return status
 */
EXPORT_FUNCTION enum authinfo_result_t
authinfo_read_file(const char *path, char *buffer, size_t *size);

/// Opaque representation of a password.
struct authinfo_password_t;

/// Represents an entry in authinfo file.
struct authinfo_parse_entry_t {
    const char *host;           /**< Host. NULL for the "default" entry. */
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
    AUTHINFO_PET_NO_ERROR,      /**< No error. This is never returned to the
                                 * user. */
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
 * @param data data to parse
 * @param size size of the data
 * @param arg arbitrary argument that will be passed to callbacks
 * @param entry_callback a callback to be called for every parsed entry
 * @param error_callback a callback to be called for every parsing error
 */
EXPORT_FUNCTION void authinfo_parse(const char *data, size_t size,
                                    void *arg,
                                    authinfo_parse_entry_cb_t entry_callback,
                                    authinfo_parse_error_cb_t error_callback);

/**
 * Extracts a password from #authinfo_password_t structure. Extracted password
 * is returned in @em data. Note that returned value is valid only during
 * lifetime of the containing #authinfo_parse_entry_t structure. It should be
 * copied, if longer lifetime is required.
 *
 * @param password #authinfo_password_t structure to extract password from
 * @param[out] data extracted password is returned here
 *
 * @return status
 */
EXPORT_FUNCTION enum authinfo_result_t
authinfo_password_extract(struct authinfo_password_t *password,
                          const char **data);

/**
 * Release resources held by the #authinfo_parse_entry_t structure returned by
 * authinfo_simple_query() function. Note this function *must* not be called
 * on the entries that are passed to the entry callback by authinfo_parse()
 * function.
 *
 * @param entry an entry to free
 */
EXPORT_FUNCTION void
authinfo_parse_entry_free(struct authinfo_parse_entry_t *entry);

/**
 * A shortcut function that looks for the first matching entry in the authinfo
 * file.
 *
 * @param data authinfo file data
 * @param size data size
 * @param host host name to match; NULL matches any host name
 * @param protocol protocol to match; NULL matches everything
 * @param user user to match; NULL matches everything
 * @param[out] entry parsed entry returned here in case of success; after it's
 *             not needed anymore it should be freed by
 *             authinfo_parse_entry_free() function
 * @param[out] error parse error returned here if data could not be parsed
 *
 * @retval AUTHINFO_OK matching entry found
 * @retval AUTHINFO_ENOMATCH no matching entry found
 * @retval AUTHINFO_EPARSE data could not be parsed
 * @retval AUTHINFO_ENOMEM could not allocate memory
 */
EXPORT_FUNCTION enum authinfo_result_t
authinfo_simple_query(const char *data, size_t size,
                      const char *host, const char *protocol, const char *user,
                      struct authinfo_parse_entry_t *entry,
                      struct authinfo_parse_error_t *error);

#ifdef __cplusplus
}
#endif

#endif /* _AUTHINFO_H_ */
