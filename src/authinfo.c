/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */
/**
 * @file   authinfo.c
 * @author Aliaksey Artamonau <aliaksiej.artamonau@gmail.com>
 *
 */

#include "config.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#ifdef HAVE_GPGME
#include <locale.h>
#include <gpgme.h>
#include "base64.h"
#endif

#include "authinfo.h"
#include "authinfo_internal.h"

#define DOT "."
#define GPG_EXT ".gpg"
#define GPG_PREFIX "gpg:"
#define TOKEN_SIZE_MAX 8192

struct authinfo_password_t {
    char data[TOKEN_SIZE_MAX];
    bool encrypted;
};

struct authinfo_stream_t {
    const char *data;
    size_t size;

    unsigned int line;
    unsigned int column;
};

/* internal macros */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))

#ifdef DEBUG
#define TRACE_GPGME_ERROR(msg, error) \
    do { \
        char buf[128]; \
        gpgme_strerror_r(error, buf, sizeof(buf)); \
        TRACE("%s: %s: %s\n", msg, gpgme_strsource(error), buf); \
    } while (0);
#else
#define TRACE_GPGME_ERROR(msg, error)
#endif  /* DEBUG */
/* internal macros end */

/* internal functions prototypes */
#ifdef HAVE_GPGME
static enum authinfo_result_t authinfo_gpgme_init(void);

static enum authinfo_result_t
authinfo_gpgme_decrypt(char *buf, size_t *data_size, size_t buf_size,
                       gpgme_data_encoding_t encoding);

static enum authinfo_result_t
authinfo_gpgme_error2result(gpgme_error_t error);
#endif  /* HAVE_GPGME */

static bool authinfo_is_gpged_file(const char *path);

static bool authinfo_is_gpged_password(const char *password);

static enum authinfo_result_t authinfo_errno2result(int errnum);

static char *authinfo_path_join(const char *dir, const char *name);

static enum authinfo_result_t authinfo_path_probe(const char *path);

static enum authinfo_result_t
authinfo_find_files_in_dir(const char *dir,
                           const char **name, size_t count, char **pathp);

static enum authinfo_result_t
authinfo_find_file_in_dir(const char *dir, const char *name, char **pathp);

static enum authinfo_result_t
authinfo_do_read_file(const char *path, char *buffer,
                      size_t buffer_size, size_t *data_size);

static int
authinfo_lookahead(struct authinfo_stream_t *stream);

static int
authinfo_next_char(struct authinfo_stream_t *stream);

static void authinfo_skip_spaces(struct authinfo_stream_t *stream);

static bool authinfo_eol(struct authinfo_stream_t *stream);

static bool authinfo_eof(struct authinfo_stream_t *stream);

static void authinfo_skip_line(struct authinfo_stream_t *stream);

static bool authinfo_skip_comment(struct authinfo_stream_t *stream);

static bool authinfo_skip_macdef(struct authinfo_stream_t *stream);

static bool
authinfo_next_token(struct authinfo_stream_t *stream, char *token,
                    struct authinfo_parse_error_t *error);

static bool
authinfo_quoted_token(struct authinfo_stream_t *stream, char *token,
                      struct authinfo_parse_error_t *error);

static bool authinfo_report_entry(authinfo_parse_entry_cb_t entry_callback,
                                  authinfo_parse_error_cb_t error_callback,
                                  void *arg,
                                  unsigned int line,
                                  const struct authinfo_parse_entry_t *entry);

static bool
authinfo_report_error(authinfo_parse_error_cb_t error_callback, void *arg,
                      enum authinfo_parse_error_type_t type,
                      unsigned int line, unsigned int column);
/* internal functions prototypes end */

enum authinfo_result_t
authinfo_init(void)
{
#ifdef HAVE_GPGME
    return authinfo_gpgme_init();
#else
    return AUTHINFO_OK;
#endif  /* HAVE_GPGME */
}

static const char *authinfo_result2str[] = {
    [AUTHINFO_OK] = "Success",
    [AUTHINFO_EACCESS] = "Permission denied",
    [AUTHINFO_ENOENT] = "File or directory not found",
    [AUTHINFO_ENOMEM] = "Could not allocate memory",
    [AUTHINFO_ETOOBIG] = "Authinfo file is too big",
    [AUTHINFO_EUNKNOWN] = "Unknown error happened",
    [AUTHINFO_EGPGME] = "Unknown GPGME error",
    [AUTHINFO_EGPGME_DECRYPT_FAILED] = "Decryption failed",
    [AUTHINFO_EGPGME_BAD_PASSPHRASE] = "Bad passphrase supplied",
    [AUTHINFO_EGPGME_BAD_BASE64] = "Malformed base64-encoded password",
    [AUTHINFO_ENOGPGME] = "Library built without GPG support"
};

const char *
authinfo_strerror(enum authinfo_result_t status)
{
    if (status >= AUTHINFO_RESULT_MAX) {
        return "Got unexpected status code";
    }

    return authinfo_result2str[status];
}

enum authinfo_result_t
authinfo_find_file(char **path)
{
    char *home;
    enum authinfo_result_t ret;

    home = getenv("HOME");
    if (home) {
        const char *names[] = { DOT "authinfo",
                                DOT "netrc" };

        ret = authinfo_find_files_in_dir(home, names, ARRAY_SIZE(names), path);
        if (ret != AUTHINFO_ENOENT) {
            return ret;
        }
    }

    const char *names[] = { "authinfo",
                            "netrc" };

    return authinfo_find_files_in_dir(SYSCONF_DIR, names,
                                      ARRAY_SIZE(names), path);
}

enum authinfo_result_t
authinfo_read_file(const char *path, char *buffer, size_t *size)
{
    enum authinfo_result_t ret;
    size_t data_size;

    ret = authinfo_do_read_file(path, buffer, *size, &data_size);
    if (ret != AUTHINFO_OK) {
        return ret;
    }

    if (authinfo_is_gpged_file(path)) {
#ifdef HAVE_GPGME
        assert(data_size <= *size);
        ret = authinfo_gpgme_decrypt(buffer, &data_size, *size,
                                     GPGME_DATA_ENCODING_NONE);
#else
        ret = AUTHINFO_ENOGPGME;
#endif  /* HAVE_GPGME */
    }

    if (ret == AUTHINFO_OK) {
        *size = data_size;
    }

    return ret;
}

enum parse_state_t {
    LINE_START,
    WAITING_NEXT_PAIR,
    WAITING_HOST,
    WAITING_PROTOCOL,
    WAITING_USER,
    WAITING_PASSWORD,
    WAITING_FORCE,
    LINE_END,
    PARSE_STATE_MAX
};

#ifdef DEBUG
const char *parse_state2str(enum parse_state_t state)
{
    const char *strs[] = {
        [LINE_START] = "LINE_START",
        [WAITING_NEXT_PAIR] = "WAITING_NEXT_PAIR",
        [WAITING_HOST] = "WAITING_HOST",
        [WAITING_PROTOCOL] = "WAITING_PROTOCOL",
        [WAITING_USER] = "WAITING_USER",
        [WAITING_PASSWORD] = "WAITING_PASSWORD",
        [WAITING_FORCE] = "WAITING_FORCE",
        [LINE_END] = "LINE_END"
    };

    if (state >= PARSE_STATE_MAX) {
        return "UNKNOWN";
    } else {
        return strs[state];
    }
}
#endif

void
authinfo_parse(const char *data, size_t size,
               void *arg,
               authinfo_parse_entry_cb_t entry_callback,
               authinfo_parse_error_cb_t error_callback)
{
    char host[TOKEN_SIZE_MAX];
    char protocol[TOKEN_SIZE_MAX];
    char user[TOKEN_SIZE_MAX];
    struct authinfo_password_t password;

    struct authinfo_parse_entry_t entry;

    bool stop = false;

    enum parse_state_t state = LINE_START;

    struct authinfo_stream_t stream = {
        .data = data,
        .size = size,
        .line = 1,
        .column = 0,
    };

    while (!stop) {
        char token[TOKEN_SIZE_MAX];
        struct authinfo_parse_error_t parse_error;

        unsigned long token_column = stream.column;
        authinfo_skip_spaces(&stream);

        TRACE("\n");
        TRACE("State: %s\n", parse_state2str(state));
        TRACE("Position: %u:%u\n", stream.line, stream.column);

        if (authinfo_eol(&stream)) {
            TRACE("Encountered EOL at %u:%u\n", stream.line, stream.column);

            switch (state) {
            case LINE_START:
                /* is this really a EOF? */
                if (authinfo_eof(&stream)) {
                    TRACE("Encountered EOF at %u:%u\n",
                          stream.line, stream.column);
                    stop = true;
                } else {
                    TRACE("Skipping empty line %u\n", stream.line);
                    /* we haven't read anything; just go to the next line */
                    authinfo_skip_line(&stream);
                }
                continue;
            case WAITING_NEXT_PAIR:
                /* report the entry */
                state = LINE_END;
                break;
            default:
                state = LINE_END;
                /* we were waiting for some value; report an error */
                stop = authinfo_report_error(error_callback, arg,
                                             AUTHINFO_PET_MISSING_VALUE,
                                             stream.line, token_column);

            }
        }

        TRACE("Updated state: %s\n", parse_state2str(state));

        switch (state) {
        case LINE_START:
            entry.host = NULL;
            entry.protocol = NULL;
            entry.user = NULL;
            entry.password = NULL;
            entry.force = false;

            if (!authinfo_skip_comment(&stream)) {
                if (!authinfo_skip_macdef(&stream)) {
                    state = WAITING_NEXT_PAIR;
                }
            }

            break;
        case LINE_END:
            stop = authinfo_report_entry(entry_callback, error_callback, arg,
                                         stream.line, &entry);
            authinfo_skip_line(&stream);
            state = LINE_START;
            break;
        case WAITING_NEXT_PAIR:
            if (authinfo_next_token(&stream, token, &parse_error)) {
                bool report_duplicate = false;

                TRACE("Read token \"%s\"\n", token);

                if (strcmp(token, "default") == 0) {
                    /* empty will indicate the default match entry */
                    host[0] = '\0';
                    report_duplicate = (entry.host != NULL);
                    entry.host = host;
                } else if (strcmp(token, "machine") == 0 ||
                           strcmp(token, "host") == 0) {
                    state = WAITING_HOST;
                    report_duplicate = (entry.host != NULL);
                } else if (strcmp(token, "login") == 0 ||
                           strcmp(token, "user") == 0 ||
                           strcmp(token, "account") == 0) {
                    state = WAITING_USER;
                    report_duplicate = (entry.user != NULL);
                } else if (strcmp(token, "password") == 0) {
                    state = WAITING_PASSWORD;
                    report_duplicate = (entry.password != NULL);
                } else if (strcmp(token, "force") == 0) {
                    state = WAITING_FORCE;
                    report_duplicate = entry.force;
                } else if (strcmp(token, "port") == 0 ||
                           strcmp(token, "protocol") == 0) {
                    state = WAITING_PROTOCOL;
                    report_duplicate = (entry.protocol != NULL);
                } else {
                    stop = authinfo_report_error(error_callback, arg,
                                                 AUTHINFO_PET_BAD_KEYWORD,
                                                 stream.line, token_column);
                }

                if (report_duplicate) {
                    stop = authinfo_report_error(error_callback, arg,
                                                 AUTHINFO_PET_DUPLICATED_KEYWORD,
                                                 stream.line, token_column);

                }
            } else {
                TRACE("Failed to read token at (%u:%u): %s\n",
                      parse_error.line, parse_error.column,
                      authinfo_parse_strerror(parse_error.type));

                switch (parse_error.type) {
                case AUTHINFO_PET_VALUE_TOO_LONG:
                    stop = authinfo_report_error(error_callback, arg,
                                                 AUTHINFO_PET_BAD_KEYWORD,
                                                 parse_error.line,
                                                 parse_error.column);
                    break;
                default:
                    stop = authinfo_report_error(error_callback, arg,
                                                 parse_error.type,
                                                 parse_error.line,
                                                 parse_error.column);
                }
            }
            break;
        case WAITING_HOST:
        case WAITING_PROTOCOL:
        case WAITING_USER:
        case WAITING_PASSWORD:
        case WAITING_FORCE:
            if (authinfo_next_token(&stream, token, &parse_error)) {
                TRACE("Read token \"%s\"\n", token);

                switch (state) {
                case WAITING_FORCE:
                    if (strcmp(token, "yes") == 0) {
                        entry.force = true;
                    } else {
                        stop = authinfo_report_error(error_callback, arg,
                                                     AUTHINFO_PET_BAD_VALUE,
                                                     stream.line, token_column);
                    }

                    break;

#define ASSIGN(name) if (entry.name == NULL) {   \
                        strcpy(name, token);     \
                        entry.name = name;       \
                     }

                case WAITING_HOST:
                    ASSIGN(host);
                    break;
                case WAITING_PROTOCOL:
                    ASSIGN(protocol);
                    break;
                case WAITING_USER:
                    ASSIGN(user);
                    break;
                case WAITING_PASSWORD:
                    if (entry.password == NULL) {
                        strcpy(password.data, token);
                        password.encrypted = authinfo_is_gpged_password(token);
                        entry.password = &password;
                    }
                    break;
                default:
                    /* should not happen */
                    assert(false);

                }
#undef ASSIGN

                state = WAITING_NEXT_PAIR;
            } else {
                stop = authinfo_report_error(error_callback, arg,
                                             parse_error.type,
                                             parse_error.line,
                                             parse_error.column);
                state = WAITING_NEXT_PAIR;
            }

            break;
        default:
            /* should not happen */
            assert(false);
        }
    }
}


static const char *authinfo_parse_error_type2str[] = {
    [AUTHINFO_PET_MISSING_HOST] = "Host not specified",
    [AUTHINFO_PET_MISSING_VALUE] = "Expected a value",
    [AUTHINFO_PET_VALUE_TOO_LONG] = "Value is too long",
    [AUTHINFO_PET_BAD_VALUE] = "Invalid value",
    [AUTHINFO_PET_BAD_KEYWORD] = "Unknown keyword used",
    [AUTHINFO_PET_DUPLICATED_KEYWORD] = "Duplicate or synonymous keyword",
    [AUTHINFO_PET_UNTERMINATED_QUOTED_TOKEN] = "Quoted token ended unexpectedly",
    [AUTHINFO_PET_UNSUPPORTED_ESCAPE] = "Unsupported escape sequence"
};

const char *
authinfo_parse_strerror(enum authinfo_parse_error_type_t error)
{
    if (error >= AUTHINFO_PET_MAX) {
        return "Unknown";
    } else {
        return authinfo_parse_error_type2str[error];
    }
}

enum authinfo_result_t
authinfo_password_extract(struct authinfo_password_t *password,
                          const char **data)
{
    enum authinfo_result_t ret = AUTHINFO_OK;

    if (password->encrypted) {
#ifdef HAVE_GPGME
        int n;
        size_t password_length = strlen(password->data) - strlen(GPG_PREFIX);
        char b64_password[password_length + 1];
        char raw_password[TOKEN_SIZE_MAX];

        assert(password_length < TOKEN_SIZE_MAX);

        strcpy(b64_password, password->data + strlen(GPG_PREFIX));
        n = base64_decode((uint8_t *) raw_password,
                          b64_password, TOKEN_SIZE_MAX);
        if (n == -1) {
            ret = AUTHINFO_EGPGME_BAD_BASE64;
        } else {
            size_t data_length = n;

            assert(data_length < password_length);
            ret = authinfo_gpgme_decrypt(raw_password, &data_length,
                                         TOKEN_SIZE_MAX - 1,
                                         GPGME_DATA_ENCODING_NONE);
            if (ret == AUTHINFO_OK) {
                assert(data_length < TOKEN_SIZE_MAX);

                memcpy(password->data, raw_password, data_length);
                password->data[data_length] = '\0';
                password->encrypted = false; /* in case we are called again */
            }
        }
#else
        ret = AUTHINFO_ENOGPGME;
#endif
    }

    if (ret == AUTHINFO_OK) {
        *data = password->data;
    }

    return ret;
}

/* internal */

#ifdef HAVE_GPGME

static enum authinfo_result_t
authinfo_gpgme_init(void)
{
    gpgme_error_t ret;

    gpgme_check_version(NULL);

    ret = gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_ALL, NULL));
    if (ret != GPG_ERR_NO_ERROR) {
        TRACE_GPGME_ERROR("Couldn't set GPGME locale", ret);
        return authinfo_gpgme_error2result(ret);
    }

#ifdef LC_MESSAGES
    ret = gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
    if (ret != GPG_ERR_NO_ERROR) {
        TRACE_GPGME_ERROR("Couldn't set GPGME locale", ret);
        return authinfo_gpgme_error2result(ret);
    }

#endif  /* LC_MESSAGES */

    return AUTHINFO_OK;
}

static enum authinfo_result_t
authinfo_gpgme_decrypt(char *buf, size_t *data_size, size_t buf_size,
                       gpgme_data_encoding_t encoding)
{
    gpgme_error_t gpgme_ret;
    gpgme_ctx_t ctx;
    gpgme_data_t cipher;
    gpgme_data_t plain;
    char *plain_data;
    size_t plain_length;

    enum authinfo_result_t ret = AUTHINFO_OK;

    gpgme_ret = gpgme_new(&ctx);
    if (gpgme_ret != GPG_ERR_NO_ERROR) {
        TRACE_GPGME_ERROR("Could not create GPGME context", gpgme_ret);
        return authinfo_gpgme_error2result(gpgme_ret);
    }

    gpgme_ret = gpgme_data_new_from_mem(&cipher, buf, *data_size, 1);
    if (gpgme_ret != GPG_ERR_NO_ERROR) {
        TRACE_GPGME_ERROR("Could not create GPGME data buffer", gpgme_ret);
        ret = authinfo_gpgme_error2result(gpgme_ret);
        goto gpgme_decrypt_release_ctx;
    }

    gpgme_ret = gpgme_data_set_encoding(cipher, encoding);
    if (gpgme_ret != GPG_ERR_NO_ERROR) {
        TRACE_GPGME_ERROR("Could not set buffer data encoding", gpgme_ret);
        ret = authinfo_gpgme_error2result(gpgme_ret);
        goto gpgme_decrypt_release_cipher;
    }

    gpgme_ret = gpgme_data_new(&plain);
    if (gpgme_ret != GPG_ERR_NO_ERROR) {
        TRACE_GPGME_ERROR("Could not create GPGME data buffer", gpgme_ret);
        ret = authinfo_gpgme_error2result(gpgme_ret);
        goto gpgme_decrypt_release_cipher;
    }

    gpgme_ret = gpgme_op_decrypt(ctx, cipher, plain);
    if (gpgme_ret != GPG_ERR_NO_ERROR) {
        TRACE_GPGME_ERROR("Could not decrypt cipher text", gpgme_ret);
        ret = authinfo_gpgme_error2result(gpgme_ret);
        goto gpgme_decrypt_release_plain;
    }

    plain_data = gpgme_data_release_and_get_mem(plain, &plain_length);
    if (plain_length > buf_size) {
        ret = AUTHINFO_ETOOBIG;
    } else {
        memcpy(buf, plain_data, plain_length);
        *data_size = plain_length;
    }

    gpgme_free(plain_data);
    goto gpgme_decrypt_release_cipher;

gpgme_decrypt_release_plain:
    gpgme_data_release(plain);
gpgme_decrypt_release_cipher:
    gpgme_data_release(cipher);
gpgme_decrypt_release_ctx:
    gpgme_release(ctx);

    return ret;
}

static enum authinfo_result_t
authinfo_gpgme_error2result(gpgme_error_t error)
{
    switch (gpg_err_code(error)) {
    case GPG_ERR_DECRYPT_FAILED:
        return AUTHINFO_EGPGME_DECRYPT_FAILED;
    case GPG_ERR_BAD_PASSPHRASE:
        return AUTHINFO_EGPGME_BAD_PASSPHRASE;
    default:
        return AUTHINFO_EGPGME;
    }
}

#endif  /* HAVE_GPGME */

static bool
authinfo_is_gpged_file(const char *path)
{
    size_t extlen = strlen(GPG_EXT);
    size_t n = strlen(path);

    if (n < extlen) {
        return false;
    }

    path += n - extlen;
    return (strcasecmp(path, GPG_EXT) == 0);
}

static bool
authinfo_is_gpged_password(const char *password)
{
    return (strncmp(password, GPG_PREFIX, strlen(GPG_PREFIX)) == 0);
}

static enum authinfo_result_t
authinfo_errno2result(int errnum)
{
    enum authinfo_result_t ret;

    switch (errnum) {
    case EACCES:
        ret = AUTHINFO_EACCESS;
        break;
    case ENOENT:
    case ENOTDIR:
    case ELOOP:
        ret = AUTHINFO_ENOENT;
        break;
    case ENOMEM:
        ret = AUTHINFO_ENOMEM;
        break;
    default:
        ret = AUTHINFO_EUNKNOWN;
    }

    return ret;
}

static char *
authinfo_path_join(const char *dir, const char *name)
{
    char *path = NULL;
    size_t length = strlen(dir) + strlen(name) + 2;

    path = malloc(length);
    if (!path) {
        TRACE("could not allocate %zu bytes\n", length);
        return NULL;
    }

    snprintf(path, length, "%s/%s", dir, name);
    return path;
}

static enum authinfo_result_t
authinfo_find_files_in_dir(const char *dir,
                           const char **names, size_t count, char **path)
{
    enum authinfo_result_t ret = AUTHINFO_ENOENT;

    for (int i = 0; i < count; ++i) {
        const char *name = names[i];

#ifdef HAVE_GPGME
        /* probe GPGed file first */
        size_t name_length = strlen(name);
        char gpged_name[name_length + strlen(GPG_EXT) + 1];

        memcpy(gpged_name, name, name_length);
        strcpy(gpged_name + name_length, GPG_EXT);

        ret = authinfo_find_file_in_dir(dir, gpged_name, path);
        if (ret != AUTHINFO_ENOENT) {
            break;
        }
#endif  /* HAVE_GPGME */

        ret = authinfo_find_file_in_dir(dir, name, path);
        if (ret != AUTHINFO_ENOENT) {
            break;
        }
    }

    return ret;
}

static enum authinfo_result_t
authinfo_find_file_in_dir(const char *dir, const char *name, char **pathp)
{
    char *path;
    enum authinfo_result_t ret;

    path = authinfo_path_join(dir, name);
    if (!path) {
        return AUTHINFO_ENOMEM;
    }
    *pathp = path;

    ret = authinfo_path_probe(path);
    TRACE("Probed %s: %s\n", path, authinfo_strerror(ret));

    if (ret != AUTHINFO_OK) {
        free(path);
    }

    return ret;
}

static enum authinfo_result_t
authinfo_path_probe(const char *path)
{
    enum authinfo_result_t ret = AUTHINFO_OK;

    if (access(path, R_OK) != 0) {
        ret = authinfo_errno2result(errno);
    }

    return ret;
}

static enum authinfo_result_t
authinfo_do_read_file(const char *path, char *buffer,
                      size_t buffer_size, size_t *data_size)
{
    int fd;
    char *buffer_start = buffer;

    while (true) {
        fd = open(path, O_RDONLY);
        if (fd != -1) {
            break;
        }

        if (errno == EINTR) {
            continue;
        } else {
            TRACE("Could not open authinfo file: %s\n", strerror(errno));
            return authinfo_errno2result(errno);
        }
    }

    while (true) {
        ssize_t nread;

        if (buffer_size == 0) {
            /* it's not completely correct to return an error here because
             * it's possible that the file is exactly the size of the buffer;
             * but we'll ignore this rare case */
            return AUTHINFO_ETOOBIG;
        }

        nread = read(fd, buffer, MIN(buffer_size, 0xffff));
        if (nread == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                TRACE("Could not read authinfo file: %s\n", strerror(errno));
                return authinfo_errno2result(errno);
            }
        } else if (nread == 0) {
            assert(buffer_size != 0);
            *data_size = buffer - buffer_start;
            return AUTHINFO_OK;
        }

        assert(buffer_size >= nread);

        buffer_size -= nread;
        buffer += nread;
    }
}

static int
authinfo_lookahead(struct authinfo_stream_t *stream)
{
    assert(stream->size);
    return *stream->data;
}

static int
authinfo_next_char(struct authinfo_stream_t *stream)
{
    int c;

    assert(stream->size);
    c = *stream->data;

    stream->data += 1;
    stream->size -= 1;
    if (c == '\n') {
        stream->line += 1;
        stream->column = 0;
    } else {
        stream->column += 1;
    }

    return c;
}

static void
authinfo_skip_spaces(struct authinfo_stream_t *stream)
{
    while (!authinfo_eof(stream)) {
        int c = authinfo_lookahead(stream);
        if (c != ' ' && c != '\t') {
            break;
        }

        (void) authinfo_next_char(stream);
    }
}

static bool
authinfo_eol(struct authinfo_stream_t *stream)
{
    return authinfo_eof(stream) || authinfo_lookahead(stream) == '\n';
}

static bool
authinfo_eof(struct authinfo_stream_t *stream)
{
    return stream->size == 0;
}

static void
authinfo_skip_line(struct authinfo_stream_t *stream)
{
    while (!authinfo_eof(stream) &&
           authinfo_lookahead(stream) != '\n') {
        (void) authinfo_next_char(stream);
    }

    if (!authinfo_eof(stream)) {
        /* we stopped on new line so we want to skip it */
        (void) authinfo_next_char(stream);
    }
}

static bool
authinfo_skip_comment(struct authinfo_stream_t *stream)
{
    /* this is ensured by authinfo_parse function */
    assert(!authinfo_eof(stream));

    if (authinfo_lookahead(stream) == '#') {
        TRACE("Skipping comment at line %u\n", stream->line);
        authinfo_skip_line(stream);
        return true;
    }

    return false;
}

static bool
authinfo_skip_macdef(struct authinfo_stream_t *stream)
{
    char token[TOKEN_SIZE_MAX];

    struct authinfo_stream_t tmp_stream = *stream;

    if (authinfo_next_token(&tmp_stream, token, NULL) &&
        strcmp(token, "macdef") == 0) {

        do {
            authinfo_skip_line(&tmp_stream);
        } while (!authinfo_eol(&tmp_stream));

        TRACE("Skipped macdef on lines %u-%u\n", stream->line, tmp_stream.line);

        /* skip current empty line (if any) */
        authinfo_skip_line(&tmp_stream);

        *stream = tmp_stream;

        return true;
    }

    return false;
}

static bool
authinfo_report_entry(authinfo_parse_entry_cb_t entry_callback,
                      authinfo_parse_error_cb_t error_callback,
                      void *arg,
                      unsigned int line,
                      const struct authinfo_parse_entry_t *entry)
{
    bool stop;
    struct authinfo_parse_entry_t e = *entry;

    if (!e.host) {
        /* missing host is an error */
        return authinfo_report_error(error_callback, arg,
                                     AUTHINFO_PET_MISSING_HOST, line, 0);
    }

    /* if host is empty it means that this's a "default" entry; we report
     * this by setting host to NULL */
    if (strcmp(e.host, "") == 0) {
        e.host = NULL;
    }

    TRACE("Reporting an entry: host -> %s, protocol -> %s, "
          "user -> %s, password -> %s, force -> %d\n",
          e.host, e.protocol, e.user,
          e.password ? e.password->data : "(null)",
          (int) e.force);
    stop = (*entry_callback)(&e, arg);
    TRACE("    ====> %s\n", stop ? "stopping" : "continuing");

    return stop;
}

static bool
authinfo_report_error(authinfo_parse_error_cb_t error_callback, void *arg,
                      enum authinfo_parse_error_type_t type,
                      unsigned int line, unsigned int column)
{
    struct authinfo_parse_error_t error = {
        .line = line,
        .column = column,
        .type = type
    };

    TRACE("Reporting an error: %s (%u:%u)\n",
          authinfo_parse_strerror(type), line, column);
    bool stop = (*error_callback)(&error, arg);
    TRACE("    ====> %s\n",
          stop ? "stopping" : "continuing");

    return stop;
}

static bool
authinfo_next_token(struct authinfo_stream_t *stream, char *token,
                    struct authinfo_parse_error_t *error)
{
    bool ret = true;
    size_t span;
    struct authinfo_stream_t tmp_stream;

    if (!authinfo_eof(stream) && authinfo_lookahead(stream) == '"') {
        return authinfo_quoted_token(stream, token, error);
    }

    tmp_stream = *stream;
    while (!authinfo_eof(&tmp_stream)) {
        int c = authinfo_lookahead(&tmp_stream);
        if (c == ' ' || c == '\t' || c == '\n') {
            break;
        }

        (void) authinfo_next_char(&tmp_stream);
    }

    span = tmp_stream.data - stream->data;
    if (span >= TOKEN_SIZE_MAX) {
        if (error != NULL) {
            error->type = AUTHINFO_PET_VALUE_TOO_LONG;
            error->line = stream->line;
            error->column = stream->column;
        }
        ret = false;
    } else {
        memcpy(token, stream->data, span);
        token[span] = '\0';
    }

    *stream = tmp_stream;

    return ret;
}

static bool
authinfo_quoted_token(struct authinfo_stream_t *stream, char *token,
                      struct authinfo_parse_error_t *error)
{
    enum { NORMAL,
           SEEN_BACKSLASH,
           DONE } state = NORMAL;
    unsigned long token_column = stream->column;
    size_t nwritten = 0;
    bool error_occurred = false;
    int c;

    c = authinfo_next_char(stream);
    assert(c == '"');

    while (state != DONE) {
        if (authinfo_eol(stream)) {
            error_occurred = true;
            if (error != NULL) {
                error->type = AUTHINFO_PET_UNTERMINATED_QUOTED_TOKEN;
                error->line = stream->line;
                error->column = stream->column;
            }
            break;
        }

        /* this is safe because authinfo_eol above prevents us from hitting
         * EOF */
        c = authinfo_lookahead(stream);

        switch (state) {
        case NORMAL:
            switch (c) {
            case '"':
                state = DONE;
                break;
            case '\\':
                state = SEEN_BACKSLASH;
                break;
            default:
                if (!error_occurred) {
                    token[nwritten++] = c;
                }
            }
            break;
        case SEEN_BACKSLASH:
            switch (c) {
            case '"':
                if (!error_occurred) {
                    token[nwritten++] = '"';
                }
                state = NORMAL;
                break;
            case '\\':
                if (!error_occurred) {
                    token[nwritten++] = '\\';
                }
                state = NORMAL;
                break;
            default:
                if (!error_occurred) {
                    error_occurred = true;
                    if (error != NULL) {
                        error->type = AUTHINFO_PET_UNSUPPORTED_ESCAPE;
                        error->line = stream->line;
                        error->column = stream->column - 1;
                    }
                }
                state = NORMAL;
            }
            break;
        default:
            /* should not happen */
            assert(false);
        }

        if (state != DONE && nwritten >= (TOKEN_SIZE_MAX - 1)) {
            error_occurred = true;
            if (error != NULL) {
                error->type = AUTHINFO_PET_VALUE_TOO_LONG;
                error->line = stream->line;
                error->column = token_column;
            }
        }

        (void) authinfo_next_char(stream);
    }

    token[nwritten] = '\0';

    return !error_occurred;
}
