/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */
/**
 * @file   authinfo.c
 * @author Aliaksey Artamonau <aliaksiej.artamonau@gmail.com>
 *
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "authinfo.h"
#include "authinfo_internal.h"

#define DOT "."
#define AUTHINFO "authinfo"
#define DOT_AUTHINFO (DOT AUTHINFO)

/* internal macros */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
/* internal macros end */

/* internal functions prototypes */
static enum authinfo_result_t authinfo_errno2result(int errnum);
static char *authinfo_path_join(const char *dir, const char *name);
static enum authinfo_result_t authinfo_path_probe(const char *path);

static enum authinfo_result_t
authinfo_find_file_in_dir(const char *dir, const char *name, char **pathp);
/* internal functions prototypes end */

static const char *authinfo_result2str[] = {
    [AUTHINFO_OK] = "Success",
    [AUTHINFO_EACCESS] = "Permission denied",
    [AUTHINFO_ENOENT] = "File or directory not found",
    [AUTHINFO_ENOMEM] = "Could not allocate memory",
    [AUTHINFO_TOOBIG] = "Authinfo file is too big",
    [AUTHINFO_EUNKNOWN] = "Unknown error happened",
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
        ret = authinfo_find_file_in_dir(home, DOT_AUTHINFO, path);
        if (ret != AUTHINFO_ENOENT) {
            /* we either successfully found the file or got some error */
            return ret;
        }
    }

    return authinfo_find_file_in_dir(SYSCONF_DIR, AUTHINFO, path);
}

enum authinfo_result_t
authinfo_read_file(const char *path, char *buffer, size_t size)
{
    int fd;

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

        if (size == 0) {
            return AUTHINFO_TOOBIG;
        }

        nread = read(fd, buffer, MIN(size, 0xffff));
        if (nread == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                TRACE("Could not read authinfo file: %s\n", strerror(errno));
                return authinfo_errno2result(errno);
            }
        } else if (nread == 0) {
            assert(size != 0);
            *buffer = '\0';
            return AUTHINFO_OK;
        }

        assert(size >= nread);

        size -= nread;
        buffer += nread;
    }
}

/* internal */
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
