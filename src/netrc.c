/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */
/**
 * @file   netrc.c
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

#include "netrc.h"
#include "netrc_internal.h"

#define DOT "."
#define NETRC "netrc"
#define DOT_NETRC (DOT NETRC)

/* internal macros */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
/* internal macros end */

/* internal functions prototypes */
static enum netrc_result_t netrc_errno2result(int errnum);
static char *netrc_path_join(const char *dir, const char *name);
static enum netrc_result_t netrc_path_probe(const char *path);
static enum netrc_result_t netrc_find_file_in_dir(const char *dir,
                                                  const char *name,
                                                  char **pathp);
/* internal functions prototypes end */

static const char *netrc_result2str[] = {
    [NETRC_OK] = "Success",
    [NETRC_EACCESS] = "Permission denied",
    [NETRC_ENOENT] = "File or directory not found",
    [NETRC_ENOMEM] = "Could not allocate memory",
    [NETRC_TOOBIG] = "Netrc file is too big",
    [NETRC_EUNKNOWN] = "Unknown error happened",
};

const char *
netrc_strerror(enum netrc_result_t status)
{
    if (status >= NETRC_RESULT_MAX) {
        return "Got unexpected status code";
    }

    return netrc_result2str[status];
}

enum netrc_result_t
netrc_find_file(char **path)
{
    char *home;
    enum netrc_result_t ret;

    home = getenv("HOME");
    if (home) {
        ret = netrc_find_file_in_dir(home, DOT_NETRC, path);
        if (ret != NETRC_ENOENT) {
            /* we either successfully found the file or got some error */
            return ret;
        }
    }

    return netrc_find_file_in_dir(SYSCONF_DIR, NETRC, path);
}

enum netrc_result_t
netrc_read_file(const char *path, char *buffer, size_t size)
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
            TRACE("Could not open netrc file: %s\n", strerror(errno));
            return netrc_errno2result(errno);
        }
    }

    while (true) {
        ssize_t nread;

        if (size == 0) {
            return NETRC_TOOBIG;
        }

        nread = read(fd, buffer, MIN(size, 0xffff));
        if (nread == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                TRACE("Could not read netrc file: %s\n", strerror(errno));
                return netrc_errno2result(errno);
            }
        } else if (nread == 0) {
            assert(size != 0);
            *buffer = '\0';
            return NETRC_OK;
        }

        assert(size >= nread);

        size -= nread;
        buffer += nread;
    }
}

/* internal */
static enum netrc_result_t
netrc_errno2result(int errnum)
{
    enum netrc_result_t ret;

    switch (errnum) {
    case EACCES:
        ret = NETRC_EACCESS;
        break;
    case ENOENT:
    case ENOTDIR:
    case ELOOP:
        ret = NETRC_ENOENT;
        break;
    case ENOMEM:
        ret = NETRC_ENOMEM;
        break;
    default:
        ret = NETRC_EUNKNOWN;
    }

    return ret;
}

static char *
netrc_path_join(const char *dir, const char *name)
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

static enum netrc_result_t
netrc_find_file_in_dir(const char *dir, const char *name, char **pathp)
{
    char *path;
    enum netrc_result_t ret;

    path = netrc_path_join(dir, name);
    if (!path) {
        return NETRC_ENOMEM;
    }
    *pathp = path;

    ret = netrc_path_probe(path);
    TRACE("Probed %s: %s\n", path, netrc_strerror(ret));

    if (ret != NETRC_OK) {
        free(path);
    }

    return ret;
}

static enum netrc_result_t
netrc_path_probe(const char *path)
{
    enum netrc_result_t ret = NETRC_OK;

    if (access(path, R_OK) != 0) {
        ret = netrc_errno2result(errno);
    }

    return ret;
}
