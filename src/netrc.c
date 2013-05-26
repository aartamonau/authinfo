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

#include "netrc.h"
#include "netrc_internal.h"

#define DOT "."
#define NETRC "netrc"
#define DOT_NETRC (DOT NETRC)

/* internal functions prototypes */
static char *netrc_path_join(const char *dir, const char *name);
static enum netrc_result_t netrc_path_probe(const char *path);
static enum netrc_result_t netrc_find_file_in_dir(const char *dir,
                                                  const char *name,
                                                  char **pathp);
/* internal functions prototypes end */

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

/* internal */
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
    TRACE("Probed %s: %d\n", path, ret);

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
        switch (errno) {
        case ENOENT:
        case ENOTDIR:
        case ELOOP:
            ret = NETRC_ENOENT;
            break;
        case EACCES:
            ret = NETRC_EACCESS;
            break;
        default:
            TRACE("got unexpected error %s\n", strerror(errno));
            ret = NETRC_EUNKNOWN;
        }
    }

    return ret;
}
