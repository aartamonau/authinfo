/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

#include <stdlib.h>
#include <stdio.h>
#include "authinfo.h"

static void
dump_file(const char *path)
{
    char buf[10240];
    enum authinfo_result_t ret;

    ret = authinfo_read_file(path, buf, sizeof(buf));
    if (ret != AUTHINFO_OK) {
        printf("Could not read authinfo file: %s\n", authinfo_strerror(ret));
        return;
    }

    printf("authinfo file (%s) dump:\n%s", path, buf);
}

int
main(void)
{
    char *authinfo_path;
    int ret;

    ret = authinfo_find_file(&authinfo_path);
    switch (ret) {
    case AUTHINFO_OK:
        printf("Found authinfo file at %s\n", authinfo_path);
        dump_file(authinfo_path);
        ret = EXIT_SUCCESS;
        break;
    case AUTHINFO_ENOENT:
        printf("Couldn't find authinfo file\n");
        ret = EXIT_SUCCESS;
        break;
    default:
        printf("Got unexpected error while "
               "looking for authinfo file: %s\n", authinfo_strerror(ret));
        ret = EXIT_FAILURE;
    }

    return ret;
}
