/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

#include <stdlib.h>
#include <stdio.h>
#include "netrc.h"

static void
dump_file(const char *path)
{
    char buf[10240];
    enum netrc_result_t ret;

    ret = netrc_read_file(path, buf, sizeof(buf));
    if (ret != NETRC_OK) {
        printf("Could not read netrc file: %s\n", netrc_strerror(ret));
        return;
    }

    printf("netrc file (%s) dump:\n%s", path, buf);
}

int
main(void)
{
    char *netrc_path;
    int ret;

    ret = netrc_find_file(&netrc_path);
    switch (ret) {
    case NETRC_OK:
        printf("Found netrc file at %s\n", netrc_path);
        dump_file(netrc_path);
        ret = EXIT_SUCCESS;
        break;
    case NETRC_ENOENT:
        printf("Couldn't find netrc file\n");
        ret = EXIT_SUCCESS;
        break;
    default:
        printf("Got unexpected error while "
               "looking for netrc file: %s\n", netrc_strerror(ret));
        ret = EXIT_FAILURE;
    }

    return ret;
}
