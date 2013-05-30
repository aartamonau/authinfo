/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

#include <stdlib.h>
#include <stdio.h>
#include "authinfo.h"

static bool
entry_callback(const struct authinfo_parse_entry_t *entry, void *arg)
{
    printf("Entry: host %s, protocol %s, user %s, password %s, force %s\n",
           entry->host, entry->protocol, entry->user, entry->password,
           (entry->force ? "true" : "false"));
    /* don't stop */
    return false;
}

static bool
error_callback(enum authinfo_parse_error_type_t type,
               unsigned int line, unsigned int column, void *arg)
{
    printf("Error in line %u, column %u: %s\n",
           line, column, authinfo_parse_strerror(type));
    /* don't stop */
    return false;
}

static void
parse_file(const char *path)
{
    char buf[10240];
    enum authinfo_result_t ret;

    ret = authinfo_read_file(path, buf, sizeof(buf));
    if (ret != AUTHINFO_OK) {
        printf("Could not read authinfo file: %s\n", authinfo_strerror(ret));
        return;
    }

    printf("\n============================================================\n");
    printf("%s\n", path);
    printf("============================================================\n");
    printf("%s", buf);

    printf("\n=========================parse results=========================\n");
    authinfo_parse(buf, NULL, entry_callback, error_callback);
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
        parse_file(authinfo_path);
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
