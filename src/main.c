/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>

#include "authinfo.h"

enum command_t {
    CMD_QUERY,
    CMD_VALIDATE,
    CMD_VERSION,
    CMD_HELP,
};

enum option_t {
    OPT_USER = 1,
    OPT_HOST,
    OPT_PROTOCOL,
    OPT_PATH,
};

static const char *program = NULL;

static int command = CMD_HELP;

static const char *authinfo_path = NULL;

static const char *user = NULL;
static const char *host = NULL;
static const char *protocol = NULL;

static void
usage(void)
{
    printf("Usage: %s [COMMAND] [OPTIONS]\n\n", program);
    printf("Supported commands:\n");
    printf("   --query      query authinfo file for matching entries\n");
    printf("        --user             match user name\n");
    printf("        --host             match host name\n");
    printf("        --protocol         match protocol\n");
    printf("        --path             use this authinfo file instead of autodiscovered\n");
    printf("   --validate   check authinfo file for syntax errors\n");
    printf("        --path             use this authinfo file instead of autodiscovered\n");
    printf("   --version    print version info\n");
    printf("   --help       print this help\n");
}

int
main(int argc, char *argv[])
{
    struct option options[] = {
        {"query", no_argument, &command, CMD_QUERY},
        {"validate", no_argument, &command, CMD_VALIDATE},
        {"version", no_argument, &command, CMD_VERSION},
        {"help", no_argument, &command, CMD_HELP},
        {"user", required_argument, NULL, OPT_USER},
        {"host", required_argument, NULL, OPT_HOST},
        {"protocol", required_argument, NULL, OPT_PROTOCOL},
        {"path", required_argument, NULL, OPT_PATH},
        {0, 0, 0, 0}
    };

    program = argv[0];

    while (true) {
        int opt;

        opt = getopt_long(argc, argv, "", options, NULL);
        if (opt == '?') {
            return EXIT_FAILURE;
        } else if (opt == -1) {
            break;
        }

        switch (opt) {
        case 0:
            break;
        case OPT_USER:
            user = optarg;
            break;
        case OPT_HOST:
            host = optarg;
            break;
        case OPT_PROTOCOL:
            protocol = optarg;
            break;
        case OPT_PATH:
            authinfo_path = optarg;
            break;
        default:
            /* should not happen */
            assert(false);
        }
    }

    return EXIT_SUCCESS;
}
