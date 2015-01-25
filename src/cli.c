/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

/*
 * Copyright (C) 2013 Aliaksey Artamonau <aliaksiej.artamonau@gmail.com>
 *
 * This file is part of authinfo.
 *
 * Authinfo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Authinfo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with authinfo.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <locale.h>
#include <sys/resource.h>
#include <errno.h>

#include "config.h"
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

static char *authinfo_path = NULL;

static const char *user = NULL;
static const char *host = NULL;
static const char *protocol = NULL;

static int error_count = 0;

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

static void
version(void)
{
    printf("authinfo version %s\n", PACKAGE_VERSION);
}

static void
authinfo_error(enum authinfo_result_t error, const char *msg)
{
    fprintf(stderr, "%s: %s (%s)\n", program, msg, authinfo_strerror(error));
    exit(EXIT_FAILURE);
}

static void
init_authinfo(void)
{
    enum authinfo_result_t ret;

    ret = authinfo_init("authinfo");
    if (ret != AUTHINFO_OK) {
        authinfo_error(ret, "failed to initialize authinfo library");
    }
}

static void
maybe_find_file(void)
{
    enum authinfo_result_t ret;

    if (authinfo_path) {
        return;
    }

    ret = authinfo_find_file(&authinfo_path);
    if (ret != AUTHINFO_OK) {
        authinfo_error(ret, "failed to find authinfo file");
    }
}

static void
read_file(struct authinfo_data_t **data)
{
    enum authinfo_result_t ret;

    assert(authinfo_path);

    ret = authinfo_data_from_file(authinfo_path, data);
    if (ret != AUTHINFO_OK) {
        authinfo_error(ret, "couldn't read authinfo file");
    }
}

static void
emit_env_var(const char *var, const char *value)
{
    if (value == NULL) {
        value = "";
    }

    size_t len = strlen(value);
    /* every original character will at most require 4 characters in the
     * escaped string; plus we need two bytes for starting and ending quotes */
    char escaped_value[4 * len + 3];

    const char *s = value;
    char *d = escaped_value;

    *d++ = '\'';

    while (*s) {
        if (*s == '\'') {
            /* there's no way to escape single quote in single-quoted string;
             * so we produce a closing single quote, then escaped single
             * quote and then an opening single quote again */
            *d++ = '\'';
            *d++ = '\\';
            *d++ = '\'';
            *d++ = '\'';
        } else {
            *d++ = *s;
        }

        s += 1;
    }

    *d++ = '\'';
    *d = '\0';

    printf("%s=%s\n", var, escaped_value);
    printf("export %s\n", var);
}

static void
query_process_entry(struct authinfo_parse_entry_t *entry)
{
    const char *password = NULL;

    if (entry->password != NULL) {
        enum authinfo_result_t ret;

        ret = authinfo_password_extract(entry->password, &password);
        if (ret != AUTHINFO_OK) {
            authinfo_error(ret, "couldn't extract password");
        }
    }

    emit_env_var("AUTHINFO_HOST", entry->host);
    emit_env_var("AUTHINFO_USER", entry->user);
    emit_env_var("AUTHINFO_PROTOCOL", entry->protocol);
    emit_env_var("AUTHINFO_PASSWORD", password);

    authinfo_parse_entry_free(entry);
}

static void
query(void)
{
    enum authinfo_result_t ret;
    struct authinfo_parse_entry_t entry;
    struct authinfo_parse_error_t error;
    struct authinfo_data_t *data;

    int status = EXIT_SUCCESS;

    init_authinfo();
    maybe_find_file();
    read_file(&data);

    ret = authinfo_simple_query(data, host, protocol, user,
                                &entry, &error);
    authinfo_data_free(data);
    switch (ret) {
    case AUTHINFO_OK:
        query_process_entry(&entry);
        break;
    case AUTHINFO_ENOMATCH:
        fprintf(stderr, "%s: no matching entries found\n", program);
        status = EXIT_FAILURE;
        break;
    case AUTHINFO_EPARSE:
        fprintf(stderr, "%s: parse error at %s:%u:%u (%s)\n",
                program, authinfo_path, error.line, error.column,
                authinfo_parse_strerror(error.type));
        status = EXIT_FAILURE;
        break;
    default:
        authinfo_error(ret, "couldn't find matching entry");
    }

    exit(status);
}

static bool
validate_error(const struct authinfo_parse_error_t *error, void *arg)
{
    printf("  %u:%u: %s\n",
           error->line, error->column, authinfo_parse_strerror(error->type));
    ++error_count;
    return false;
}

static bool
validate_entry(const struct authinfo_parse_entry_t *entry, void *arg)
{
    return false;
}

static void
validate(void)
{
    struct authinfo_data_t *data;

    init_authinfo();
    maybe_find_file();
    read_file(&data);

    printf("Parsing %s.\n", authinfo_path);
    authinfo_parse(data, NULL, validate_entry, validate_error);

    authinfo_data_free(data);

    if (error_count == 0) {
        printf("  No errors found\n");
    } else {
        exit(EXIT_FAILURE);
    }
}

void
disable_core_dumps()
{
    struct rlimit limit;

    if (getrlimit(RLIMIT_CORE, &limit) != 0) {
        limit.rlim_max = 0;
    }

    limit.rlim_cur = 0;
    if (setrlimit(RLIMIT_CORE, &limit) != 0) {
        fprintf(stderr, "Couldn't disable core dumps: %s\n", strerror(errno));
    }
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

    setlocale(LC_ALL, "");

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

    disable_core_dumps();

    switch (command) {
    case CMD_QUERY:
        query();
        break;
    case CMD_VALIDATE:
        validate();
        break;
    case CMD_VERSION:
        version();
        break;
    case CMD_HELP:
        usage();
        break;
    default:
        assert(false);
    }

    return EXIT_SUCCESS;
}
