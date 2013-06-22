/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <locale.h>

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

    ret = authinfo_init();
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
read_file(char *buffer, size_t *size)
{
    enum authinfo_result_t ret;

    assert(authinfo_path);

    ret = authinfo_read_file(authinfo_path, buffer, size);
    if (ret != AUTHINFO_OK) {
        authinfo_error(ret, "couldn't read authinfo file");
    }
}

static void
emit_env_var(const char *var, const char *value)
{
    if (value == NULL) {
        return;
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
query_process_entry(const struct authinfo_parse_entry_t *entry)
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
    emit_env_var("AUTHINFO_DEFAULT", (entry->host == NULL) ? "yes" : "no");
}

static void
query(void)
{
    char buffer[1 << 16];
    size_t size = sizeof(buffer);

    enum authinfo_result_t ret;
    struct authinfo_parse_entry_t entry;
    struct authinfo_parse_error_t error;

    int status = EXIT_SUCCESS;

    init_authinfo();
    maybe_find_file();
    read_file(buffer, &size);

    ret = authinfo_simple_query(buffer, size, host, protocol, user,
                                &entry, &error);
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
    char buffer[1 << 16];
    size_t size = sizeof(buffer);

    init_authinfo();
    maybe_find_file();
    read_file(buffer, &size);

    printf("Parsing %s.\n", authinfo_path);
    authinfo_parse(buffer, size, NULL, validate_entry, validate_error);

    if (error_count == 0) {
        printf("  No errors found\n");
    } else {
        exit(EXIT_FAILURE);
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
