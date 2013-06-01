/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include "authinfo.h"

#define ITEMS_MAX 50

static int entries_start;
static int entries_count;
static struct authinfo_parse_entry_t entries[ITEMS_MAX];

static int errors_start;
static int errors_count;
static struct authinfo_parse_error_t errors[ITEMS_MAX];

static char *
xstrdup(const char *str)
{
    char *ret = NULL;

    if (str) {
        ret = strdup(str);
        assert(ret);
    }

    return ret;
}

static void
xfree(void *p)
{
    if (p) {
        free(p);
    }
}

static void
copy_entry(struct authinfo_parse_entry_t *dst,
           const struct authinfo_parse_entry_t *src)
{
    dst->host = xstrdup(src->host);
    dst->protocol = xstrdup(src->protocol);
    dst->user = xstrdup(src->user);
    dst->password = xstrdup(src->password);
    dst->force = src->force;
}

static void
free_entry(struct authinfo_parse_entry_t *entry)
{
    xfree((void *) entry->host);
    xfree((void *) entry->protocol);
    xfree((void *) entry->user);
    xfree((void *) entry->password);
}

static bool
parse_all_entry_cb(const struct authinfo_parse_entry_t *entry, void *arg)
{
    assert(entries_count < ITEMS_MAX);
    copy_entry(&entries[entries_count++], entry);

    return false;
}

static bool
parse_all_error_cb(const struct authinfo_parse_error_t *error, void *arg)
{
    assert(errors_count < ITEMS_MAX);
    errors[errors_count++] = *error;

    return false;
}

static void
parse_all(const char *data)
{
    entries_start = entries_count;
    errors_start = errors_count;

    authinfo_parse(data, NULL, parse_all_entry_cb, parse_all_error_cb);
}

static void
dump_entries(void)
{
    if (entries_count) {
        fprintf(stderr, "Parsed entries:\n");
        for (int i = entries_start; i < entries_count; ++i) {
            struct authinfo_parse_entry_t *e = &entries[i];

            fprintf(stderr,
                    "\thost -> '%s', protocol -> '%s', "
                    "user -> '%s', password -> '%s', force -> %s\n",
                    e->host, e->protocol, e->user, e->password,
                    (e->force ? "true" : "false"));
        }
    } else {
        fprintf(stderr, "No parsed entries\n");
    }
}

static void
dump_errors(void)
{
    if (errors_count) {
        fprintf(stderr, "Parsing errors:\n");
        for (int i = errors_start; i < errors_count; ++i) {
            struct authinfo_parse_error_t *e = &errors[i];

            fprintf(stderr, "\t%u:%u: %s\n",
                    e->line, e->column, authinfo_parse_strerror(e->type));
        }
    } else {
        fprintf(stderr, "No parsing errors\n");
    }
}

static void
setup(void)
{
    entries_start = 0;
    entries_count = 0;
    errors_start = 0;
    errors_count = 0;
}

static void
teardown(void)
{
    for (int i = 0; i < entries_count; ++i) {
        free_entry(&entries[i]);
    }
}

#define NOTE_FAILURE() \
    fprintf(stderr, "FAILURE: %s:%d\n", __func__, __LINE__);

#define ASSERT_EMPTY() \
    if ((entries_count != entries_start) || (errors_count != errors_start)) { \
        NOTE_FAILURE(); \
        dump_entries(); \
        dump_errors(); \
        ck_abort_msg("Non-empty set of parsed entries or errors"); \
    }

#define ASSERT_PARSES_COUNT(count) \
    if ((entries_count - entries_start != (count)) ||   \
        (errors_count != errors_start)) { \
        NOTE_FAILURE(); \
        dump_entries(); \
        dump_errors(); \
        ck_abort_msg("Number of parsed entries not equal expected (%d)", count); \
    }

#define ASSERT_STREQ(x, y) \
    if ((x) != NULL && (y) != NULL) { \
        ck_assert_str_eq((x), (y)); \
    } else { \
        ck_assert_ptr_eq((x), (y)); \
    }

#define ASSERT_ENTRY(entry, host_, user_, password_, protocol_, force_) \
    ASSERT_STREQ((entry).host, host_); \
    ASSERT_STREQ((entry).user, user_); \
    ASSERT_STREQ((entry).password, password_); \
    ASSERT_STREQ((entry).protocol, protocol_); \
    ck_assert_int_eq((entry).force, force_);

#define ASSERT_SINGLE_ENTRY(host, user, password, protocol, force) \
    ASSERT_PARSES_COUNT(1); \
    ASSERT_ENTRY(entries[entries_start], host, user, password, protocol, force);


#define TEST(name) \
    START_TEST(test_parse_##name); \
    fprintf(stderr, "==Test: %s=====================\n", #name);

TEST(empty)
{
    parse_all("");
    ASSERT_EMPTY();

    parse_all(" ");
    ASSERT_EMPTY();

    parse_all("\t");
    ASSERT_EMPTY();

    parse_all("\n");
    ASSERT_EMPTY();

    parse_all(" \n");
    ASSERT_EMPTY();

    parse_all("\t\n");
    ASSERT_EMPTY();

    parse_all("\n\n");
    ASSERT_EMPTY();

    parse_all("\t\n \n\t ");
    ASSERT_EMPTY();
}
END_TEST

TEST(comment_basic)
{
    parse_all("# commented line only");
    ASSERT_EMPTY();

    parse_all("# commented line only\n");
    ASSERT_EMPTY();

    parse_all("   # commented line only");
    ASSERT_EMPTY();

    parse_all("   # commented line only\n");
    ASSERT_EMPTY();
}
END_TEST

TEST(macdef_basic)
{
    parse_all(
        "macdef test\n"
        "def");
    ASSERT_EMPTY();

    parse_all(
        "macdef test\n"
        "def\n");
    ASSERT_EMPTY();

    parse_all(
        "macdef test\n"
        "def\n\n");
    ASSERT_EMPTY();
}
END_TEST

TEST(basic)
{
    parse_all("host hostname user username "
              "password password protocol protocol force yes");
    ASSERT_SINGLE_ENTRY("hostname", "username", "password", "protocol", true);

    /* test synonymous keywords */
    parse_all("machine hostname login username "
              "password password port protocol force yes");
    ASSERT_SINGLE_ENTRY("hostname", "username", "password", "protocol", true);

    parse_all("machine hostname account username "
              "password password protocol protocol force yes");
    ASSERT_SINGLE_ENTRY("hostname", "username", "password", "protocol", true);

    parse_all("default user username "
              "password password protocol protocol force yes");
    ASSERT_SINGLE_ENTRY("", "username", "password", "protocol", true);

    /* everything except host can be omitted */
    parse_all("host hostname user username "
              "password password protocol protocol");
    ASSERT_SINGLE_ENTRY("hostname", "username", "password", "protocol", false);

    parse_all("host hostname user username "
              "password password force yes");
    ASSERT_SINGLE_ENTRY("hostname", "username", "password", NULL, true);

    parse_all("host hostname user username "
              "protocol protocol force yes");
    ASSERT_SINGLE_ENTRY("hostname", "username", NULL, "protocol", true);

    parse_all("host hostname "
              "password password protocol protocol force yes");
    ASSERT_SINGLE_ENTRY("hostname", NULL, "password", "protocol", true);

    parse_all("host hostname user username "
              "password password");
    ASSERT_SINGLE_ENTRY("hostname", "username", "password", NULL, false);

    parse_all("host hostname user username");
    ASSERT_SINGLE_ENTRY("hostname", "username", NULL, NULL, false);

    parse_all("host hostname");
    ASSERT_SINGLE_ENTRY("hostname", NULL, NULL, NULL, false);
}
END_TEST

TEST(quoted)
{
    parse_all("host hostname user username password \"password\"");
    ASSERT_SINGLE_ENTRY("hostname", "username", "password", NULL, false);

    parse_all("host hostname user username password \"pass word\"");
    ASSERT_SINGLE_ENTRY("hostname", "username", "pass word", NULL, false);

    parse_all("host hostname user username password \"pass \\\"word\"");
    ASSERT_SINGLE_ENTRY("hostname", "username", "pass \"word", NULL, false);

    parse_all("host hostname user username password \"pass \\\"\\\\word\"");
    ASSERT_SINGLE_ENTRY("hostname", "username", "pass \"\\word", NULL, false);

    parse_all("host hostname user username password \"pass \\\"\\\\\"");
    ASSERT_SINGLE_ENTRY("hostname", "username", "pass \"\\", NULL, false);

    parse_all("host hostname user username password \" \\\"\\\\\"");
    ASSERT_SINGLE_ENTRY("hostname", "username", " \"\\", NULL, false);

    parse_all("host hostname user username password \"\\\"\\\\\"");
    ASSERT_SINGLE_ENTRY("hostname", "username", "\"\\", NULL, false);
}
END_TEST

Suite *
parsing_suite(void)
{
    Suite *s = suite_create("Parsing");

#define TEST_CASE(name, desc) \
    TCase *tc_##name = tcase_create(desc); \
    tcase_add_checked_fixture(tc_##name, setup, teardown); \
    tcase_add_test(tc_##name, test_parse_##name); \
    suite_add_tcase(s, tc_##name);

    TEST_CASE(empty, "Parsing empty file");
    TEST_CASE(comment_basic, "Basic comment parsing");
    TEST_CASE(macdef_basic, "Basic macdef parsing");
    TEST_CASE(basic, "Basic entry parsing");
    TEST_CASE(quoted, "Parsing quoted tokens");

#undef TEST_CASE

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s = parsing_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
