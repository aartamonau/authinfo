/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include "authinfo.h"

#define ITEMS_MAX 50

static int entries_count;
static struct authinfo_parse_entry_t entries[ITEMS_MAX];

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
    authinfo_parse(data, NULL, parse_all_entry_cb, parse_all_error_cb);
}

static void
dump_entries(void)
{
    if (entries_count) {
        fprintf(stderr, "Parsed entries:\n");
        for (int i = 0; i < entries_count; ++i) {
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
        for (int i = 0; i < errors_count; ++i) {
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
    entries_count = 0;
    errors_count = 0;
}

static void
teardown(void)
{
    for (int i = 0; i < entries_count; ++i) {
        free_entry(&entries[i]);
    }
}

#define ASSERT_EMPTY() \
    if (entries_count != 0 || errors_count != 0) { \
        fprintf(stderr, "FAILURE: %s:%d\n", __func__, __LINE__); \
        dump_entries(); \
        dump_errors(); \
        fprintf(stderr, "\n"); \
        ck_abort_msg("Non-empty set of parsed entries or errors"); \
    }

#define TEST(name) \
    START_TEST(name); \
    fprintf(stderr, "==Test: %s=====================\n", #name);

TEST(test_parse_empty)
{
    parse_all("");
    ASSERT_EMPTY();

    parse_all("\n");
    ASSERT_EMPTY();

    parse_all("\n\n");
    ASSERT_EMPTY();
}
END_TEST

TEST(test_parse_comment_basic)
{
    parse_all("# commented line only");
    ASSERT_EMPTY();

    parse_all("# commented line only\n");
    ASSERT_EMPTY();
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
