/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <check.h>
#include <stdlib.h>
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

START_TEST(test_parse_empty)
{
    parse_all("");
    ck_assert_int_eq(entries_count, 0);
    ck_assert_int_eq(errors_count, 0);

    parse_all("\n");
    ck_assert_int_eq(entries_count, 0);
    ck_assert_int_eq(errors_count, 0);

    parse_all("\n\n");
    ck_assert_int_eq(entries_count, 0);
    ck_assert_int_eq(errors_count, 0);
}
END_TEST

Suite *
parsing_suite(void)
{
    Suite *s = suite_create("Parsing");

    TCase *tc_empty = tcase_create("Parsing empty file");
    tcase_add_checked_fixture(tc_empty, setup, teardown);
    tcase_add_test(tc_empty, test_parse_empty);
    suite_add_tcase(s, tc_empty);

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
