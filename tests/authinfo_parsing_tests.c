/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include "authinfo.h"

#define ITEMS_MAX 50

struct entry_t {
    char *host;
    char *protocol;
    char *user;
    char *password;
    bool force;
};

static int entries_start;
static int entries_count;
static struct entry_t entries[ITEMS_MAX];

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
copy_entry(struct entry_t *dst,
           const struct authinfo_parse_entry_t *src)
{
    dst->host = xstrdup(src->host);
    dst->protocol = xstrdup(src->protocol);
    dst->user = xstrdup(src->user);
    dst->force = src->force;

    if (src->password) {
        enum authinfo_result_t ret;
        const char *pwdata;

        ret = authinfo_password_extract(src->password, &pwdata);
        assert(ret == AUTHINFO_OK);

        dst->password = strdup(pwdata);
    } else {
        dst->password = NULL;
    }
}

static void
free_entry(struct entry_t *entry)
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
parse_all(const char *raw_data)
{
    enum authinfo_result_t ret;
    struct authinfo_data_t *data;

    entries_start = entries_count;
    errors_start = errors_count;

    ret = authinfo_data_from_mem(raw_data, strlen(raw_data), &data);
    assert(ret == AUTHINFO_OK);

    authinfo_parse(data, NULL, parse_all_entry_cb, parse_all_error_cb);

    authinfo_data_free(data);
}

static bool
parse_one_entry_cb(const struct authinfo_parse_entry_t *entry, void *arg)
{
    assert(entries_count < ITEMS_MAX);
    copy_entry(&entries[entries_count++], entry);

    return true;
}

static bool
parse_one_error_cb(const struct authinfo_parse_error_t *error, void *arg)
{
    assert(errors_count < ITEMS_MAX);
    errors[errors_count++] = *error;

    return true;
}

static void
parse_one(const char *raw_data)
{
    enum authinfo_result_t ret;
    struct authinfo_data_t *data;

    entries_start = entries_count;
    errors_start = errors_count;

    ret = authinfo_data_from_mem(raw_data, strlen(raw_data), &data);
    assert(ret == AUTHINFO_OK);

    authinfo_parse(data, NULL, parse_one_entry_cb, parse_one_error_cb);

    authinfo_data_free(data);
}


static void
dump_entries(void)
{
    if (entries_count) {
        fprintf(stderr, "Parsed entries:\n");
        for (int i = entries_start; i < entries_count; ++i) {
            struct entry_t *e = &entries[i];

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

    assert(authinfo_init(NULL) == AUTHINFO_OK);
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
    if ((entries_count - entries_start != (count))) { \
        NOTE_FAILURE(); \
        dump_entries(); \
        dump_errors(); \
        ck_abort_msg("Number of parsed entries differs from expected (%d)", (count)); \
    }

#define ASSERT_STREQ(x, y) \
    if ((x) != NULL && (y) != NULL) { \
        ck_assert_str_eq((x), (y)); \
    } else { \
        ck_assert_ptr_eq((void *)(x), (void *)(y)); \
    }

#define ASSERT_ENTRY(entry, host_, user_, password_, protocol_, force_) \
    ASSERT_STREQ((entry).host, host_); \
    ASSERT_STREQ((entry).user, user_); \
    ASSERT_STREQ((entry).password, password_); \
    ASSERT_STREQ((entry).protocol, protocol_); \
    ck_assert_int_eq((entry).force, force_);

#define ASSERT_NTH_ENTRY(number, host, user, password, protocol, force) \
    ASSERT_ENTRY(entries[entries_start + (number)], \
                 host, user, password, protocol, force);

#define ASSERT_SINGLE_ENTRY(host, user, password, protocol, force) \
    ASSERT_PARSES_COUNT(1); \
    ASSERT_ERRORS_COUNT(0); \
    ASSERT_NTH_ENTRY(0, host, user, password, protocol, force);

#define ASSERT_ERRORS_COUNT(count) \
    if (errors_count - errors_start != (count)) { \
        NOTE_FAILURE(); \
        dump_entries(); \
        dump_errors(); \
        ck_abort_msg("Number of parsing errors differs from expected (%d)", (count)); \
    }

#define ASSERT_NTH_ERROR(number, type_) \
    if (errors[errors_start + (number)].type != (type_)) { \
        ck_abort_msg("Error type (%s) differs from expected (%s)", \
                     authinfo_parse_strerror(errors[errors_start + (number)].type), \
                     authinfo_parse_strerror((type_))); \
    }

#define ASSERT_SINGLE_ERROR(type) \
    ASSERT_ERRORS_COUNT(1); \
    ASSERT_NTH_ERROR(0, type);

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

    parse_all("user username "
              "password password protocol protocol force yes");
    ASSERT_SINGLE_ENTRY(NULL, "username", "password", "protocol", true);

    parse_all("default user username "
              "password password protocol protocol force yes");
    ASSERT_SINGLE_ENTRY(NULL, "username", "password", "protocol", true);

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

TEST(multi_entry)
{
    parse_all(
        "host hostname user username "
        "password password protocol protocol force yes\n"

        "machine hostname login username "
        "password password port protocol force yes\n"

        "machine hostname account username "
        "password password protocol protocol force yes\n"

        "#comment\n"

        "user username "
        "password password protocol protocol force yes\n"

        "default user username "
        "password password protocol protocol force yes\n"

        "host hostname user username "
        "password password protocol protocol\n"

        "    #comment\n"

        "host hostname user username "
        "password password force yes\n"

        "host hostname user username "
        "protocol protocol force yes\n"

        "host hostname "
        "password password protocol protocol force yes\n"

        "macdef test\n"
        "def\n"
        "\n"

        "host hostname user username "
        "password password\n"

        "host hostname user username\n"

        "host hostname\n"

        "host hostname user username password \"password\" \n"

        "host hostname user username password \"pass word\" \n"

        "host hostname user username password \"pass \\\"word\" \n"

        "host hostname user username password \"pass \\\"\\\\word\" \n"

        "host hostname user username password \"pass \\\"\\\\\" \n"

        "host hostname user username password \" \\\"\\\\\" \n"

        "host hostname user username password \"\\\"\\\\\" \n"

        " # find a cool macdef on the next line\n"
        "macdef cool\n"
        "really cool");

    ASSERT_PARSES_COUNT(19);
    ASSERT_ERRORS_COUNT(0);

    ASSERT_NTH_ENTRY(0, "hostname", "username", "password", "protocol", true);
    ASSERT_NTH_ENTRY(1, "hostname", "username", "password", "protocol", true);
    ASSERT_NTH_ENTRY(2, "hostname", "username", "password", "protocol", true);
    ASSERT_NTH_ENTRY(3, NULL, "username", "password", "protocol", true);
    ASSERT_NTH_ENTRY(4, NULL, "username", "password", "protocol", true);
    ASSERT_NTH_ENTRY(5, "hostname", "username", "password", "protocol", false);
    ASSERT_NTH_ENTRY(6, "hostname", "username", "password", NULL, true);
    ASSERT_NTH_ENTRY(7, "hostname", "username", NULL, "protocol", true);
    ASSERT_NTH_ENTRY(8, "hostname", NULL, "password", "protocol", true);
    ASSERT_NTH_ENTRY(9, "hostname", "username", "password", NULL, false);
    ASSERT_NTH_ENTRY(10, "hostname", "username", NULL, NULL, false);
    ASSERT_NTH_ENTRY(11, "hostname", NULL, NULL, NULL, false);
    ASSERT_NTH_ENTRY(12, "hostname", "username", "password", NULL, false);
    ASSERT_NTH_ENTRY(13, "hostname", "username", "pass word", NULL, false);
    ASSERT_NTH_ENTRY(14, "hostname", "username", "pass \"word", NULL, false);
    ASSERT_NTH_ENTRY(15, "hostname", "username", "pass \"\\word", NULL, false);
    ASSERT_NTH_ENTRY(16, "hostname", "username", "pass \"\\", NULL, false);
    ASSERT_NTH_ENTRY(17, "hostname", "username", " \"\\", NULL, false);
    ASSERT_NTH_ENTRY(18, "hostname", "username", "\"\\", NULL, false);
}
END_TEST

TEST(errors)
{
    parse_all("host hostname user username "
              "password password protocol");
    ASSERT_SINGLE_ERROR(AUTHINFO_PET_MISSING_VALUE);

    parse_all("host hostname user username "
              "password password protocol protocol force true");
    ASSERT_SINGLE_ERROR(AUTHINFO_PET_BAD_VALUE);

    parse_all("host hostname userr user username "
              "password password protocol protocol force yes");
    ASSERT_SINGLE_ERROR(AUTHINFO_PET_BAD_KEYWORD);

    parse_all("host hostname user username account username "
              "password password protocol protocol force yes");
    ASSERT_SINGLE_ERROR(AUTHINFO_PET_DUPLICATED_KEYWORD);

    parse_all("host hostname user username "
              "password \"password protocol protocol force yes");
    ASSERT_SINGLE_ERROR(AUTHINFO_PET_UNTERMINATED_QUOTED_TOKEN);

    parse_all("host hostname user username "
              "password \"pass\\word\" protocol protocol force yes");
    ASSERT_SINGLE_ERROR(AUTHINFO_PET_UNSUPPORTED_ESCAPE);
}
END_TEST

TEST(first_only)
{
    parse_one(
        "# comment\n"

        "macdef test\n"
        "test\n"
        "\n"

        "host hostname user username "
        "password password protocol protocol force yes\n"

        "machine hostname login username "
        "password password port protocol force yes\n"

        "machine hostname account username "
        "password password protocol protocol force yes\n");

    ASSERT_SINGLE_ENTRY("hostname", "username", "password", "protocol", true);

    parse_one(
        "# comment\n"

        "macdef test\n"
        "test\n"
        "\n"

        "host hostname user username "
        "password password protocol protocol force true");

    ASSERT_PARSES_COUNT(0);
    ASSERT_SINGLE_ERROR(AUTHINFO_PET_BAD_VALUE);

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
    TEST_CASE(multi_entry, "Parsing several entries");
    TEST_CASE(errors, "Parsing errors test");
    TEST_CASE(first_only, "Getting only first parse or error");

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
