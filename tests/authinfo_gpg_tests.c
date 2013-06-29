/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

#include "config.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <check.h>
#include <gpgme.h>

#include "authinfo.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define GPG(body) \
    do { \
        gpgme_error_t __err = (body); \
        if (gpg_err_code(__err) != GPG_ERR_NO_ERROR) {  \
            fprintf(stderr, "%s:%d: %s failed -> %s\n", \
                    __FILE__, __LINE__, #body, gpgme_strerror(__err)); \
            ck_abort(); \
        } \
    } while(0)

#define AUTHINFO(body) \
    do { \
        enum authinfo_result_t __err = (body); \
        if (__err != AUTHINFO_OK) { \
            fprintf(stderr, "%s:%d: %s failed -> %s\n", \
                    __FILE__, __LINE__, #body, authinfo_strerror(__err)); \
            ck_abort(); \
        } \
    } while(0)

static void
setup(void)
{
    AUTHINFO(authinfo_init());

    gpgme_ctx_t ctx;
    gpgme_data_t data;

    GPG(gpgme_new(&ctx));

    GPG(gpgme_data_new_from_file(&data,
                                 TOP_SRCDIR "/tests/files/gpg_tests/public.key",
                                 1));
    GPG(gpgme_op_import(ctx, data));
    gpgme_data_release(data);

    GPG(gpgme_data_new_from_file(&data,
                                 TOP_SRCDIR "/tests/files/gpg_tests/private.key",
                                 1));
    GPG(gpgme_op_import(ctx, data));
    gpgme_data_release(data);

    gpgme_release(ctx);
}

static void
teardown(void)
{
    gpgme_ctx_t ctx;
    gpgme_key_t test_key = NULL;
    gpgme_key_t key;

    GPG(gpgme_new(&ctx));

    GPG(gpgme_op_keylist_start(ctx, NULL, 0));
    while (true) {
        gpgme_error_t err;

        err = gpgme_op_keylist_next(ctx, &key);
        if (gpg_err_code(err) == GPG_ERR_EOF) {
            break;
        }
        GPG(err);

        if (key->uids && strcmp(key->uids->email, "authinfo@test.com") == 0) {
            ck_assert(test_key == NULL);
            test_key = key;
        } else {
            gpgme_key_release(key);
        }
    }

    if (test_key) {
        GPG(gpgme_op_delete(ctx, test_key, 1));
        gpgme_key_release(test_key);
    }

    gpgme_release(ctx);
}

#define TEST(name) \
    START_TEST(test_gpg_##name); \
    fprintf(stderr, "==Test: %s=====================\n", #name);

TEST(read_file)
{
    char plain[1024] = {0};
    char encrypted[1024] = {0};

    size_t plain_size = sizeof(plain);
    size_t encrypted_size = sizeof(encrypted);

    AUTHINFO(authinfo_read_file(TOP_SRCDIR "/tests/files/gpg_tests/read_file.gpg",
                                encrypted, &encrypted_size));
    AUTHINFO(authinfo_read_file(TOP_SRCDIR "/tests/files/gpg_tests/read_file",
                                plain, &plain_size));

    ck_assert_uint_eq(plain_size, encrypted_size);
    ck_assert(memcmp(plain, encrypted, plain_size) == 0);
}
END_TEST

TEST(gpged_password)
{
    char buffer[1024] = {0};
    size_t buffer_size = sizeof(buffer);

    struct authinfo_parse_entry_t entry;
    struct authinfo_parse_error_t error;
    const char *password;

    AUTHINFO(authinfo_read_file(TOP_SRCDIR "/tests/files/gpg_tests/gpged_password",
                                buffer, &buffer_size));
    AUTHINFO(authinfo_simple_query(buffer, buffer_size, NULL, NULL, NULL,
                                   &entry, &error));
    AUTHINFO(authinfo_password_extract(entry.password, &password));

    ck_assert_str_eq(entry.host, "host");
    ck_assert_str_eq(entry.user, "user");
    ck_assert_str_eq(entry.protocol, "protocol");
    ck_assert_str_eq(password, "password");

    authinfo_parse_entry_free(&entry);
}
END_TEST

Suite *
gpg_suite(void)
{
    Suite *s = suite_create("Parsing");

#define TEST_CASE(name, desc) \
    TCase *tc_##name = tcase_create(desc); \
    tcase_add_checked_fixture(tc_##name, setup, teardown); \
    tcase_add_test(tc_##name, test_gpg_##name); \
    suite_add_tcase(s, tc_##name);

    TEST_CASE(read_file, "Reading encrypted/unencrypted files");
    TEST_CASE(gpged_password, "Parsing file with encrypted password");

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s = gpg_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
