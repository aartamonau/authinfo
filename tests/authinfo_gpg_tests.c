/* -*- mode: c; c-basic-offset: 4; tab-width: 4; indent-tabs-mode: nil; -*- */

#include "config.h"

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <check.h>
#include <gpgme.h>

#include "authinfo.h"

#include "public_key.inc"
#include "private_key.inc"

Suite *
gpg_suite(void)
{
    Suite *s = suite_create("Parsing");
    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s = gpg_suite();
    SRunner *sr = srunner_create(s);

    (void) private_key;
    (void) public_key;

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
