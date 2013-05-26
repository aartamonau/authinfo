/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */

#include <stdio.h>
#include "netrc.h"
#include "netrc_internal.h"

void
netrc_foo(void)
{
    TRACE("testing trace\n");
    TRACE("testing trace with arg %d\n", 10);
    printf("netrc_foo\n");
}
