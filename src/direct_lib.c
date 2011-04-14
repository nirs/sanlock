/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include "sanlock_internal.h"

void log_level(int space_id GNUC_UNUSED, int token_id GNUC_UNUSED,
	       int level GNUC_UNUSED, const char *fmt GNUC_UNUSED, ...);

void log_level(int space_id GNUC_UNUSED, int token_id GNUC_UNUSED,
	       int level GNUC_UNUSED, const char *fmt GNUC_UNUSED, ...)
{
}

int host_id_leader_read(struct timeout *ti GNUC_UNUSED,
                        char *space_name GNUC_UNUSED,
			uint64_t host_id GNUC_UNUSED,
                        struct leader_record *leader_ret GNUC_UNUSED);

int host_id_leader_read(struct timeout *ti GNUC_UNUSED,
                        char *space_name GNUC_UNUSED,
			uint64_t host_id GNUC_UNUSED,
                        struct leader_record *leader_ret GNUC_UNUSED)
{
	return -1;
}

