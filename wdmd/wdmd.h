/*
 * Copyright (C) 2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __WDMD_H__
#define __WDMD_H__

#define WDMD_NAME_SIZE 128

int wdmd_connect(void);
int wdmd_register(int con, char *name);
int wdmd_refcount_set(int con);
int wdmd_refcount_clear(int con);
int wdmd_test_live(int con, uint64_t renewal_time, uint64_t expire_time);
int wdmd_status(int con, int *test_interval, int *fire_timeout, uint64_t *last_keepalive);

#endif
