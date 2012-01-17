/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
