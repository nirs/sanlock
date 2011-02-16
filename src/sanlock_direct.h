/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __SANLOCK_DIRECT_H__
#define __SANLOCK_DIRECT_H__

int sanlock_direct_init(void);
int sanlock_direct_dump(void);
int sanlock_direct_acquire(void);
int sanlock_direct_release(void);
int sanlock_direct_migrate(void);
int sanlock_direct_acquire_id(void);
int sanlock_direct_release_id(void);
int sanlock_direct_renew_id(void);

#endif
