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

int sanlock_direct_acquire_id(struct sanlk_lockspace *ls);
int sanlock_direct_release_id(struct sanlk_lockspace *ls);
int sanlock_direct_renew_id(struct sanlk_lockspace *ls);

int sanlock_direct_read_id(struct sanlk_lockspace *ls,
                           uint64_t *timestamp,
                           uint64_t *owner_id,
                           uint64_t *owner_generation);

int sanlock_direct_live_id(struct sanlk_lockspace *ls,
                           uint64_t *timestamp,
                           uint64_t *owner_id,
                           uint64_t *owner_generation,
                           int *live);
#endif
