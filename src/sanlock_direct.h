/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __SANLOCK_DIRECT_H__
#define __SANLOCK_DIRECT_H__

int sanlock_direct_read_id(struct sanlk_lockspace *ls,
                           uint64_t *timestamp,
                           uint64_t *owner_id,
                           uint64_t *owner_generation,
                           int use_aio);

int sanlock_direct_live_id(struct sanlk_lockspace *ls,
                           uint64_t *timestamp,
                           uint64_t *owner_id,
                           uint64_t *owner_generation,
                           int *live,
                           int use_aio);

/* Use max_hosts = 0 for default max_hosts value */

int sanlock_direct_init(struct sanlk_lockspace *ls,
                        struct sanlk_resource *res,
                        int max_hosts, int num_hosts, int use_aio);

#endif
