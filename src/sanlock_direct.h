/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __SANLOCK_DIRECT_H__
#define __SANLOCK_DIRECT_H__

/*
 * Use io_timeout_sec = 0 for default value
 */

int sanlock_direct_read_id(struct sanlk_lockspace *ls,
                           uint64_t *timestamp,
                           uint64_t *owner_id,
                           uint64_t *owner_generation,
                           int use_aio,
			   int io_timeout_sec);

int sanlock_direct_live_id(struct sanlk_lockspace *ls,
                           uint64_t *timestamp,
                           uint64_t *owner_id,
                           uint64_t *owner_generation,
                           int *live,
                           int use_aio,
			   int io_timeout_sec);

/*
 * Use max_hosts = 0 for default value.
 * Use num_hosts = 0 for default value.
 * Provide either lockspace or resource, not both
 */

int sanlock_direct_init(struct sanlk_lockspace *ls,
                        struct sanlk_resource *res,
                        int max_hosts, int num_hosts, int use_aio);

/*
 * Returns the alignment in bytes required by sanlock_direct_init()
 * (1MB for disks with 512 sectors, 8MB for disks with 4096 sectors)
 */

int sanlock_direct_align(struct sanlk_disk *disk);

#endif
