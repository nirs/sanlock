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
 * Use max_hosts = 0 for default value.
 * Use num_hosts = 0 for default value.
 * Provide either lockspace or resource, not both
 *
 * (Old api, see write_lockspace/resource)
 */

int sanlock_direct_init(struct sanlk_lockspace *ls,
                        struct sanlk_resource *res,
                        int max_hosts, int num_hosts, int use_aio);

/*
 * write a lockspace to disk
 * (also see sanlock_write_lockspace)
 */

int sanlock_direct_write_lockspace(struct sanlk_lockspace *ls, int max_hosts,
				   uint32_t flags, uint32_t io_timeout);

/*
 * format a resource lease area on disk
 * (also see sanlock_write_resource)
 */

int sanlock_direct_write_resource(struct sanlk_resource *res,
				  int max_hosts, int num_hosts, uint32_t flags);

/*
 * Returns the alignment in bytes required by sanlock_direct_init()
 * (1MB for disks with 512 sectors, 8MB for disks with 4096 sectors)
 */

int sanlock_direct_align(struct sanlk_disk *disk);

#endif
