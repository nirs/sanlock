/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __SANLOCK_RESOURCE_H__
#define __SANLOCK_RESOURCE_H__

/*
 * sock > -1, pid is ignored:
 * process creates registered connection and acquires/releases leases on
 * that connection for itself
 *
 * sock == -1, pid is used:
 * process asks daemon to acquire/release leases for another separately
 * registered pid
 */

int sanlock_register(void);

int sanlock_acquire(int sock, int pid, int res_count,
		    struct sanlk_resource *res_args[],
		    struct sanlk_options *opt_in);
int sanlock_release(int sock, int pid, int res_count,
		    struct sanlk_resource *res_args[]);
int sanlock_migrate(int sock, int pid, uint64_t target_host_id, char **state);
int sanlock_setowner(int sock, int pid);

#endif
