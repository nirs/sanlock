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

int sanlock_acquire(int sock, int pid, uint32_t flags, int res_count,
		    struct sanlk_resource *res_args[],
		    struct sanlk_options *opt_in);

#define SANLK_REL_ALL 0x1

int sanlock_release(int sock, int pid, uint32_t flags, int res_count,
		    struct sanlk_resource *res_args[]);

/*
 * SANLK_INQ_STRING
 * allocates and returns a state string, caller frees.
 * "RESOURCE1 RESOURCE2 RESOURCE3 ..."
 * RESOURCE = <lockspace_name>:<resource_name>:<path>:<offset>[:<path>:<offset>...]:<version>
 *
 * SANLK_INQ_STRUCT
 * allocates and returns an array of sanlk_resource structs, caller frees.
 * [sanlk_resource][sanlk_disk...][sanlk_resource][sanlk_disk...]...
 */

#define SANLK_INQ_STRING 0x1
#define SANLK_INQ_STRUCT 0x2

int sanlock_inquire(int sock, int pid, uint32_t flags, int *res_count,
		    void **res_out);

#endif
