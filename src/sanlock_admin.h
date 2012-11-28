/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __SANLOCK_ADMIN_H__
#define __SANLOCK_ADMIN_H__

/* add flags */
#define SANLK_ADD_ASYNC		0x00000001

/* rem flags */
#define SANLK_REM_ASYNC		0x00000001
#define SANLK_REM_UNUSED	0x00000002

/* inq flags */
#define SANLK_INQ_WAIT		0x00000001

/* sanlk_lockspace.flags returned by get */
#define SANLK_LSF_ADD		0x00000001
#define SANLK_LSF_REM		0x00000002

/*
 * add_lockspace returns:
 * 0: the lockspace has been added successfully
 * -EEXIST: the lockspace already exists
 * -EINPROGRESS: the lockspace is already in the process of being added
 * (the in-progress add may or may not succeed)
 * -EAGAIN: the lockspace is being removed
 *
 * The _timeout version takes the io_timeout in seconds.
 * If 0, the global setting for the daemon will be used.
 */

int sanlock_add_lockspace(struct sanlk_lockspace *ls, uint32_t flags);

int sanlock_add_lockspace_timeout(struct sanlk_lockspace *ls, uint32_t flags,
				  uint32_t io_timeout);

/*
 * inq_lockspace returns:
 * 0: the lockspace exists and is currently held
 * -ENOENT: lockspace not found
 */

int sanlock_inq_lockspace(struct sanlk_lockspace *ls, uint32_t flags);

/*
 * rem_lockspace returns:
 * 0: the lockspace has been removed successfully
 * -EINPROGRESS: the lockspace is already in the process of being removed
 * -ENOENT: lockspace not found
 * -EBUSY: UNUSED was set and lockspace is being used
 *
 * The sanlock daemon will kill any pids using the lockspace when the
 * lockspace is removed (unless UNUSED is set).
 */

int sanlock_rem_lockspace(struct sanlk_lockspace *ls, uint32_t flags);

/*
 * get_lockspace returns:
 * 0: all lockspaces copied out, lss_count set to number
 * -ENOSPC: sanlock internal buffer ran out of space
 * (lss_count set to number that would have been copied)
 * -ENOBUFS: lss_size too small
 * (lss_count set to number that would have been copied)
 *
 *  sanlk_lockspace.flags set to SANLK_LSF_
 */

int sanlock_get_lockspaces(struct sanlk_lockspace *lss, int lss_size,
			   int *lss_count, uint32_t flags);

/*
 * Returns the alignment in bytes required by sanlock_init()
 * (1MB for disks with 512 sectors, 8MB for disks with 4096 sectors)
 */

int sanlock_align(struct sanlk_disk *disk);

/*
 * Ask sanlock daemon to initialize disk space.
 * Use max_hosts = 0 for default value.
 * Use num_hosts = 0 for default value.
 * Provide either lockspace or resource, not both
 *
 * (Old api, see write_lockspace/resource)
 */

int sanlock_init(struct sanlk_lockspace *ls,
		 struct sanlk_resource *res,
		 int max_hosts, int num_hosts);

/*
 * write a lockspace to disk
 *
 * the sanlock daemon writes max_hosts lockspace leader records to disk
 *
 * the lockspace will support up to max_hosts using the lockspace at once
 *
 * use max_hosts = 0 for default value
 *
 * the first host_id (1) (the first record at offset) is the last
 * leader record written, so read_lockspace of host_id 1 will fail
 * until the entire write_lockspace is complete.
 */

int sanlock_write_lockspace(struct sanlk_lockspace *ls, int max_hosts,
			    uint32_t flags, uint32_t io_timeout);

/*
 * read one host's lockspace record from disk
 *
 * the sanlock daemon reads one lockspace leader record from disk
 *
 * the minimum input is path and offset
 *
 * if name is specified and does not match the leader record name,
 * SANLK_LEADER_LOCKSPACE is returned
 *
 * if name is not specified, it is filled it with the value from disk
 *
 * if host_id is zero, host_id 1 is used (the first record at offset)
 *
 * if there is no delta lease magic number found at the host_id location,
 * SANLK_LEADER_MAGIC is returned
 *
 * on success, zero is returned and
 * io_timeout and the entire sanlk_lockspace struct are written to
 */

int sanlock_read_lockspace(struct sanlk_lockspace *ls,
			   uint32_t flags, uint32_t *io_timeout);

/*
 * format a resource lease area on disk
 *
 * the sanlock daemon writes a resource lease area to disk
 *
 * use max_hosts = 0 for default value
 * use num_hosts = 0 for default value
 */

int sanlock_write_resource(struct sanlk_resource *res,
			   int max_hosts, int num_hosts, uint32_t flags);

/*
 * read a resource lease from disk
 *
 * the sanlock daemon reads the lease's leader record from disk
 *
 * the minimum input is one disk with path and offset
 *
 * if lockspace name is specified and does not match the leader record
 * lockspace name, SANLK_LEADER_LOCKSPACE is returned
 *
 * if resource name is specified and does not match the leader record
 * resource name, SANLK_LEADER_RESOURCE is returned
 *
 * if there is no paxos lease magic number found in the leader record,
 * SANLK_LEADER_MAGIC is returned
 *
 * on success, zero is returned and
 * the entire sanlk_resource struct is written to (res->disks is not changed)
 */

int sanlock_read_resource(struct sanlk_resource *res, uint32_t flags);

#endif
