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

/* host status returned in low byte of sanlk_host.flags by get */
#define SANLK_HOST_UNKNOWN 0x00000001
#define SANLK_HOST_FREE    0x00000002
#define SANLK_HOST_LIVE    0x00000003
#define SANLK_HOST_FAIL    0x00000004
#define SANLK_HOST_DEAD    0x00000005
#define SANLK_HOST_MASK    0x0000000F /* select SANLK_HOST_ from flags */

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
 *
 *  sanlk_lockspace.flags set to SANLK_LSF_
 */

int sanlock_get_lockspaces(struct sanlk_lockspace **lss, int *lss_count,
			   uint32_t flags);

/*
 * When host_id is > 0, returns the sanlk_host info about the
 * specified host_id.
 *
 * When host_id is 0, returns sanlk_host info about all hosts
 * that have been seen alive.
 *
 * host status returned by sanlk_host.flags & SANLK_HOST_MASK:
 *
 * UNKNOWN: after adding lockspace, there has not yet been
 * enough time monitoring other hosts to make an accurate
 * assessment.
 *
 * FREE: delta lease not held
 * the delta lease timestamp is zero
 *
 * LIVE: the host is alive
 * now - last < other_host_fail_seconds
 *
 * FAIL: the host is failing and may be in recovery (killing pids)
 * now - last > other_host_fail_seconds
 *
 * DEAD: the host is dead, its watchdog has fired
 * now - last > other_host_dead_seconds
 *
 * now: local monotonic time
 *
 * last: if we have never seen the host's timestamp change, then
 * last is the local monotime when we first checked it, otherwise
 * last is the local monotime when we last saw the timestamp change
 * (which would be some time after it was written by the host.)
 *
 * other_host_fail_seconds: based on the host's io_timeout,
 * the number of seconds after which it would begin recovery
 * (killing pids) if still alive and unable to renew its lease.
 *
 * other_host_dead_seconds: based on the host's io_timeout,
 * the number of seconds after which its watchdog has fired.
 */

int sanlock_get_hosts(const char *ls_name, uint64_t host_id,
		      struct sanlk_host **hss, int *hss_count,
		      uint32_t flags);

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

/*
 * read resource lease and its owners from disk
 *
 * the sanlock daemon reads the entire lease area from disk,
 * including the leader record and all per-host dblock/mode_block records
 *
 * res.lver is set (from leader record)
 * res.flags is set to SANLK_RES_SHARED if any shared owners exist (from mode blocks)
 * host.host_id and host.generation are set for each owner (from leader or mode blocks)
 * host.timestamp is set for an exclusive owner (from leader record)
 */

int sanlock_read_resource_owners(struct sanlk_resource *res, uint32_t flags,
				 struct sanlk_host **hss, int *hss_count);

/*
 * Check the condition of a resource based on the state of the
 * resource's owners.  This can be used to check if a resource
 * is held by hosts that would cause an acquire to fail.
 *
 * owners is the list of hosts returned by sanlock_read_resource_owners()
 * hosts is the list of hosts returned by sanlock_get_hosts()
 *
 * (This is a client side operation as does not go to the daemon.)
 *
 * For each owner, check its state in hosts:
 *
 * - if not found in hosts, then the owner is not running and
 *   would not prevent acquire
 *
 * - if found in hosts but the generation does not match,
 *   then the owner host has been restarted since owning the
 *   resource and would not prevent acquire
 *
 * - if found in hosts with matching generation, then check
 *   host.flags & MASK:
 *
 * - FREE: would not prevent acquire
 * - DEAD: would not prevent acquire
 * - LIVE: prevents acquire, test fails
 * - FAIL: prevents acquire, test fails
 * - UNKNOWN: might prevent acquire, test fails
 *
 *
 * test_flags returned:
 * SANLK_TRF_FAIL: state of owners would prevent acquire, test fails
 */

#define SANLK_TRF_FAIL 0x00000001

int sanlock_test_resource_owners(struct sanlk_resource *res, uint32_t flags,
				 struct sanlk_host *owners, int owners_count,
				 struct sanlk_host *hosts, int hosts_count,
				 uint32_t *test_flags);

#endif
