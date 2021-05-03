/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __SANLOCK_RESOURCE_H__
#define __SANLOCK_RESOURCE_H__

/*
 * sock > -1, pid is ignored:
 * process creates registered connection and acquires/releases leases on
 * that connection for itself
 *
 * A threaded sanlock client must serialize libsanlock calls that are
 * made using a registered socket connection.
 *
 * sock == -1, pid is used:
 * process asks daemon to acquire/release leases for another separately
 * registered pid
 */

/* restrict flags */
#define SANLK_RESTRICT_ALL		0x00000001
#define SANLK_RESTRICT_SIGKILL		0x00000002
#define SANLK_RESTRICT_SIGTERM		0x00000004

/* killpath flags */
#define SANLK_KILLPATH_PID		0x00000001

/*
 * acquire flags
 *
 * SANLK_ACQUIRE_LVB
 * Enable the use of an LVB with the lock.
 *
 * SANLK_ACQUIRE_ORPHAN
 * If the lock already exists as an orphan,
 * then acquire it.  Otherwise, acquire a
 * new lock as usual.
 *
 * SANLK_ACQUIRE_ORPHAN_ONLY
 * If the lock already exists as an orphan,
 * then acquire it.  Otherwise, do not acquire
 * a lock at all and return -ENOENT.
 *
 * SANLK_ACQUIRE_OWNER_NOWAIT
 * If the lock cannot be granted immediately
 * because the owner's lease needs to time out, do
 * not wait, but return -SANLK_ACQUIRE_OWNED_RETRY.
 */

#define SANLK_ACQUIRE_LVB		0x00000001
#define SANLK_ACQUIRE_ORPHAN		0x00000002
#define SANLK_ACQUIRE_ORPHAN_ONLY	0x00000004
#define SANLK_ACQUIRE_OWNER_NOWAIT	0x00000008

/*
 * release flags
 *
 * SANLK_REL_ALL
 * Release all resources held by the client.
 * The res args are ignored.
 *
 * SANLK_REL_RENAME
 * Rename the resource lease on disk when it
 * is released.  The resource is freed and
 * renamed in a single disk operation (write
 * to the leader record.)  The first res
 * arg is the resource to release, and the
 * second resource arg contains the new name
 * for the first resource.
 *
 * SANLK_REL_ORPHAN
 * Release orphan resources asynchronously.
 * Takes a single resource struct.  If the
 * resource name is empty, then all orphans
 * for the specified lockspace are released.
 * If the resource name is set, then an
 * orphan with the matching resource name is
 * released.
 */

#define SANLK_REL_ALL		0x00000001
#define SANLK_REL_RENAME	0x00000002
#define SANLK_REL_ORPHAN	0x00000004

/*
 * convert flags
 *
 * SANLK_CONVERT_OWNER_NOWAIT
 * Same as SANLK_ACQUIRE_OWNER_NOWAIT.
 */

#define SANLK_CONVERT_OWNER_NOWAIT	0x00000008 /* NB: value must match SANLK_ACQUIRE_OWNER_NOWAIT */

/*
 * request flags
 *
 * SANLK_REQUEST_NEXT_LVER
 * The caller specifies 0 lver in res, and the daemon
 * automatically requests the current lver + 1.  When
 * multiple hosts are making requests, this flag can
 * produce unexpected results, and it would be safer
 * to read the resource, check that the current owner
 * is the one being targetted, and use that owner's
 * lver + 1 as the specifically requested lver.
 */

#define SANLK_REQUEST_NEXT_LVER	0x00000001

/*
 * request force_mode
 *
 * SANLK_REQ_FORCE (SANLK_REQ_KILL_PID deprecated)
 * Send SIGKILL to the pid holding the resource
 * (or SIGTERM if SIGKILL is restricted.)
 *
 * SANLK_REQ_GRACEFUL
 * Run killpath against the pid if it is defined, otherwise
 * send SIGTERM to the pid (or SIGKILL if SIGTERM is restricted).
 */

#define SANLK_REQ_FORCE			0x00000001
#define SANLK_REQ_GRACEFUL		0x00000002

/* old name deprecated */
#define SANLK_REQ_KILL_PID		SANLK_REQ_FORCE

int sanlock_register(void);

int sanlock_restrict(int sock, uint32_t flags);

int sanlock_killpath(int sock, uint32_t flags, const char *path, char *args);

int sanlock_acquire(int sock, int pid, uint32_t flags, int res_count,
		    struct sanlk_resource *res_args[],
		    struct sanlk_options *opt_in);

int sanlock_release(int sock, int pid, uint32_t flags, int res_count,
		    struct sanlk_resource *res_args[]);

int sanlock_inquire(int sock, int pid, uint32_t flags, int *res_count,
		    char **res_state);

int sanlock_convert(int sock, int pid, uint32_t flags,
		    struct sanlk_resource *res);

int sanlock_request(uint32_t flags, uint32_t force_mode,
		    struct sanlk_resource *res);

int sanlock_examine(uint32_t flags, struct sanlk_lockspace *ls,
		    struct sanlk_resource *res);

int sanlock_set_lvb(uint32_t flags, struct sanlk_resource *res,
		    char *lvb, int lvblen);

int sanlock_get_lvb(uint32_t flags, struct sanlk_resource *res,
		    char *lvb, int lvblen);

/*
 * Functions to convert between string and struct resource formats.
 * All allocate space for returned data that the caller must free.
 */

/*
 * convert from struct sanlk_resource to string with format:
 * <lockspace_name>:<resource_name>:<path>:<offset>[:<path>:<offset>...]:<lver>
 */

int sanlock_res_to_str(struct sanlk_resource *res, char **str_ret);

/*
 * convert to struct sanlk_resource from string with format:
 * <lockspace_name>:<resource_name>:<path>:<offset>[:<path>:<offset>...][:<lver>]
 */

int sanlock_str_to_res(char *str, struct sanlk_resource **res_ret);

/*
 * convert from array of struct sanlk_resource * to state string with format:
 * "RESOURCE1 RESOURCE2 RESOURCE3 ..."
 * RESOURCE format in sanlock_res_to_str() comment
 */

int sanlock_args_to_state(int res_count,
			  struct sanlk_resource *res_args[],
			  char **res_state);

/*
 * convert to array of struct sanlk_resource * from state string with format:
 * "RESOURCE1 RESOURCE2 RESOURCE3 ..."
 * RESOURCE format in sanlock_str_to_res() comment
 */

int sanlock_state_to_args(char *res_state,
			  int *res_count,
			  struct sanlk_resource ***res_args);

/*
 * convert to struct sanlk_lockspace from string with format:
 * <lockspace_name>:<host_id>:<path>:<offset>
 */

int sanlock_str_to_lockspace(char *str, struct sanlk_lockspace *ls);

#endif
