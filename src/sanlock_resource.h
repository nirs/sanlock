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
 * sock == -1, pid is used:
 * process asks daemon to acquire/release leases for another separately
 * registered pid
 */

/* restrict flags */
#define SANLK_RESTRICT_ALL	0x00000001
#define SANLK_RESTRICT_SIGKILL	0x00000002
#define SANLK_RESTRICT_SIGTERM	0x00000004

/* killpath flags */
#define SANLK_KILLPATH_PID	0x00000001

/* release flags */
#define SANLK_REL_ALL		0x00000001

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

int sanlock_request(uint32_t flags, uint32_t force_mode,
		    struct sanlk_resource *res);

int sanlock_examine(uint32_t flags, struct sanlk_lockspace *ls,
		    struct sanlk_resource *res);

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
