/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __SANLOCK_H__
#define __SANLOCK_H__

/* an acquire or release call can specify this many explicit
   resources in a single call. */

#define SANLK_MAX_RESOURCES	8

/* max resource name length */

#define SANLK_NAME_LEN		48   

/* max disk path length, includes terminating \0 byte, and escape chars,
   i.e. the strlen with esc chars inserted must still be less than 1024. */

#define SANLK_PATH_LEN		1024

/* max length of kill script path and args, includes terminate \0 byte */

#define SANLK_HELPER_PATH_LEN	128
#define SANLK_HELPER_ARGS_LEN	128

/* max disks in a single lease */

#define SANLK_MAX_DISKS 4

/*
 * max length of a sanlk_resource in string format
 * <lockspace_name>:<resource_name>:<path>:<offset>[:<path>:<offset>...]:<lver>
 *     48 SANLK_NAME_LEN
 * +    1 colon
 * +   48 SANLK_NAME_LEN
 * +    1 colon
 * + 4184 (4 MAX_DISKS * (1024 SANLK_PATH_LEN + 1 colon + 20 offset + 1 colon))
 * +   20 lver
 * ------
 *   4302
 */

#define SANLK_MAX_RES_STR	4400

/* TODO: add more padding to sanlk_disk so we can extend sync_disk
   later without changing abi */

struct sanlk_disk {
	char path[SANLK_PATH_LEN]; /* must include terminating \0 */
	uint64_t offset;
	uint32_t pad1;
	uint32_t pad2;
};

/*
 * PERSISTENT: if the pid holding the resource lease exits,
 * the lease will not be released, but will be moved to the
 * orphans list.  On disk and from the perspective of other
 * hosts, nothing changes when a lease is orphaned; it continues
 * to be held by the host.
 *
 * (If persistent shared locks are used on a resource, then
 * all the locks on that resource should be persistent.)
 *
 * A new process can acquire an orphan resource using
 * the ACQUIRE_ORPHAN flag.  This implies that the lockspace
 * had continued running and the resource not released by the
 * host between the time the resource became an orphan and was
 * then transferred to a new process.
 *
 * Orphan impact on the lockspace: if the lockspace is stopping
 * because of rem, or lease failure, the ls config option
 * USED_BY_ORPHANS will block the release of the lockspace
 * (like the USED option), if orphans exist for the lockspace.
 * Without USED_BY_ORPHANS, the lockspace would exit and
 * leave the orphan resources unchanged (not released) on disk.
 * The unreleased orphan resources could be acquired by another
 * host if the lockspace lease is cleanly released.
 */

#define SANLK_RES_LVER		0x00000001	/* lver field is set */
#define SANLK_RES_NUM_HOSTS	0x00000002	/* data32 field is new num_hosts */
#define SANLK_RES_SHARED	0x00000004
#define SANLK_RES_PERSISTENT	0x00000008
#define SANLK_RES_ALIGN1M	0x00000010
#define SANLK_RES_ALIGN2M	0x00000020
#define SANLK_RES_ALIGN4M	0x00000040
#define SANLK_RES_ALIGN8M	0x00000080
#define SANLK_RES_SECTOR512	0x00000100
#define SANLK_RES_SECTOR4K	0x00000200

struct sanlk_resource {
	char lockspace_name[SANLK_NAME_LEN]; /* terminating \0 not required */
	char name[SANLK_NAME_LEN]; /* terminating \0 not required */
	uint64_t lver;     /* use with SANLK_RES_LVER */
	uint64_t data64;   /* per-resource command-specific data */
	uint32_t data32;   /* per-resource command-specific data */
	uint32_t unused;
	uint32_t flags;    /* SANLK_RES_ */
	uint32_t num_disks;
	/* followed by num_disks sanlk_disk structs */
	struct sanlk_disk disks[0];
};

/* make these values match the RES equivalent in case of typos */
#define SANLK_RIF_ALIGN1M	0x00000010
#define SANLK_RIF_ALIGN2M	0x00000020
#define SANLK_RIF_ALIGN4M	0x00000040
#define SANLK_RIF_ALIGN8M	0x00000080
#define SANLK_RIF_SECTOR512	0x00000100
#define SANLK_RIF_SECTOR4K	0x00000200

struct sanlk_rindex {
	uint32_t flags;		/* SANLK_RIF_ */
	uint32_t max_resources; /* the max res structs that will follow rindex */
	uint64_t unused;
	char lockspace_name[SANLK_NAME_LEN]; /* terminating \0 not required */
	struct sanlk_disk disk; /* location of rindex */
};

struct sanlk_rentry {
	char name[SANLK_NAME_LEN]; /* terminating \0 not required */
	uint64_t offset;
	uint32_t flags;
	uint32_t unused;
};

/* command-specific command options (can include per resource data, but
   that requires the extra work of segmenting it by resource name) */

struct sanlk_options {
	char owner_name[SANLK_NAME_LEN]; /* optional user friendly name */
	uint32_t flags;
	uint32_t len;
	/* followed by len bytes (migration input will use this) */
	char str[0];
};

#define SANLK_LSF_ADD		0x00000001
#define SANLK_LSF_REM		0x00000002

/* make these values match the RES equivalent in case of typos */
#define SANLK_LSF_ALIGN1M	0x00000010
#define SANLK_LSF_ALIGN2M	0x00000020
#define SANLK_LSF_ALIGN4M	0x00000040
#define SANLK_LSF_ALIGN8M	0x00000080
#define SANLK_LSF_SECTOR512	0x00000100
#define SANLK_LSF_SECTOR4K	0x00000200

struct sanlk_lockspace {
	char name[SANLK_NAME_LEN];
	uint64_t host_id;
	uint32_t flags; /* SANLK_LSF_ */
	struct sanlk_disk host_id_disk;
};

struct sanlk_host {
	uint64_t host_id;
	uint64_t generation;
	uint64_t timestamp;
	uint32_t io_timeout;
	uint32_t flags;
};

struct sanlk_host_event {
	uint64_t host_id;
	uint64_t generation;
	uint64_t event;
	uint64_t data;
};

size_t sanlock_path_export(char *dst, const char *src, size_t dstlen);
size_t sanlock_path_import(char *dst, const char *src, size_t dstlen);

const char *sanlock_strerror(int rv);

#endif
