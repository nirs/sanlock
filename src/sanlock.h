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

#define SANLK_RES_LVER		0x1	/* lver field is set */
#define SANLK_RES_NUM_HOSTS	0x2	/* data32 field is new num_hosts */
#define SANLK_RES_SHARED	0x4

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

/* command-specific command options (can include per resource data, but
   that requires the extra work of segmenting it by resource name) */

struct sanlk_options {
	char owner_name[SANLK_NAME_LEN]; /* optional user friendly name */
	uint32_t flags;
	uint32_t len;
	/* followed by len bytes (migration input will use this) */
	char str[0];
};

struct sanlk_lockspace {
	char name[SANLK_NAME_LEN];
	uint64_t host_id;
	uint32_t flags;
	struct sanlk_disk host_id_disk;
};

struct sanlk_host {
	uint64_t host_id;
	uint64_t generation;
	uint64_t timestamp;
	uint32_t io_timeout;
	uint32_t flags;
};

size_t sanlock_path_export(char *dst, const char *src, size_t dstlen);
size_t sanlock_path_import(char *dst, const char *src, size_t dstlen);

#endif
