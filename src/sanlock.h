/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __SANLOCK_H__
#define __SANLOCK_H__

/* pid can own this many resources at once */

#define SANLK_MAX_RESOURCES	8

/* max resource name length */

#define SANLK_NAME_LEN		48   

/* max disk path length, includes terminating \0 byte */

#define SANLK_PATH_LEN		1024

/* disk offset units */

#define SANLK_UNITS_BYTES	0
#define SANLK_UNITS_SECTORS	1
#define SANLK_UNITS_KB		2
#define SANLK_UNITS_MB		3

struct sanlk_disk {
	char path[SANLK_PATH_LEN]; /* must include terminating \0 */
	uint64_t offset;
	uint32_t units;
	uint32_t pad1;
	uint32_t pad2;
};

#define SANLK_RES_LVER		0x1

struct sanlk_resource {
	char lockspace_name[SANLK_NAME_LEN]; /* terminating \0 not required */
	char name[SANLK_NAME_LEN]; /* terminating \0 not required */
	uint64_t lver;     /* use with SANLK_RES_LVER */
	uint64_t data64;   /* per-resource command-specific data */
	uint32_t data32;   /* per-resource command-specific data */
	uint32_t unused;
	uint32_t flags;
	uint32_t num_disks;
	/* followed by num_disks sanlk_disk structs */
	struct sanlk_disk disks[0];
};

/* command-specific command options (can include per resource data, but
   that requires the extra work of segmenting it by resource name) */

#define SANLK_OPT_NUM_HOSTS	0x1

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

#endif

