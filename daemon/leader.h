/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __LEADER_H__
#define __LEADER_H__

enum {
	DP_OK = 1,
	DP_NONE = 0,    /* unused */
	DP_ERROR = -1,
	DP_INVAL = -2,
	DP_NOMEM = -3,
	DP_LIVE_LEADER = -4,
	DP_DIFF_LEADERS = -5,
	DP_READ_LEADERS = -6,
	DP_OWN_DBLOCK = -7,
	DP_WRITE1_DBLOCKS = -8,
	DP_WRITE2_DBLOCKS = -9,
	DP_WRITE_REQUESTS = -10,
	DP_WRITE_LEADERS = -11,
	DP_READ1_MBAL = -12,
	DP_READ1_LVER = -13,
	DP_READ2_MBAL = -14,
	DP_READ2_LVER = -15,
	DP_READ1_DBLOCKS = -16,
	DP_READ2_DBLOCKS = -17,
	DP_BAD_MAGIC = -18,
	DP_BAD_VERSION = -19,
	DP_BAD_CLUSTERMODE = -20,
	DP_BAD_RESOURCEID = -21,
	DP_BAD_NUMHOSTS = -22,
	DP_BAD_CHECKSUM = -23,
	DP_BAD_LEADER = -24,
	DP_OTHER_INP = -25,
	DP_BAD_SECTORSIZE = -26,
	DP_REACQUIRE_LVER = -27,
	DP_BAD_LOCKSPACE = -28,
};

/* does not include terminating null byte */
/* NB NAME_ID_SIZE must match SANLK_NAME_LEN */
/* NB NAME_ID_SIZE is part of ondisk format */

#define NAME_ID_SIZE 48

#define PAXOS_DISK_MAGIC 0x06152010
#define PAXOS_DISK_VERSION_MAJOR 0x00040000
#define PAXOS_DISK_VERSION_MINOR 0x00000001

#define DELTA_DISK_MAGIC 0x12212010
#define DELTA_DISK_VERSION_MAJOR 0x00030000
#define DELTA_DISK_VERSION_MINOR 0x00000001

/* for all disk structures:
   uint64 aligned on 8 byte boundaries,
   uint32 aligned on 4 byte boundaries, etc */

/* NB. adjust LEADER_COMPARE_LEN and LEADER_CHECKSUM_LEN when changing
   this struct.
   LEADER_CHECKSUM_LEN should end just before the checksum field.
   LEADER_COMPARE_LEN should end just before timestamp.
   The checksum field should follow the timestamp field.

   The leader may be partially through updating the timestamp on
   multiple leader blocks in a lease, but for the purpose of counting
   repetitions of a leader block owned by a single host they should be
   counted together, so COMPARE_LEN should exclude timestamp.

   The leader may also be partially through updating next_owner_id on
   multiple leader blocks in a lease, but this potential inconsistency,
   like timestamp, should not factor against the repetition count. */

#define LEADER_COMPARE_LEN 152
#define LEADER_CHECKSUM_LEN 168
#define LEASE_FREE 0

struct leader_record {
	uint32_t magic;
	uint32_t version;
	uint32_t cluster_mode;
	uint32_t sector_size;
	uint64_t num_hosts;
	uint64_t max_hosts;
	uint64_t owner_id; /* host_id of owner */
	uint64_t owner_generation;
	uint64_t lver;
	char space_name[NAME_ID_SIZE]; /* lockspace for resource */
	char resource_name[NAME_ID_SIZE]; /* resource being locked */
	uint64_t timestamp;
	uint64_t next_owner_id;
	uint32_t checksum;
	uint32_t pad2;
};

#endif
