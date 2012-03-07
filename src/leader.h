/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __LEADER_H__
#define __LEADER_H__

/* does not include terminating null byte */
/* NB NAME_ID_SIZE must match SANLK_NAME_LEN */
/* NB NAME_ID_SIZE is part of ondisk format */

#define NAME_ID_SIZE 48

#define PAXOS_DISK_MAGIC 0x06152010
#define PAXOS_DISK_VERSION_MAJOR 0x00060000
#define PAXOS_DISK_VERSION_MINOR 0x00000001 

#define DELTA_DISK_MAGIC 0x12212010
#define DELTA_DISK_VERSION_MAJOR 0x00030000
#define DELTA_DISK_VERSION_MINOR 0x00000002

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
   counted together, so COMPARE_LEN should exclude timestamp. */

#define LEADER_COMPARE_LEN 152
#define LEADER_CHECKSUM_LEN 168
#define LEASE_FREE 0

#define LFL_SHORT_HOLD 0x00000001

struct leader_record {
	uint32_t magic;
	uint32_t version;
	uint32_t flags;
	uint32_t sector_size;
	uint64_t num_hosts;
	uint64_t max_hosts;
	uint64_t owner_id; /* host_id of owner */
	uint64_t owner_generation;
	uint64_t lver;
	char space_name[NAME_ID_SIZE]; /* lockspace for resource */
	char resource_name[NAME_ID_SIZE]; /* resource being locked */
	uint64_t timestamp;
	uint64_t unused1;
	uint32_t checksum;
	uint32_t unused2;
	uint64_t write_id;		/* for extra info, debug */
	uint64_t write_generation;	/* for extra info, debug */
	uint64_t write_timestamp;	/* for extra info, debug */
};

/* leader_record can use first 256 bytes of a sector,
   bitmap uses the last 256 bytes */

#define LEADER_RECORD_MAX 256
#define HOSTID_BITMAP_OFFSET 256
#define HOSTID_BITMAP_SIZE 256

#define REQ_DISK_MAGIC 0x08292011
#define REQ_DISK_VERSION_MAJOR 0x00010000
#define REQ_DISK_VERSION_MINOR 0x00000001

struct request_record {
	uint32_t magic;
	uint32_t version;
	uint64_t lver;
	uint32_t force_mode;
};

#endif
