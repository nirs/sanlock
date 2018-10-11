/*
 * Copyright 2018 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __RINDEX_DISK_H__
#define __RINDEX_DISK_H__

/*
 * The resource index uses two align-size areas:
 *
 * 1. The first area (the rindex itself) holds a header and
 * entries.  with each entry recording a resource lease name
 * and the offset of that lease (the resource lease disk areads
 * follow the two align-size disk areas used by the resource index.)
 *
 * 2. The second area holds an internal paxos lease that sanlock
 * uses to protect updates to the rindex in the first area.
 *
 * The rindex is one align-size area containing between 256 and
 * 2048 sectors, depending on the sector_size and align_size.
 *
 * sector 0 of the index holds the rindex_header.
 * After this, sectors 1 to 250/500/1000/2000 hold rindex_entry's.
 * The remaining sectors in the align-size area are unused.
 *
 * 512 byte sectors hold 8 entries per sector,
 * 4096 byte sectors hold 64 entries per sector.
 *
 * ALIGN1M / SECTOR512 = 2000 sectors used for rindex, 16000 max entries
 * ALIGN1M / SECTOR4K  = 250 sectors used for rindex, 16000 max entries
 * ALIGN2M / SECTOR4K  = 500 sectors used for rindex, 32000 max entries
 * ALIGN4M / SECTOR4K  = 1000 sectors used for rindex, 64000 max entries
 * ALIGN8M / SECTOR4K  = 2000 sectors used for rindex, 128000 max entries
 *
 * rindex_header.sector_size = 512 | 4096
 *
 * area_size = 1M | 2M | 4M | 8M
 *
 * rindex_header.max_resources defaults to 4096 to limit searching.
 * The caller can specify max_resources up to the max supported by
 * the sector_size/align_size combination.
 *
 * rindex_header.rindex_offset:
 * location of rindex_header from start of device, set by caller,
 * must be multiple of area_size.  (rindex_offset will often be
 * 1*area_size because rindex typically follows the lockspace area
 * which typically starts at offset 0 on the device.)
 *
 * entry_size = 64 bytes
 *
 * entry_index = N = 0 to (max_resources - 1)
 *
 * rindex_entry N offset = rindex_offset + sector_size + (N * entry_size)
 * (the sector_size contains the rindex_header)
 *
 * rindex_entry N holds information about the resource lease in
 * the N'th area following the two areas used by the resource index.
 *
 * resource_leases_start = rindex_offset + (2 * area_size)
 * resource leases begin after the two resource index areas.
 * (rindex_offset will often be area_size, so resource_leases_start
 * will often by 3*area_size)
 *
 * resource lease N offset = resource_leases_start + (N * area_size)
 *
 * rindex_entry[N].res_offset = resource lease N offset
 */

#define RINDEX_DISK_MAGIC 0x01042018
#define RINDEX_DISK_VERSION_MAJOR 0x00010000
#define RINDEX_DISK_VERSION_MINOR 0x00000002

/* MINOR 2: addition of align flags */

/* rindex_header flags */
#define RHF_ALIGN_1M   0x00000001
#define RHF_ALIGN_2M   0x00000002
#define RHF_ALIGN_4M   0x00000004
#define RHF_ALIGN_8M   0x00000008

struct rindex_header {
	uint32_t magic;
	uint32_t version;
	uint32_t flags; /* RHF_ */
	uint32_t sector_size;
	uint32_t max_resources;
	uint32_t unused;
	uint64_t rx_offset; /* location of rindex_header from start of disk */
	char lockspace_name[NAME_ID_SIZE];
};

#define MAX_RINDEX_ENTRIES_1M 16000
#define MAX_RINDEX_ENTRIES_8M 128000

/* The entry size is fixed */

struct rindex_entry {
	uint64_t res_offset; /* location of resource from start of disk */
	uint32_t flags;
	uint32_t unused;
	char name[NAME_ID_SIZE];
};

#endif
