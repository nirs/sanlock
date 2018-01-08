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
 * The resource index is uses two align-size (1/8M) areas.
 *
 * The first area (the rindex itself) holds a header and entrys,
 * with each entry recording a resource lease name and the
 * offset of that lease (the resource leases follow the index
 * areas.)
 *
 * The second area holds an internal paxos lease that sanlock
 * uses to protect updates to the rindex.
 *
 * The rindex is one align-size area containing 2048 sectors.
 * The sector 0 of the index holds the rindex_header.
 * After this, sectors 1-2000 of the index hold rindex_entry's.
 * The final 47 sectors are unused.
 *
 * 512 byte sectors hold 8 entries per sector, so 2000 sectors
 * holds up to 16000 entries.
 *
 * 4096 byte sectors hold 64 entries per sector, so 2000 sectors
 * holds up to 128000 entries.
 *
 * rindex_header.sector_size = 512 | 4096
 *
 * area_size = 1M | 8M
 * (determined from sector_size)
 *
 * rindex_header.max_resources defaults to 4096 to limit searching.
 * The caller can specify up to 16000 | 128000 max_resources.
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
#define RINDEX_DISK_VERSION_MINOR 0x00000001

struct rindex_header {
	uint32_t magic;
	uint32_t version;
	uint32_t flags;
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
