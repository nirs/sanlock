/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sanlock_internal.h"
#include "diskio.h"
#include "log.h"
#include "crc32c.h"
#include "host_id.h"
#include "delta_lease.h"
#include "paxos_lease.h"

/*
 * largely copied from vdsm.git/sync_manager/
 */

#define NO_VAL 0

struct request_record {
	uint64_t lver;
	uint8_t force_mode;
};

/* ref: ballot_ticket_record */
struct paxos_dblock {
	uint64_t mbal; /* aka curr_bal */
	uint64_t bal;  /* aka inp_bal */
	uint64_t inp;  /* aka inp_val */
	uint64_t lver; /* leader version */
};

int majority_disks(struct token *token, int num)
{
	int num_disks = token->r.num_disks;

	/* odd number of disks */

	if (num_disks % 2)
		return num >= ((num_disks / 2) + 1);

	/* even number of disks */

	if (num > (num_disks / 2))
		return 1;

	if (num < (num_disks / 2))
		return 0;

	/* TODO: half of disks are majority if tiebreaker disk is present */
	return 0;
}

static int write_dblock(struct timeout *ti,
			struct sync_disk *disk, uint64_t host_id,
			struct paxos_dblock *pd)
{
	int rv;

	/* 1 leader block + 1 request block;
	   host_id N is block offset N-1 */

	rv = write_sector(disk, 2 + host_id - 1, (char *)pd,
			  sizeof(struct paxos_dblock),
			  ti->io_timeout_seconds, ti->use_aio, "dblock");
	return rv;
}

static int write_request(struct timeout *ti,
			 struct sync_disk *disk, struct request_record *rr)
{
	int rv;

	rv = write_sector(disk, 1, (char *)rr, sizeof(struct request_record),
			  ti->io_timeout_seconds, ti->use_aio, "request");
	return rv;
}

static int write_leader(struct timeout *ti,
			struct sync_disk *disk, struct leader_record *lr)
{
	int rv;

	rv = write_sector(disk, 0, (char *)lr, sizeof(struct leader_record),
			  ti->io_timeout_seconds, ti->use_aio, "leader");
	return rv;
}

static int read_dblock(struct timeout *ti,
		       struct sync_disk *disk, uint64_t host_id,
		       struct paxos_dblock *pd)
{
	int rv;

	/* 1 leader block + 1 request block; host_id N is block offset N-1 */

	rv = read_sectors(disk, 2 + host_id - 1, 1, (char *)pd,
			  sizeof(struct paxos_dblock),
			  ti->io_timeout_seconds, ti->use_aio, "dblock");
	return rv;
}

static int read_dblocks(struct timeout *ti,
			struct sync_disk *disk, struct paxos_dblock *pds,
			int pds_count)
{
	char *data;
	int data_len, rv, i;

	data_len = pds_count * disk->sector_size;

	data = malloc(data_len);
	if (!data) {
		log_error("read_dblocks malloc %d %s", data_len, disk->path);
		rv = -1;
		goto out;
	}

	/* 2 = 1 leader block + 1 request block */

	rv = read_sectors(disk, 2, pds_count, data, data_len,
			  ti->io_timeout_seconds, ti->use_aio, "dblocks");
	if (rv < 0)
		goto out_free;

	/* copy the first N bytes from each sector, where N is size of
	   paxos_dblock */

	for (i = 0; i < pds_count; i++) {
		memcpy(&pds[i], data + (i * disk->sector_size),
		       sizeof(struct paxos_dblock));
	}

	rv = 0;
 out_free:
	free(data);
 out:
	return rv;
}

static int read_leader(struct timeout *ti,
		       struct sync_disk *disk, struct leader_record *lr)
{
	int rv;

	/* 0 = leader record is first sector */

	rv = read_sectors(disk, 0, 1, (char *)lr,
			  sizeof(struct leader_record),
			  ti->io_timeout_seconds, ti->use_aio, "leader");

	return rv;
}


#if 0
static int read_request(struct timeout *ti,
			struct sync_disk *disk, struct request_record *rr)
{
	int rv;

	/* 1 = request record is second sector */

	rv = read_sectors(disk, 1, (char *)rr, sizeof(struct request_record),
			  ti->io_timeout_seconds, ti->use_aio, "request");

	return rv;
}
#endif

/* host_id and inp are both generally our_host_id */

static int run_disk_paxos(struct timeout *ti,
			  struct token *token, uint64_t host_id, uint64_t inp,
			  int num_hosts, uint64_t lver,
			  struct paxos_dblock *dblock_out)
{
	struct paxos_dblock bk[num_hosts];
	struct paxos_dblock bk_max;
	struct paxos_dblock dblock;
	int num_disks = token->r.num_disks;
	int num_writes, num_reads;
	int d, q, rv;

	if (!host_id) {
		log_errot(token, "invalid host_id");
		return SANLK_INVAL;
	}

	if (!inp) {
		log_errot(token, "invalid inp");
		return SANLK_INVAL;
	}

	/* read one of our own dblock's to get initial dblock values */

	memset(&dblock, 0, sizeof(struct paxos_dblock));

	for (d = 0; d < num_disks; d++) {
		rv = read_dblock(ti, &token->disks[d], host_id, &dblock);
		if (rv < 0)
			continue;
		/* need only one dblock to get initial values */
		break;
	}

	if (rv < 0) {
		log_errot(token, "no initial dblock found");
		return SANLK_OWN_DBLOCK;
	}

	log_token(token, "initial dblock %u mbal %llu bal %llu inp %llu lver %llu", d,
		  (unsigned long long)dblock.mbal,
		  (unsigned long long)dblock.bal,
		  (unsigned long long)dblock.inp,
		  (unsigned long long)dblock.lver);

	if (lver > dblock.lver) {
		dblock.mbal = host_id;
		dblock.bal = 0;		/* or NO_VAL? lamport paper has 0 */
		dblock.inp = NO_VAL;
		dblock.lver = lver;
	} else {
		dblock.mbal += num_hosts;
	}

	/*
	 * phase 1
	 *
	 * "For each disk d, it tries first to write dblock[p] to disk[d][p]
	 * and then to read disk[d][q] for all other processors q.  It aborts
	 * the ballot if, for any d and q, it finds disk[d][q].mbal >
	 * dblock[p].mbal. The phase completes when p has written and read a
	 * majority of the disks, without reading any block whose mbal
	 * component is greater than dblock[p].mbal."
	 */

	memset(&bk_max, 0, sizeof(struct paxos_dblock));
	bk_max.bal = NO_VAL;
	bk_max.inp = NO_VAL;

	num_writes = 0;

	for (d = 0; d < num_disks; d++) {
		rv = write_dblock(ti, &token->disks[d], host_id, &dblock);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_errot(token, "cannot write dblock to majority of disks");
		return SANLK_WRITE1_DBLOCKS;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_dblocks(ti, &token->disks[d], bk, num_hosts);
		if (rv < 0)
			continue;
		num_reads++;

		for (q = 0; q < num_hosts; q++) {
			if (bk[q].lver < dblock.lver)
				continue;

			if (bk[q].lver > dblock.lver) {
				log_errot(token, "bk %d %d lver %llu dblock lver %llu",
					  d, q,
					  (unsigned long long)bk[q].lver,
					  (unsigned long long)dblock.lver);
				return SANLK_READ1_LVER;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk[q].mbal > dblock.mbal) {
				log_errot(token, "bk %d %d mbal %llu dblock mbal %llu",
					  d, q,
					  (unsigned long long)bk[q].mbal,
					  (unsigned long long)dblock.mbal);
				return SANLK_READ1_MBAL;
			}

			/* see choosing inp for phase 2 in comment below */

			if (bk[q].inp == NO_VAL)
				continue;

			if (bk_max.bal == NO_VAL || bk[q].bal > bk_max.bal)
				bk_max = bk[q];
		}
	}

	if (!majority_disks(token, num_reads)) {
		log_errot(token, "cannot read dblocks on majority of disks");
		return SANLK_READ1_DBLOCKS;
	}

	/*
	 * "When it completes phase 1, p chooses a new value of dblock[p].inp,
	 * sets dblock[p].bal to dblock[p].mbal (its current ballot number),
	 * and begins phase 2."
	 *
	 * "We now describe how processor p chooses the value of dblock[p].inp
	 * that it tries to commit in phase 2. Let blocksSeen be the set
	 * consisting of dblock[p] and all the records disk[d][q] read by p in
	 * phase 1. Let nonInitBlks be the subset of blocksSeen consisting of
	 * those records whose inp field is not NotAnInput.  If nonInitBlks is
	 * empty, then p sets dblock[p].inp to its own input value input[p].
	 * Otherwise, it sets dblock[p].inp to bk.inp for some record bk in
	 * nonInitBlks having the largest value of bk.bal."
	 */

	log_token(token, "bk_max inp %llu bal %llu",
		  (unsigned long long)bk_max.inp,
		  (unsigned long long)bk_max.bal);

	dblock.inp = (bk_max.inp == NO_VAL) ? inp : bk_max.inp;
	dblock.bal = dblock.mbal;

	/*
	 * phase 2
	 *
	 * Same description as phase 1, same sequence of writes/reads.
	 */

	num_writes = 0;

	for (d = 0; d < num_disks; d++) {
		rv = write_dblock(ti, &token->disks[d], host_id, &dblock);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_errot(token, "cannot write dblock to majority of disks 2");
		return SANLK_WRITE2_DBLOCKS;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_dblocks(ti, &token->disks[d], bk, num_hosts);
		if (rv < 0)
			continue;
		num_reads++;

		for (q = 0; q < num_hosts; q++) {
			if (bk[q].lver < dblock.lver)
				continue;

			if (bk[q].lver > dblock.lver) {
				log_errot(token, "bk %d %d lver %llu dblock lver %llu",
					  d, q,
					  (unsigned long long)bk[q].lver,
					  (unsigned long long)dblock.lver);
				return SANLK_READ2_LVER;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk[q].mbal > dblock.mbal) {
				log_errot(token, "bk %d %d mbal %llu dblock mbal %llu",
					  d, q,
					  (unsigned long long)bk[q].mbal,
					  (unsigned long long)dblock.mbal);
				return SANLK_READ2_MBAL;
			}
		}
	}

	if (!majority_disks(token, num_reads)) {
		log_errot(token, "cannot read dblocks from majority of disks 2");
		return SANLK_READ2_DBLOCKS;
	}

	/* "When it completes phase 2, p has committed dblock[p].inp." */

	memcpy(dblock_out, &dblock, sizeof(struct paxos_dblock));

	return SANLK_OK;
}

uint32_t leader_checksum(struct leader_record *lr)
{
	return crc32c((uint32_t)~1, (char *)lr, LEADER_CHECKSUM_LEN);
}

static void log_leader_error(int result,
			     struct token *token,
			     struct sync_disk *disk,
			     struct leader_record *lr,
			     const char *caller)
{
	log_errot(token, "leader1 %s error %d sn %.48s rn %.48s",
		  caller ? caller : "unknown",
		  result,
		  token->r.lockspace_name,
		  token->r.name);

	log_errot(token, "leader2 path %s offset %llu",
		  disk->path,
		  (unsigned long long)disk->offset);

	log_errot(token, "leader3 m %u v %u ss %u nh %llu mh %llu oi %llu og %llu lv %llu",
		  lr->magic,
		  lr->version,
		  lr->sector_size,
		  (unsigned long long)lr->num_hosts,
		  (unsigned long long)lr->max_hosts,
		  (unsigned long long)lr->owner_id,
		  (unsigned long long)lr->owner_generation,
		  (unsigned long long)lr->lver);

	log_errot(token, "leader4 sn %.48s rn %.48s ts %llu cs %x",
		  lr->space_name,
		  lr->resource_name,
		  (unsigned long long)lr->timestamp,
		  lr->checksum);
}

static int verify_leader(struct token *token, struct sync_disk *disk,
			 struct leader_record *lr,
			 const char *caller)
{
	struct leader_record leader_rr;
	uint32_t sum;
	int result, rv;

	if (lr->magic != PAXOS_DISK_MAGIC) {
		log_errot(token, "verify_leader wrong magic %x %s",
			  lr->magic, disk->path);
		result = SANLK_BAD_MAGIC;
		goto fail;
	}

	if ((lr->version & 0xFFFF0000) != PAXOS_DISK_VERSION_MAJOR) {
		log_errot(token, "verify_leader wrong version %x %s",
			  lr->version, disk->path);
		result = SANLK_BAD_VERSION;
		goto fail;
	}

	if (lr->sector_size != disk->sector_size) {
		log_errot(token, "verify_leader wrong sector size %d %d %s",
			  lr->sector_size, disk->sector_size, disk->path);
		result = SANLK_BAD_SECTORSIZE;
		goto fail;
	}

	if (strncmp(lr->space_name, token->r.lockspace_name, NAME_ID_SIZE)) {
		log_errot(token, "verify_leader wrong space name %.48s %.48s %s",
			  lr->space_name, token->r.lockspace_name, disk->path);
		result = SANLK_BAD_LOCKSPACE;
		goto fail;
	}

	if (strncmp(lr->resource_name, token->r.name, NAME_ID_SIZE)) {
		log_errot(token, "verify_leader wrong resource name %.48s %.48s %s",
			  lr->resource_name, token->r.name, disk->path);
		result = SANLK_BAD_RESOURCEID;
		goto fail;
	}

	if (lr->num_hosts < token->host_id) {
		log_errot(token, "verify_leader num_hosts too small %llu %llu %s",
			  (unsigned long long)lr->num_hosts,
			  (unsigned long long)token->host_id, disk->path);
		result = SANLK_BAD_NUMHOSTS;
		goto fail;
	}

	sum = leader_checksum(lr);

	if (lr->checksum != sum) {
		log_errot(token, "verify_leader wrong checksum %x %x %s",
			  lr->checksum, sum, disk->path);
		result = SANLK_BAD_CHECKSUM;
		goto fail;
	}

	return SANLK_OK;

 fail:
	log_leader_error(result, token, disk, lr, caller);

	memset(&leader_rr, 0, sizeof(leader_rr));

	rv = read_sectors(disk, 0, 1, (char *)&leader_rr,
			  sizeof(struct leader_record),
			  0, 0, "paxos_verify");

	log_leader_error(rv, token, disk, &leader_rr, "paxos_verify");

	return result;
}

static int leaders_match(struct leader_record *a, struct leader_record *b)
{
	if (!memcmp(a, b, LEADER_COMPARE_LEN))
		return 1;
	return 0;
}

int paxos_lease_leader_read(struct timeout *ti,
			    struct token *token, struct leader_record *leader_ret,
			    const char *caller)
{
	struct leader_record prev_leader;
	struct leader_record *leaders;
	int *leader_reps;
	int leaders_len, leader_reps_len;
	int num_reads;
	int num_disks = token->r.num_disks;
	int rv, d, i, found;
	int error;

	leaders_len = num_disks * sizeof(struct leader_record);
	leader_reps_len = num_disks * sizeof(int);

	leaders = malloc(leaders_len);
	if (!leaders)
		return SANLK_NOMEM;

	leader_reps = malloc(leader_reps_len);
	if (!leader_reps) {
		free(leaders);
		return SANLK_NOMEM;
	}

	/*
	 * find a leader block that's consistent on the majority of disks,
	 * so we can use as the basis for the new leader
	 * ref: validate_multiple_disk_leader
	 */

	memset(&prev_leader, 0, sizeof(struct leader_record));
	memset(leaders, 0, leaders_len);
	memset(leader_reps, 0, leader_reps_len);

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_leader(ti, &token->disks[d], &leaders[d]);
		if (rv < 0)
			continue;

		rv = verify_leader(token, &token->disks[d], &leaders[d], caller);
		if (rv < 0)
			continue;

		num_reads++;

		leader_reps[d] = 1;

		/* count how many times the same leader block repeats */

		for (i = 0; i < d; i++) {
			if (leaders_match(&leaders[d], &leaders[i])) {
				leader_reps[i]++;
				break;
			}
		}
	}

	if (!majority_disks(token, num_reads)) {
		log_errot(token, "paxos_leader_read no majority reads");
		error = SANLK_READ_LEADERS;
		goto fail;
	}

	/* check that a majority of disks have the same leader */

	found = 0;

	for (d = 0; d < num_disks; d++) {
		if (!majority_disks(token, leader_reps[d]))
			continue;

		/* leader on d is the same on a majority of disks,
		   prev_leader becomes the prototype for new_leader */

		memcpy(&prev_leader, &leaders[d], sizeof(struct leader_record));
		found = 1;
		break;
	}

	if (!found) {
		log_errot(token, "paxos_leader_read no majority reps");
		error = SANLK_DIFF_LEADERS;
		goto fail;
	}

	log_token(token, "%s leader_read owner %llu lver %llu hosts %llu "
		  "time %llu res %s",
		  caller ? caller : "unknown",
		  (unsigned long long)prev_leader.owner_id,
		  (unsigned long long)prev_leader.lver,
		  (unsigned long long)prev_leader.num_hosts,
		  (unsigned long long)prev_leader.timestamp,
		  prev_leader.resource_name);

	memcpy(leader_ret, &prev_leader, sizeof(struct leader_record));
	return SANLK_OK;

 fail:
	free(leaders);
	free(leader_reps);
	return error;
}

static int write_new_leader(struct timeout *ti,
			    struct token *token, struct leader_record *nl)
{
	int num_disks = token->r.num_disks;
	int num_writes = 0;
	int error = SANLK_OK;
	int rv, d;

	for (d = 0; d < num_disks; d++) {
		rv = write_leader(ti, &token->disks[d], nl);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_errot(token, "write_new_leader no majority writes");
		error = SANLK_WRITE_LEADERS;
	}

	return error;
}

/*
 * acquire a lease
 * ref: obtain()
 */

int paxos_lease_acquire(struct timeout *ti,
			struct token *token, uint32_t flags,
		        struct leader_record *leader_ret,
		        uint64_t acquire_lver,
		        int new_num_hosts)
{
	struct leader_record prev_leader;
	struct leader_record new_leader;
	struct leader_record host_id_leader;
	struct sync_disk host_id_disk;
	struct paxos_dblock dblock;
	time_t start;
	uint64_t last_timestamp = 0;
	int error, rv, disk_open = 0;

	log_token(token, "paxos_acquire begin lver %llu flags %x",
		  (unsigned long long)acquire_lver, flags);

	error = paxos_lease_leader_read(ti, token, &prev_leader, "paxos_acquire");
	if (error < 0)
		goto out;

	if (flags & PAXOS_ACQUIRE_FORCE)
		goto run;

	if (prev_leader.timestamp == LEASE_FREE) {
		log_token(token, "paxos_acquire lease free");
		goto run;
	}

	if (prev_leader.owner_id == token->host_id &&
	    prev_leader.owner_generation == token->host_generation) {
		log_token(token, "paxos_acquire already owner id %llu gen %llu",
			  (unsigned long long)token->host_id,
			  (unsigned long long)token->host_generation);
		goto run;
	}

	/*
	 * Check if current owner is alive based on its host_id renewals.
	 * If the current owner has been dead long enough we can assume that
	 * its watchdog has triggered and we can go for the paxos lease.
	 */

	log_token(token, "paxos_acquire check owner_id %llu",
		  (unsigned long long)prev_leader.owner_id);

	memset(&host_id_disk, 0, sizeof(host_id_disk));

	rv = host_id_disk_info(prev_leader.space_name, &host_id_disk);
	if (rv < 0) {
		log_errot(token, "paxos_acquire no lockspace info %.48s",
			  prev_leader.space_name);
		error = SANLK_BAD_SPACE_NAME;
		goto out;
	}

	disk_open = open_disks_fd(&host_id_disk, 1);
	if (disk_open != 1) {
		log_errot(token, "paxos_acquire cannot open host_id_disk");
		error = SANLK_BAD_SPACE_DISK;
		goto out;
	}

	start = time(NULL);

	while (1) {
		error = delta_lease_leader_read(ti, &host_id_disk,
						prev_leader.space_name,
						prev_leader.owner_id,
						&host_id_leader,
						"paxos_acquire");
		if (error < 0) {
			log_errot(token, "paxos_acquire host_id %llu read %d",
				  (unsigned long long)prev_leader.owner_id,
				  error);
			goto out;
		}

		/* a host_id cannot become free in less than
		   host_id_timeout_sec after the final renewal because
		   a host_id must first be acquired before being freed,
		   and acquiring cannot take less than host_id_timeout_sec */

		if (host_id_leader.timestamp == LEASE_FREE) {
			log_token(token, "paxos_acquire host_id %llu free",
				  (unsigned long long)prev_leader.owner_id);
			goto run;
		}

		/* another host has acquired the host_id of the host that
		   owned this paxos lease; acquiring a host_id also cannot be
		   done in less than host_id_timeout_sec */

		if (host_id_leader.owner_id != prev_leader.owner_id) {
			log_token(token, "paxos_acquire host_id %llu owner %llu",
				  (unsigned long long)prev_leader.owner_id,
				  (unsigned long long)host_id_leader.owner_id);
			goto run;
		}

		/* the host_id that owns this lease may be alive, but it
		   owned the lease in a previous generation without freeing it,
		   and no longer owns it */

		if (host_id_leader.owner_generation > prev_leader.owner_generation) {
			log_token(token, "paxos_acquire host_id %llu "
				  "generation now %llu old %llu",
				  (unsigned long long)prev_leader.owner_id,
				  (unsigned long long)host_id_leader.owner_generation,
				  (unsigned long long)prev_leader.owner_generation);
			goto run;
		}

		/* if the owner hasn't renewed its host_id lease for
		   host_id_timeout_seconds then its watchdog should have fired
		   by now

		   if we trust that the clocks are in sync among hosts, then this
		   check could be: if (time(NULL) - host_id_leader.timestamp >
		   ti->host_id_timeout_seconds), but if the clocks are out of sync,
		   this check would easily give two hosts the lease.

		   N.B. we need to be careful about ever comparing local time(NULL)
		   to a time value we read off disk from another node that may
		   have different time. */

		if (time(NULL) - start > ti->host_id_timeout_seconds) {
			log_token(token, "paxos_acquire host_id %llu expired %llu",
				  (unsigned long long)prev_leader.owner_id,
				  (unsigned long long)host_id_leader.timestamp);
			goto run;
		}
#if 0
		if (time(NULL) - host_id_leader.timestamp > ti->host_id_timeout_seconds) {
			log_token(token, "paxos_acquire host_id %llu expired %llu",
				  (unsigned long long)prev_leader.owner_id,
				  (unsigned long long)host_id_leader.timestamp);
			goto run;
		}
#endif

		/* the owner is renewing its host_id so it's alive */

		if (last_timestamp && (host_id_leader.timestamp != last_timestamp)) {
			if (flags & PAXOS_ACQUIRE_QUIET_FAIL) {
				log_token(token, "paxos_acquire host_id %llu alive",
					  (unsigned long long)prev_leader.owner_id);
			} else {
				log_errot(token, "paxos_acquire host_id %llu alive",
					  (unsigned long long)prev_leader.owner_id);
			}
			error = SANLK_LIVE_LEADER;
			goto out;
		}

		last_timestamp = host_id_leader.timestamp;

		sleep(1);
	}
 run:
	if (acquire_lver && prev_leader.lver != acquire_lver) {
		log_errot(token, "paxos_acquire acquire_lver %llu prev_leader %llu",
			  (unsigned long long)acquire_lver,
			  (unsigned long long)prev_leader.lver);
		error = SANLK_REACQUIRE_LVER;
		goto out;
	}

	/* TODO: test: while we were waiting in host_id_timeout_seconds loop
	 * above, another host has finished that loop, come through here
	 * and become the new leader (so if we were to read the leader record
	 * again right here it would be different from our prev_leader).
	 * what if the other host not only acquired the leader but also
	 * freed it when we get here? */

	/*
	 * run disk paxos to reach consensus on a new leader
	 */

	memcpy(&new_leader, &prev_leader, sizeof(struct leader_record));
	new_leader.lver += 1; /* req.lver */

	error = run_disk_paxos(ti, token, token->host_id, token->host_id,
			       new_leader.num_hosts, new_leader.lver, &dblock);
	if (error < 0) {
		log_errot(token, "paxos_acquire paxos error %d", error);
		goto out;
	}

	log_token(token, "paxos_acquire paxos result dblock mbal %llu bal %llu inp %llu lver %llu",
		  (unsigned long long)dblock.mbal,
		  (unsigned long long)dblock.bal,
		  (unsigned long long)dblock.inp,
		  (unsigned long long)dblock.lver);

	/* the inp value we commited wasn't us */

	if (dblock.inp != token->host_id) {
		log_errot(token, "paxos_acquire paxos contention our_host_id %llu "
			  "mbal %llu bal %llu inp %llu lver %llu",
			  (unsigned long long)token->host_id,
			  (unsigned long long)dblock.mbal,
			  (unsigned long long)dblock.bal,
			  (unsigned long long)dblock.inp,
			  (unsigned long long)dblock.lver);
		error = SANLK_OTHER_INP;
		goto out;
	}

	/* dblock has the disk paxos result: consensus inp and lver */

	new_leader.owner_id = token->host_id;
	new_leader.owner_generation = token->host_generation;
	new_leader.lver = dblock.lver;
	new_leader.timestamp = time(NULL);
	if (new_num_hosts)
		new_leader.num_hosts = new_num_hosts;
	new_leader.checksum = leader_checksum(&new_leader);

	error = write_new_leader(ti, token, &new_leader);
	if (error < 0)
		goto out;

	memcpy(leader_ret, &new_leader, sizeof(struct leader_record));

 out:
	log_token(token, "paxos_acquire done %d", error);

	if (disk_open)
		close_disks(&host_id_disk, 1);

	return error;
}

#if 0
int paxos_lease_leader_write(struct timeout *ti,
			     struct token *token,
			     struct leader_record *leader_new)
{
	int error;

	log_token(token, "paxos_lease_leader_write begin");

	leader_new->checksum = leader_checksum(leader_new);

	error = write_new_leader(ti, token, leader_new);

	log_token(token, "paxos_lease_leader_write done %d", error);
	return error;
}
#endif

#if 0
int paxos_lease_renew(struct timeout *ti,
		      struct token *token,
		      struct leader_record *leader_last,
		      struct leader_record *leader_ret)
{
	struct leader_record new_leader;
	int rv, d;
	int error;

	for (d = 0; d < token->r.num_disks; d++) {
		memset(&new_leader, 0, sizeof(struct leader_record));

		rv = read_leader(ti, &token->disks[d], &new_leader);
		if (rv < 0)
			continue;

		if (memcmp(&new_leader, leader_last,
			   sizeof(struct leader_record))) {
			log_errot(token, "leader changed between renewals");
			return SANLK_BAD_LEADER;
		}
	}

	new_leader.timestamp = time(NULL);
	new_leader.checksum = leader_checksum(&new_leader);

	error = write_new_leader(ti, token, &new_leader);
	if (error < 0)
		goto out;

	memcpy(leader_ret, &new_leader, sizeof(struct leader_record));
 out:
	return error;
}
#endif

int paxos_lease_release(struct timeout *ti,
			struct token *token,
		        struct leader_record *leader_last,
		        struct leader_record *leader_ret)
{
	struct leader_record leader;
	int error;

	error = paxos_lease_leader_read(ti, token, &leader, "paxos_release");
	if (error < 0) {
		log_errot(token, "release error cannot read leader");
		goto out;
	}

	if (memcmp(&leader, leader_last, sizeof(struct leader_record))) {
		log_errot(token, "release error leader changed");
		return SANLK_BAD_LEADER;
	}

	if (leader.owner_id != token->host_id) {
		log_errot(token, "release error other owner_id %llu",
			  (unsigned long long)leader.owner_id);
		return SANLK_OTHER_OWNER;
	}

	leader.timestamp = LEASE_FREE;
	leader.checksum = leader_checksum(&leader);

	error = write_new_leader(ti, token, &leader);
	if (error < 0)
		goto out;

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
 out:
	return error;
}

int paxos_lease_init(struct timeout *ti,
		     struct token *token, int num_hosts, int max_hosts)
{
	struct leader_record leader;
	struct request_record req;
	struct paxos_dblock dblock;
	int d, q;
	uint32_t offset, ss;
	uint64_t bb, be, sb, se;

	offset = token->disks[0].offset;
	ss = token->disks[0].sector_size;
	bb = offset;
	be = offset + (ss * (max_hosts + 2) - 1);
	sb = bb / ss;
	se = be / ss;

	memset(&leader, 0, sizeof(struct leader_record));
	memset(&req, 0, sizeof(struct request_record));
	memset(&dblock, 0, sizeof(struct paxos_dblock));

	leader.magic = PAXOS_DISK_MAGIC;
	leader.version = PAXOS_DISK_VERSION_MAJOR | PAXOS_DISK_VERSION_MINOR;
	leader.sector_size = token->disks[0].sector_size;
	leader.num_hosts = num_hosts;
	leader.max_hosts = max_hosts;
	leader.timestamp = LEASE_FREE;
	strncpy(leader.space_name, token->r.lockspace_name, NAME_ID_SIZE);
	strncpy(leader.resource_name, token->r.name, NAME_ID_SIZE);
	leader.checksum = leader_checksum(&leader);

	for (d = 0; d < token->r.num_disks; d++) {
		write_leader(ti, &token->disks[d], &leader);
		write_request(ti, &token->disks[d], &req);
		for (q = 0; q < max_hosts; q++)
			write_dblock(ti, &token->disks[d], q, &dblock);
	}

	/* TODO: return error if cannot initialize majority of disks */

	return 0;
}

