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

struct request_record {
	uint64_t lver;
	uint8_t force_mode;
};

struct paxos_dblock {
	uint64_t mbal;
	uint64_t bal;
	uint64_t inp;	/* host_id */
	uint64_t inp2;	/* host_id generation */
	uint64_t inp3;	/* host_id's timestamp */
	uint64_t lver;
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

static int write_dblock(struct task *task,
			struct sync_disk *disk,
			uint64_t host_id,
			struct paxos_dblock *pd)
{
	int rv;

	/* 1 leader block + 1 request block;
	   host_id N is block offset N-1 */

	rv = write_sector(disk, 2 + host_id - 1, (char *)pd, sizeof(struct paxos_dblock),
			  task, "dblock");
	return rv;
}

#if 0
static int write_request(struct task *task,
			 struct sync_disk *disk,
			 struct request_record *rr)
{
	int rv;

	rv = write_sector(disk, 1, (char *)rr, sizeof(struct request_record),
			  task, "request");
	return rv;
}
#endif

static int write_leader(struct task *task,
			struct sync_disk *disk,
			struct leader_record *lr)
{
	int rv;

	rv = write_sector(disk, 0, (char *)lr, sizeof(struct leader_record),
			  task, "leader");
	return rv;
}

static int read_dblock(struct task *task,
		       struct sync_disk *disk,
		       uint64_t host_id,
		       struct paxos_dblock *pd)
{
	int rv;

	/* 1 leader block + 1 request block; host_id N is block offset N-1 */

	rv = read_sectors(disk, 2 + host_id - 1, 1, (char *)pd, sizeof(struct paxos_dblock),
			  task, "dblock");
	return rv;
}

static int read_dblocks(struct task *task,
			struct sync_disk *disk,
			struct paxos_dblock *pds,
			int pds_count)
{
	char *data;
	int data_len, rv, i;

	data_len = pds_count * disk->sector_size;

	data = malloc(data_len);
	if (!data) {
		log_error("read_dblocks malloc %d %s", data_len, disk->path);
		rv = -ENOMEM;
		goto out;
	}

	/* 2 = 1 leader block + 1 request block */

	rv = read_sectors(disk, 2, pds_count, data, data_len,
			  task, "dblocks");
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

static int read_leader(struct task *task,
		       struct sync_disk *disk,
		       struct leader_record *lr)
{
	int rv;

	/* 0 = leader record is first sector */

	rv = read_sectors(disk, 0, 1, (char *)lr, sizeof(struct leader_record),
			  task, "leader");

	return rv;
}


#if 0
static int read_request(struct task *task,
			struct sync_disk *disk,
			struct request_record *rr)
{
	int rv;

	/* 1 = request record is second sector */

	rv = read_sectors(disk, 1, (char *)rr, sizeof(struct request_record),
			  task, "request");

	return rv;
}
#endif

/*
 * It's possible that we pick a bk_max from another host which has our own
 * inp values in it, and we can end up commiting our own inp values, copied
 * from another host's dblock:
 *
 * host2 leader free
 * host2 phase1 mbal 14002
 * host2 writes dblock[1] mbal 14002
 * host2 reads  no higher mbal
 * host2 choose own inp 2,1
 * host2 phase2 mbal 14002 bal 14002 inp 2,1
 * host2 writes dblock[1] bal 14002 inp 2,1
 *                                           host1 leader free
 *                                           host1 phase1 mbal 20001
 *                                           host1 writes dblock[0] mbal 20001
 *                                           host1 reads  no higher mbal
 *                                           host1 choose dblock[1] bal 14002 inp 2,1
 *                                           host1 phase2 mbal 20001 bal 20001 inp 2,1
 *                                           host1 writes dblock[0] bal 20001 inp 2,1
 * host2 reads  dblock[0] mbal 20001 > 14002
 *              abort2, retry
 * host2 leader free
 * host2 phase1 mbal 16002
 * host2 writes dblock[1] mbal 16002
 * host2 reads  dblock[0] mbal 20001 > 16002
 *       abort1 retry
 * host2 leader free
 * host2 phase1 mbal 18002
 * host2 writes dblock[1] mbal 18002
 * host2 reads  dblock[0] mbal 20001 > 18002
 *       abort1 retry
 * host2 leader free
 * host2 phase1 mbal 20002
 * host2 writes dblock[1] mbal 20002
 * host2 reads  no higher mbal
 * host2 choose dblock[0] bal 20001 inp 2,1
 *                                           host1 reads  dblock[1] mbal 20002 > 20001
 *                                                 abort2 retry
 * host2 phase2 mbal 20002 bal 20002 inp 2,1
 * host2 writes dblock[1] bal 20002 inp 2,1
 * host2 reads  no higher mbal
 * host2 commit inp 2,1
 * host2 success
 *                                           host1 leader owner 2,1
 *                                           host1 fail
 */

static int run_ballot(struct task *task, struct token *token, int num_hosts,
		      uint64_t next_lver, uint64_t our_mbal,
		      struct paxos_dblock *dblock_out)
{
	struct paxos_dblock bk[num_hosts];
	struct paxos_dblock bk_max;
	struct paxos_dblock dblock;
	int num_disks = token->r.num_disks;
	int num_writes, num_reads;
	int d, q, rv;
	int q_max = -1;

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

	log_token(token, "ballot %llu phase1 mbal %llu",
		  (unsigned long long)next_lver,
		  (unsigned long long)our_mbal);

	memset(&dblock, 0, sizeof(struct paxos_dblock));
	dblock.mbal = our_mbal;
	dblock.lver = next_lver;

	memset(&bk_max, 0, sizeof(struct paxos_dblock));

	num_writes = 0;

	for (d = 0; d < num_disks; d++) {
		rv = write_dblock(task, &token->disks[d], token->host_id, &dblock);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_errot(token, "ballot %llu dblock write error %d",
			  (unsigned long long)next_lver, rv);
		return SANLK_DBLOCK_WRITE;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_dblocks(task, &token->disks[d], bk, num_hosts);
		if (rv < 0)
			continue;
		num_reads++;

		for (q = 0; q < num_hosts; q++) {
			if (bk[q].lver < dblock.lver)
				continue;

			if (bk[q].lver > dblock.lver) {
				/* I don't think this should happen */
				log_errot(token, "ballot %llu larger1 lver[%d] %llu",
					  (unsigned long long)next_lver, q,
					  (unsigned long long)bk[q].lver);
				return SANLK_DBLOCK_LVER;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk[q].mbal > dblock.mbal) {
				log_errot(token, "ballot %llu abort1 mbal %llu mbal[%d] %llu",
					  (unsigned long long)next_lver,
					  (unsigned long long)our_mbal, q,
					  (unsigned long long)bk[q].mbal);
				return SANLK_DBLOCK_MBAL;
			}

			/* see choosing inp for phase 2 in comment below */

			if (!bk[q].inp)
				continue;

			if (!bk[q].bal) {
				log_errot(token, "ballot %llu zero bal inp[%d] %llu",
					  (unsigned long long)next_lver, q,
					  (unsigned long long)bk[q].inp);
				continue;
			}

			if (bk[q].bal > bk_max.bal) {
				bk_max = bk[q];
				q_max = q;
			}
		}
	}

	if (!majority_disks(token, num_reads)) {
		log_errot(token, "ballot %llu dblock read error %d",
			  (unsigned long long)next_lver, rv);
		return SANLK_DBLOCK_READ;
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

	if (bk_max.inp) {
		/* lver and mbal are already set */
		dblock.inp = bk_max.inp;
		dblock.inp2 = bk_max.inp2;
		dblock.inp3 = bk_max.inp3;
	} else {
		/* lver and mbal are already set */
		dblock.inp = token->host_id;
		dblock.inp2 = token->host_generation;
		dblock.inp3 = time(NULL);
	}
	dblock.bal = dblock.mbal;

	if (bk_max.inp) {
		/* not a problem, but interesting to see, so use log_error */
		log_errot(token, "ballot %llu choose bk_max[%d] lver %llu mbal %llu bal %llu inp %llu %llu %llu",
			  (unsigned long long)next_lver, q_max,
			  (unsigned long long)bk_max.lver,
			  (unsigned long long)bk_max.mbal,
			  (unsigned long long)bk_max.bal,
			  (unsigned long long)bk_max.inp,
			  (unsigned long long)bk_max.inp2,
			  (unsigned long long)bk_max.inp3);
	}


	/*
	 * phase 2
	 *
	 * Same description as phase 1, same sequence of writes/reads.
	 */

	log_token(token, "ballot %llu phase2 bal %llu inp %llu %llu %llu q_max %d",
		  (unsigned long long)dblock.lver,
		  (unsigned long long)dblock.bal,
		  (unsigned long long)dblock.inp,
		  (unsigned long long)dblock.inp2,
		  (unsigned long long)dblock.inp3,
		  q_max);

	num_writes = 0;

	for (d = 0; d < num_disks; d++) {
		rv = write_dblock(task, &token->disks[d], token->host_id, &dblock);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_errot(token, "ballot %llu our dblock write2 error %d",
			  (unsigned long long)next_lver, rv);
		return SANLK_DBLOCK_WRITE;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_dblocks(task, &token->disks[d], bk, num_hosts);
		if (rv < 0)
			continue;
		num_reads++;

		for (q = 0; q < num_hosts; q++) {
			if (bk[q].lver < dblock.lver)
				continue;

			if (bk[q].lver > dblock.lver) {
				/* I don't think this should happen */
				log_errot(token, "ballot %llu larger2 lver[%d] %llu",
					  (unsigned long long)next_lver, q,
					  (unsigned long long)bk[q].lver);
				return SANLK_DBLOCK_LVER;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk[q].mbal > dblock.mbal) {
				log_errot(token, "ballot %llu abort2 mbal %llu mbal[%d] %llu",
					  (unsigned long long)next_lver,
					  (unsigned long long)our_mbal, q,
					  (unsigned long long)bk[q].mbal);
				return SANLK_DBLOCK_MBAL;
			}
		}
	}

	if (!majority_disks(token, num_reads)) {
		log_errot(token, "ballot %llu dblock read2 error %d",
			  (unsigned long long)next_lver, rv);
		return SANLK_DBLOCK_READ;
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

	log_errot(token, "leader2 path %s offset %llu fd %d",
		  disk->path,
		  (unsigned long long)disk->offset,
		  disk->fd);

	log_errot(token, "leader3 m %x v %x ss %u nh %llu mh %llu oi %llu og %llu lv %llu",
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

	log_errot(token, "leader5 wi %llu wg %llu wt %llu",
		  (unsigned long long)lr->write_id,
		  (unsigned long long)lr->write_generation,
		  (unsigned long long)lr->write_timestamp);
}

static int verify_leader(struct token *token,
			 struct sync_disk *disk,
			 struct leader_record *lr,
			 const char *caller)
{
	struct leader_record leader_rr;
	uint32_t sum;
	int result, rv;

	if (lr->magic != PAXOS_DISK_MAGIC) {
		log_errot(token, "verify_leader wrong magic %x %s",
			  lr->magic, disk->path);
		result = SANLK_LEADER_MAGIC;
		goto fail;
	}

	if ((lr->version & 0xFFFF0000) != PAXOS_DISK_VERSION_MAJOR) {
		log_errot(token, "verify_leader wrong version %x %s",
			  lr->version, disk->path);
		result = SANLK_LEADER_VERSION;
		goto fail;
	}

	if (lr->sector_size != disk->sector_size) {
		log_errot(token, "verify_leader wrong sector size %d %d %s",
			  lr->sector_size, disk->sector_size, disk->path);
		result = SANLK_LEADER_SECTORSIZE;
		goto fail;
	}

	if (strncmp(lr->space_name, token->r.lockspace_name, NAME_ID_SIZE)) {
		log_errot(token, "verify_leader wrong space name %.48s %.48s %s",
			  lr->space_name, token->r.lockspace_name, disk->path);
		result = SANLK_LEADER_LOCKSPACE;
		goto fail;
	}

	if (strncmp(lr->resource_name, token->r.name, NAME_ID_SIZE)) {
		log_errot(token, "verify_leader wrong resource name %.48s %.48s %s",
			  lr->resource_name, token->r.name, disk->path);
		result = SANLK_LEADER_RESOURCE;
		goto fail;
	}

	if (lr->num_hosts < token->host_id) {
		log_errot(token, "verify_leader num_hosts too small %llu %llu %s",
			  (unsigned long long)lr->num_hosts,
			  (unsigned long long)token->host_id, disk->path);
		result = SANLK_LEADER_NUMHOSTS;
		goto fail;
	}

	sum = leader_checksum(lr);

	if (lr->checksum != sum) {
		log_errot(token, "verify_leader wrong checksum %x %x %s",
			  lr->checksum, sum, disk->path);
		result = SANLK_LEADER_CHECKSUM;
		goto fail;
	}

	return SANLK_OK;

 fail:
	log_leader_error(result, token, disk, lr, caller);

	memset(&leader_rr, 0, sizeof(leader_rr));

	rv = read_sectors(disk, 0, 1, (char *)&leader_rr,
			  sizeof(struct leader_record),
			  NULL, "paxos_verify");

	log_leader_error(rv, token, disk, &leader_rr, "paxos_verify");

	return result;
}

static int leaders_match(struct leader_record *a, struct leader_record *b)
{
	if (!memcmp(a, b, LEADER_COMPARE_LEN))
		return 1;
	return 0;
}

int paxos_lease_leader_read(struct task *task,
			    struct token *token,
			    struct leader_record *leader_ret,
			    const char *caller)
{
	struct leader_record leader;
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
		return -ENOMEM;

	leader_reps = malloc(leader_reps_len);
	if (!leader_reps) {
		free(leaders);
		return -ENOMEM;
	}

	/*
	 * find a leader block that's consistent on the majority of disks,
	 * so we can use as the basis for the new leader
	 */

	memset(&leader, 0, sizeof(struct leader_record));
	memset(leaders, 0, leaders_len);
	memset(leader_reps, 0, leader_reps_len);

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_leader(task, &token->disks[d], &leaders[d]);
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
		log_errot(token, "%s leader read error %d", caller, rv);
		error = SANLK_LEADER_READ;
		goto fail;
	}

	/* check that a majority of disks have the same leader */

	found = 0;

	for (d = 0; d < num_disks; d++) {
		if (!majority_disks(token, leader_reps[d]))
			continue;

		/* leader on d is the same on a majority of disks,
		   leader becomes the prototype for new_leader */

		memcpy(&leader, &leaders[d], sizeof(struct leader_record));
		found = 1;
		break;
	}

	if (!found) {
		log_errot(token, "%s leader inconsistent", caller);
		error = SANLK_LEADER_DIFF;
		goto fail;
	}

	log_token(token, "%s leader %llu owner %llu %llu %llu", caller,
		  (unsigned long long)leader.lver,
		  (unsigned long long)leader.owner_id,
		  (unsigned long long)leader.owner_generation,
		  (unsigned long long)leader.timestamp);
		  
	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return SANLK_OK;

 fail:
	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	free(leaders);
	free(leader_reps);
	return error;
}

/* return a random int between a and b inclusive */

static int get_rand(int a, int b)
{
	return a + (int) (((float)(b - a + 1)) * random() / (RAND_MAX+1.0));
}

static int write_new_leader(struct task *task,
			    struct token *token,
			    struct leader_record *nl,
			    const char *caller)
{
	int num_disks = token->r.num_disks;
	int num_writes = 0;
	int error = SANLK_OK;
	int rv, d;

	for (d = 0; d < num_disks; d++) {
		rv = write_leader(task, &token->disks[d], nl);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_errot(token, "%s write_new_leader error %d owner %llu %llu %llu",
			  caller, rv,
			  (unsigned long long)nl->owner_id,
			  (unsigned long long)nl->owner_generation,
			  (unsigned long long)nl->timestamp);
		error = SANLK_LEADER_WRITE;
	}

	return error;
}

/*
 * If we hang or crash after completing a ballot successfully, but before
 * commiting the leader_record, then the next host that runs a ballot (with the
 * same lver since we did not commit the new lver to the leader_record) will
 * commit the same inp values that we were about to commit.  If the inp values
 * they commit indicate we (who crashed or hung) are the new owner, then the
 * other hosts will begin monitoring the liveness of our host_id.  Once enough
 * time has passed, they assume we're dead, and go on with new versions.  The
 * "enough time" ensures that if we hung before writing the leader, that we
 * won't wake up and finally write what will then be an old invalid leader.
 */

int paxos_lease_acquire(struct task *task,
			struct token *token,
			uint32_t flags,
		        struct leader_record *leader_ret,
		        uint64_t acquire_lver,
		        int new_num_hosts)
{
	struct leader_record cur_leader;
	struct leader_record tmp_leader;
	struct leader_record new_leader;
	struct leader_record host_id_leader;
	struct sync_disk host_id_disk;
	struct paxos_dblock dblock;
	time_t start;
	uint64_t next_lver;
	uint64_t our_mbal = 0;
	uint64_t last_timestamp = 0;
	int error, rv, d, us, num_reads, disk_open = 0;

	log_token(token, "paxos_acquire begin acquire_lver %llu flags %x",
		  (unsigned long long)acquire_lver, flags);
 restart:

	error = paxos_lease_leader_read(task, token, &cur_leader, "paxos_acquire");
	if (error < 0)
		goto out;

	if (flags & PAXOS_ACQUIRE_FORCE)
		goto run;

	if (acquire_lver && cur_leader.lver != acquire_lver) {
		log_errot(token, "paxos_acquire acquire_lver %llu cur_leader %llu",
			  (unsigned long long)acquire_lver,
			  (unsigned long long)cur_leader.lver);
		error = SANLK_ACQUIRE_LVER;
		goto out;
	}

	if (cur_leader.timestamp == LEASE_FREE) {
		log_token(token, "paxos_acquire leader %llu free",
			  (unsigned long long)cur_leader.lver);
		goto run;
	}

	if (cur_leader.owner_id == token->host_id &&
	    cur_leader.owner_generation == token->host_generation) {
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

	log_token(token, "paxos_acquire check owner_id %llu gen %llu",
		  (unsigned long long)cur_leader.owner_id,
		  (unsigned long long)cur_leader.owner_generation);

	if (!disk_open) {
		memset(&host_id_disk, 0, sizeof(host_id_disk));

		rv = host_id_disk_info(cur_leader.space_name, &host_id_disk);
		if (rv < 0) {
			log_errot(token, "paxos_acquire no lockspace info %.48s",
			  	  cur_leader.space_name);
			error = SANLK_ACQUIRE_LOCKSPACE;
			goto out;
		}
		host_id_disk.fd = -1;

		disk_open = open_disks_fd(&host_id_disk, 1);
		if (disk_open != 1) {
			log_errot(token, "paxos_acquire cannot open host_id_disk");
			error = SANLK_ACQUIRE_IDDISK;
			goto out;
		}

		log_token(token, "paxos_acquire lockspace %.48s "
			  "path %s offset %llu sector_size %u fd %d",
			  cur_leader.space_name,
			  host_id_disk.path,
			  (unsigned long long)host_id_disk.offset,
			  host_id_disk.sector_size,
			  host_id_disk.fd);
	}

	start = time(NULL);

	while (1) {
		error = delta_lease_leader_read(task, &host_id_disk,
						cur_leader.space_name,
						cur_leader.owner_id,
						&host_id_leader,
						"paxos_acquire");
		if (error < 0) {
			log_errot(token, "paxos_acquire host_id %llu read %d",
				  (unsigned long long)cur_leader.owner_id,
				  error);
			goto out;
		}

		/* a host_id cannot become free in less than
		   host_id_timeout_sec after the final renewal because
		   a host_id must first be acquired before being freed,
		   and acquiring cannot take less than host_id_timeout_sec */

		if (host_id_leader.timestamp == LEASE_FREE) {
			log_token(token, "paxos_acquire host_id %llu free",
				  (unsigned long long)cur_leader.owner_id);
			goto run;
		}

		/* another host has acquired the host_id of the host that
		   owned this paxos lease; acquiring a host_id also cannot be
		   done in less than host_id_timeout_sec */

		if (host_id_leader.owner_id != cur_leader.owner_id) {
			log_token(token, "paxos_acquire host_id %llu owner %llu",
				  (unsigned long long)cur_leader.owner_id,
				  (unsigned long long)host_id_leader.owner_id);
			goto run;
		}

		/* the host_id that owns this lease may be alive, but it
		   owned the lease in a previous generation without freeing it,
		   and no longer owns it */

		if (host_id_leader.owner_generation > cur_leader.owner_generation) {
			log_token(token, "paxos_acquire host_id %llu "
				  "generation now %llu old %llu",
				  (unsigned long long)cur_leader.owner_id,
				  (unsigned long long)host_id_leader.owner_generation,
				  (unsigned long long)cur_leader.owner_generation);
			goto run;
		}

		/* if the owner hasn't renewed its host_id lease for
		   host_id_timeout_seconds then its watchdog should have fired
		   by now

		   if we trust that the clocks are in sync among hosts, then this
		   check could be: if (time(NULL) - host_id_leader.timestamp >
		   task->host_id_timeout_seconds), but if the clocks are out of sync,
		   this check would easily give two hosts the lease.

		   N.B. we need to be careful about ever comparing local time(NULL)
		   to a time value we read off disk from another node that may
		   have different time. */

		if (time(NULL) - start > task->host_id_timeout_seconds) {
			log_token(token, "paxos_acquire host_id %llu expired %llu",
				  (unsigned long long)cur_leader.owner_id,
				  (unsigned long long)host_id_leader.timestamp);
			goto run;
		}
#if 0
		if (time(NULL) - host_id_leader.timestamp > task->host_id_timeout_seconds) {
			log_token(token, "paxos_acquire host_id %llu expired %llu",
				  (unsigned long long)cur_leader.owner_id,
				  (unsigned long long)host_id_leader.timestamp);
			goto run;
		}
#endif

		/* the owner is renewing its host_id so it's alive */

		if (last_timestamp && (host_id_leader.timestamp != last_timestamp)) {
			if (flags & PAXOS_ACQUIRE_QUIET_FAIL) {
				log_token(token, "paxos_acquire host_id %llu alive",
					  (unsigned long long)cur_leader.owner_id);
			} else {
				log_errot(token, "paxos_acquire host_id %llu alive",
					  (unsigned long long)cur_leader.owner_id);
			}
			error = SANLK_ACQUIRE_IDLIVE;
			goto out;
		}

		last_timestamp = host_id_leader.timestamp;

		/* TODO: test with sleep(2) here */
		sleep(1);

		error = paxos_lease_leader_read(task, token, &tmp_leader, "paxos_acquire");
		if (error < 0)
			goto out;

		if (memcmp(&cur_leader, &tmp_leader, sizeof(struct leader_record))) {
			log_token(token, "paxos_acquire restart leader changed");
			goto restart;
		}
	}
 run:
	/*
	 * Use the disk paxos algorithm to attempt to commit a new leader.
	 *
	 * If we complete a ballot successfully, we can commit a leader record
	 * with next_lver.  If we find a higher mbal during a ballot, we increase
	 * our own mbal and try the ballot again.
	 *
	 * next_lver is derived from cur_leader with a zero or timed out owner.
	 * We need to monitor the leader record to see if another host commits
	 * a new leader_record with next_lver.
	 */

	next_lver = cur_leader.lver + 1;

	num_reads = 0;

	for (d = 0; d < token->r.num_disks; d++) {
		rv = read_dblock(task, &token->disks[d], token->host_id, &dblock);
		if (rv < 0)
			continue;
		num_reads++;

		if (dblock.mbal > our_mbal)
			our_mbal = dblock.mbal;
	}

	if (!num_reads) {
		log_errot(token, "paxos_acquire cannot read our dblock %d", rv);
		error = SANLK_DBLOCK_READ;
		goto out;
	}

	/* TODO: may not need to increase mbal if dblock.inp and inp2 match
	   current host_id and generation? */

	if (!our_mbal)
		our_mbal = token->host_id;
	else
		our_mbal += cur_leader.max_hosts;

 retry_ballot:

	error = paxos_lease_leader_read(task, token, &tmp_leader, "paxos_acquire");
	if (error < 0)
		goto out;

	if (tmp_leader.lver == next_lver) {
		/*
		 * another host has commited a leader_record for next_lver,
		 * check which inp (owner_id) they commited (possibly us).
		 */

		if (tmp_leader.owner_id == token->host_id &&
		    tmp_leader.owner_generation == token->host_generation) {
			/* not a problem, but interesting to see, so use log_error */

			log_errot(token, "paxos_acquire %llu owner our inp "
				  "%llu %llu %llu commited by %llu",
				  (unsigned long long)next_lver,
				  (unsigned long long)tmp_leader.owner_id,
				  (unsigned long long)tmp_leader.owner_generation,
				  (unsigned long long)tmp_leader.timestamp,
				  (unsigned long long)tmp_leader.write_id);

			memcpy(leader_ret, &tmp_leader, sizeof(struct leader_record));
			error = SANLK_OK;
		} else {
			/* not a problem, but interesting to see, so use log_error */

			log_errot(token, "paxos_acquire %llu owner is %llu",
				  (unsigned long long)next_lver,
				  (unsigned long long)tmp_leader.owner_id);

			error = SANLK_ACQUIRE_OWNED;
		}
		goto out;
	}

	error = run_ballot(task, token, cur_leader.num_hosts, next_lver, our_mbal,
			   &dblock);

	if (error == SANLK_DBLOCK_MBAL) {
		us = get_rand(0, 1000000);
		/* not a problem, but interesting to see, so use log_error */
		log_errot(token, "paxos_acquire %llu retry delay %d us",
			  (unsigned long long)next_lver, us);
		usleep(us);
		our_mbal += cur_leader.max_hosts;
		goto retry_ballot;
	}

	if (error < 0) {
		log_errot(token, "paxos_acquire %llu ballot error %d",
			  (unsigned long long)next_lver, error);
		goto out;
	}

	/* ballot success, commit next_lver with dblock values */

	memcpy(&new_leader, &cur_leader, sizeof(struct leader_record));
	new_leader.lver = dblock.lver;
	new_leader.owner_id = dblock.inp;
	new_leader.owner_generation = dblock.inp2;
	new_leader.timestamp = dblock.inp3;

	new_leader.write_id = token->host_id;
	new_leader.write_generation = token->host_generation;
	new_leader.write_timestamp = time(NULL);

	if (new_num_hosts)
		new_leader.num_hosts = new_num_hosts;
	new_leader.checksum = leader_checksum(&new_leader);

	error = write_new_leader(task, token, &new_leader, "paxos_acquire");
	if (error < 0)
		goto out;

	if (new_leader.owner_id != token->host_id) {
		/* not a problem, but interesting to see, so use log_error */

		log_errot(token, "ballot %llu commit other owner %llu %llu %llu",
			  (unsigned long long)new_leader.lver,
			  (unsigned long long)new_leader.owner_id,
			  (unsigned long long)new_leader.owner_generation,
			  (unsigned long long)new_leader.timestamp);

		error = SANLK_ACQUIRE_OTHER;
		goto out;
	}

	log_token(token, "ballot %llu commit self owner %llu %llu %llu",
		  (unsigned long long)next_lver,
		  (unsigned long long)new_leader.owner_id,
		  (unsigned long long)new_leader.owner_generation,
		  (unsigned long long)new_leader.timestamp);

	memcpy(leader_ret, &new_leader, sizeof(struct leader_record));
	error = SANLK_OK;

 out:
	if (disk_open)
		close_disks(&host_id_disk, 1);

	return error;
}

#if 0
int paxos_lease_renew(struct task *task,
		      struct token *token,
		      struct leader_record *leader_last,
		      struct leader_record *leader_ret)
{
	struct leader_record new_leader;
	int rv, d;
	int error;

	for (d = 0; d < token->r.num_disks; d++) {
		memset(&new_leader, 0, sizeof(struct leader_record));

		rv = read_leader(task, &token->disks[d], &new_leader);
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

	error = write_new_leader(task, token, &new_leader);
	if (error < 0)
		goto out;

	memcpy(leader_ret, &new_leader, sizeof(struct leader_record));
 out:
	return error;
}
#endif

int paxos_lease_release(struct task *task,
			struct token *token,
		        struct leader_record *leader_last,
		        struct leader_record *leader_ret)
{
	struct leader_record leader;
	int error;

	error = paxos_lease_leader_read(task, token, &leader, "paxos_release");
	if (error < 0) {
		log_errot(token, "release error cannot read leader");
		goto out;
	}

	if (leader.lver != leader_last->lver) {
		log_errot(token, "paxos_release %llu other lver %llu",
			  (unsigned long long)leader_last->lver,
			  (unsigned long long)leader.lver);
		return SANLK_RELEASE_LVER;
	}

	if (leader.owner_id != token->host_id ||
	    leader.owner_generation != token->host_generation) {
		log_errot(token, "paxos_release %llu other owner %llu %llu %llu",
			  (unsigned long long)leader_last->lver,
			  (unsigned long long)leader.owner_id,
			  (unsigned long long)leader.owner_generation,
			  (unsigned long long)leader.timestamp);
		return SANLK_RELEASE_OWNER;
	}

	if (memcmp(&leader, leader_last, sizeof(struct leader_record))) {
		/*
		 * This will happen when two hosts finish the same ballot
		 * successfully, the second commiting the same inp values
		 * that the first did, as it should.  But the second will
		 * write it's own write_id/gen/timestap, which will differ
		 * from what the first host wrote.  So when the first host
		 * rereads here in the release, it will find different
		 * write_id/gen/timestamp from what it wrote.  This is
		 * perfectly fine (use log_error since it's interesting
		 * to see when this happens.)
		 */
		log_errot(token, "paxos_release %llu leader different "
			  "write %llu %llu %llu vs %llu %llu %llu",
			  (unsigned long long)leader_last->lver,
			  (unsigned long long)leader_last->write_id,
			  (unsigned long long)leader_last->write_generation,
			  (unsigned long long)leader_last->write_timestamp,
			  (unsigned long long)leader.write_id,
			  (unsigned long long)leader.write_generation,
			  (unsigned long long)leader.write_timestamp);
		/*
		log_leader_error(0, token, &token->disks[0], leader_last, "paxos_release");
		log_leader_error(0, token, &token->disks[0], &leader, "paxos_release");
		*/
	}

	leader.timestamp = LEASE_FREE;
	leader.write_id = token->host_id;
	leader.write_generation = token->host_generation;
	leader.write_timestamp = time(NULL);
	leader.checksum = leader_checksum(&leader);

	error = write_new_leader(task, token, &leader, "paxos_release");
	if (error < 0)
		goto out;

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
 out:
	return error;
}

int paxos_lease_init(struct task *task,
		     struct token *token,
		     int num_hosts, int max_hosts)
{
	char *iobuf, **p_iobuf;
	struct leader_record *leader;
	int iobuf_len;
	int rv, d;

	iobuf_len = token->disks[0].sector_size * (2 + max_hosts);

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv)
		return rv;

	memset(iobuf, 0, iobuf_len);

	leader = (struct leader_record *)iobuf;
	leader->magic = PAXOS_DISK_MAGIC;
	leader->version = PAXOS_DISK_VERSION_MAJOR | PAXOS_DISK_VERSION_MINOR;
	leader->sector_size = token->disks[0].sector_size;
	leader->num_hosts = num_hosts;
	leader->max_hosts = max_hosts;
	leader->timestamp = LEASE_FREE;
	strncpy(leader->space_name, token->r.lockspace_name, NAME_ID_SIZE);
	strncpy(leader->resource_name, token->r.name, NAME_ID_SIZE);
	leader->checksum = leader_checksum(leader);

	for (d = 0; d < token->r.num_disks; d++) {
		rv = write_iobuf(token->disks[d].fd, token->disks[d].offset,
				 iobuf, iobuf_len, task);
		if (rv < 0)
			return rv;
	}

	return 0;
}

