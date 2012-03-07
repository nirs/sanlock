/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
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
#include "direct.h"
#include "log.h"
#include "lockspace.h"
#include "delta_lease.h"
#include "paxos_lease.h"
#include "resource.h"

uint32_t crc32c(uint32_t crc, uint8_t *data, size_t length);
int get_rand(int a, int b);

#define DBLOCK_CHECKSUM_LEN	 48  /* ends before checksum field */

struct paxos_dblock {
	uint64_t mbal;
	uint64_t bal;
	uint64_t inp;	/* host_id */
	uint64_t inp2;	/* host_id generation */
	uint64_t inp3;	/* host_id's timestamp */
	uint64_t lver;
	uint32_t checksum;
};

static uint32_t roundup_power_of_two(uint32_t val)
{
	val--;
	val |= val >> 1;
	val |= val >> 2;
	val |= val >> 4;
	val |= val >> 8;
	val |= val >> 16;
	val++;
	return val;
}

int paxos_lease_request_read(struct task *task, struct token *token,
			     struct request_record *rr)
{
	int rv;

	/* 1 = request record is second sector */

	rv = read_sectors(&token->disks[0], 1, 1, (char *)rr,
			  sizeof(struct request_record),
			  task, "request");
	if (rv < 0)
		return rv;
	return SANLK_OK;
}

int paxos_lease_request_write(struct task *task, struct token *token,
			      struct request_record *rr)
{
	int rv;

	rv = write_sector(&token->disks[0], 1, (char *)rr,
			  sizeof(struct request_record),
			  task, "request");
	if (rv < 0)
		return rv;
	return SANLK_OK;
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

static int write_leader(struct task *task,
			struct sync_disk *disk,
			struct leader_record *lr)
{
	int rv;

	rv = write_sector(disk, 0, (char *)lr, sizeof(struct leader_record),
			  task, "leader");
	return rv;
}

#if 0
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
#endif

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

static uint32_t dblock_checksum(struct paxos_dblock *pd)
{
	return crc32c((uint32_t)~1, (uint8_t *)pd, DBLOCK_CHECKSUM_LEN);
}

static int verify_dblock(struct token *token, struct paxos_dblock *pd)
{
	uint32_t sum;

	if (!pd->checksum && !pd->mbal && !pd->bal && !pd->inp && !pd->lver)
		return SANLK_OK;

	sum = dblock_checksum(pd);

	if (pd->checksum != sum) {
		log_errot(token, "verify_dblock wrong checksum %x %x",
			  pd->checksum, sum);
		return SANLK_DBLOCK_CHECKSUM;
	}

	return SANLK_OK;
}

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
	struct paxos_dblock dblock;
	struct paxos_dblock bk_max;
	struct paxos_dblock *bk;
	struct sync_disk *disk;
	char *iobuf[SANLK_MAX_DISKS];
	char **p_iobuf[SANLK_MAX_DISKS];
	int num_disks = token->r.num_disks;
	int num_writes, num_reads;
	int sector_size = token->disks[0].sector_size;
	int sector_count;
	int iobuf_len;
	int d, q, rv;
	int q_max = -1;
	int error;

	sector_count = roundup_power_of_two(num_hosts + 2);

	iobuf_len = sector_count * sector_size;

	if (!iobuf_len)
		return -EINVAL;

	for (d = 0; d < num_disks; d++) {
		p_iobuf[d] = &iobuf[d];

		rv = posix_memalign((void *)p_iobuf[d], getpagesize(), iobuf_len);
		if (rv)
			return rv;
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

	log_token(token, "ballot %llu phase1 mbal %llu",
		  (unsigned long long)next_lver,
		  (unsigned long long)our_mbal);

	memset(&dblock, 0, sizeof(struct paxos_dblock));
	dblock.mbal = our_mbal;
	dblock.lver = next_lver;
	dblock.checksum = dblock_checksum(&dblock);

	memset(&bk_max, 0, sizeof(struct paxos_dblock));

	num_writes = 0;

	for (d = 0; d < num_disks; d++) {
		rv = write_dblock(task, &token->disks[d], token->host_id, &dblock);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(num_disks, num_writes)) {
		log_errot(token, "ballot %llu dblock write error %d",
			  (unsigned long long)next_lver, rv);
		error = SANLK_DBLOCK_WRITE;
		goto out;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		disk = &token->disks[d];

		if (!iobuf[d])
			continue;
		memset(iobuf[d], 0, iobuf_len);

		rv = read_iobuf(disk->fd, disk->offset, iobuf[d], iobuf_len, task);
		if (rv == SANLK_AIO_TIMEOUT)
			iobuf[d] = NULL;
		if (rv < 0)
			continue;
		num_reads++;


		for (q = 0; q < num_hosts; q++) {
			bk = (struct paxos_dblock *)(iobuf[d] + ((2 + q)*sector_size));

			rv = verify_dblock(token, bk);
			if (rv < 0)
				continue;

			check_mode_block(token, q, (char *)bk);

			if (bk->lver < dblock.lver)
				continue;

			if (bk->lver > dblock.lver) {
				/* I don't think this should happen */
				log_errot(token, "ballot %llu larger1 lver[%d] %llu",
					  (unsigned long long)next_lver, q,
					  (unsigned long long)bk->lver);
				error = SANLK_DBLOCK_LVER;
				goto out;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk->mbal > dblock.mbal) {
				log_errot(token, "ballot %llu abort1 mbal %llu mbal[%d] %llu",
					  (unsigned long long)next_lver,
					  (unsigned long long)our_mbal, q,
					  (unsigned long long)bk->mbal);
				error = SANLK_DBLOCK_MBAL;
				goto out;
			}

			/* see choosing inp for phase 2 in comment below */

			if (!bk->inp)
				continue;

			if (!bk->bal) {
				log_errot(token, "ballot %llu zero bal inp[%d] %llu",
					  (unsigned long long)next_lver, q,
					  (unsigned long long)bk->inp);
				continue;
			}

			if (bk->bal > bk_max.bal) {
				bk_max = *bk;
				q_max = q;
			}
		}
	}

	if (!majority_disks(num_disks, num_reads)) {
		log_errot(token, "ballot %llu dblock read error %d",
			  (unsigned long long)next_lver, rv);
		error = SANLK_DBLOCK_READ;
		goto out;
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
		dblock.inp3 = monotime();
	}
	dblock.bal = dblock.mbal;
	dblock.checksum = dblock_checksum(&dblock);

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

	if (!majority_disks(num_disks, num_writes)) {
		log_errot(token, "ballot %llu our dblock write2 error %d",
			  (unsigned long long)next_lver, rv);
		error = SANLK_DBLOCK_WRITE;
		goto out;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		disk = &token->disks[d];

		if (!iobuf[d])
			continue;
		memset(iobuf[d], 0, iobuf_len);

		rv = read_iobuf(disk->fd, disk->offset, iobuf[d], iobuf_len, task);
		if (rv == SANLK_AIO_TIMEOUT)
			iobuf[d] = NULL;
		if (rv < 0)
			continue;
		num_reads++;

		for (q = 0; q < num_hosts; q++) {
			bk = (struct paxos_dblock *)(iobuf[d] + ((2 + q)*sector_size));

			rv = verify_dblock(token, bk);
			if (rv < 0)
				continue;

			if (bk->lver < dblock.lver)
				continue;

			if (bk->lver > dblock.lver) {
				/*
				 * This happens when we choose another host's bk, that host
				 * acquires the lease itself, releases it, and reacquires it
				 * with a new lver, all before we get here, at which point
				 * we see the larger lver.  I believe case this would always
				 * also be caught the the bk->mbal > dblock.mbal condition
				 * below.
				 */
				log_errot(token, "ballot %llu larger2 lver[%d] %llu dblock %llu",
					  (unsigned long long)next_lver, q,
					  (unsigned long long)bk->lver,
					  (unsigned long long)dblock.lver);
				log_errot(token, "ballot %llu larger2 mbal[%d] %llu dblock %llu",
					  (unsigned long long)next_lver, q,
					  (unsigned long long)bk->mbal,
					  (unsigned long long)dblock.mbal);
				log_errot(token, "ballot %llu larger2 inp[%d] %llu %llu %llu dblock %llu %llu %llu",
					  (unsigned long long)next_lver, q,
					  (unsigned long long)bk->inp,
					  (unsigned long long)bk->inp2,
					  (unsigned long long)bk->inp3,
					  (unsigned long long)dblock.inp,
					  (unsigned long long)dblock.inp2,
					  (unsigned long long)dblock.inp3);
				error = SANLK_DBLOCK_LVER;
				goto out;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk->mbal > dblock.mbal) {
				log_errot(token, "ballot %llu abort2 mbal %llu mbal[%d] %llu",
					  (unsigned long long)next_lver,
					  (unsigned long long)our_mbal, q,
					  (unsigned long long)bk->mbal);
				error = SANLK_DBLOCK_MBAL;
				goto out;
			}
		}
	}

	if (!majority_disks(num_disks, num_reads)) {
		log_errot(token, "ballot %llu dblock read2 error %d",
			  (unsigned long long)next_lver, rv);
		error = SANLK_DBLOCK_READ;
		goto out;
	}

	/* "When it completes phase 2, p has committed dblock[p].inp." */

	memcpy(dblock_out, &dblock, sizeof(struct paxos_dblock));
	error = SANLK_OK;
 out:
	for (d = 0; d < num_disks; d++) {
		/* don't free iobufs that have timed out */
		if (!iobuf[d])
			continue;
		free(iobuf[d]);
	}
	return error;
}

uint32_t leader_checksum(struct leader_record *lr)
{
	return crc32c((uint32_t)~1, (uint8_t *)lr, LEADER_CHECKSUM_LEN);
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

static int _leader_read_one(struct task *task,
			    struct token *token,
			    struct leader_record *leader_ret,
			    const char *caller)
{
	struct leader_record leader;
	int rv;

	memset(&leader, 0, sizeof(struct leader_record));

	rv = read_leader(task, &token->disks[0], &leader);
	if (rv < 0)
		return rv;

	rv = verify_leader(token, &token->disks[0], &leader, caller);

	/* copy what we read even if verify finds a problem */

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return rv;
}

/* TODO: completely untested */

static int _leader_read_num(struct task *task,
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
	int rv = 0, d, i, found;
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

	if (!majority_disks(num_disks, num_reads)) {
		log_errot(token, "%s leader read error %d", caller, rv);
		error = SANLK_LEADER_READ;
		goto out;
	}

	/* check that a majority of disks have the same leader */

	found = 0;

	for (d = 0; d < num_disks; d++) {
		if (!majority_disks(num_disks, leader_reps[d]))
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
		goto out;
	}

	error = SANLK_OK;
 out:
	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	free(leaders);
	free(leader_reps);
	return error;
}

int paxos_lease_leader_read(struct task *task,
			    struct token *token,
			    struct leader_record *leader_ret,
			    const char *caller)
{
	int rv;

	/* _leader_read_num works fine for the single disk case, but
	   we can cut out a bunch of stuff when we know there's one disk */

	if (token->r.num_disks > 1)
		rv = _leader_read_num(task, token, leader_ret, caller);
	else
		rv = _leader_read_one(task, token, leader_ret, caller);

	if (rv == SANLK_OK)
		log_token(token, "%s leader %llu owner %llu %llu %llu", caller,
			  (unsigned long long)leader_ret->lver,
			  (unsigned long long)leader_ret->owner_id,
			  (unsigned long long)leader_ret->owner_generation,
			  (unsigned long long)leader_ret->timestamp);

	return rv;
}

static int _lease_read_one(struct task *task,
			   struct token *token,
			   struct sync_disk *disk,
			   struct leader_record *leader_ret,
			   struct paxos_dblock *our_dblock,
			   uint64_t *max_mbal,
			   int *max_q,
			   const char *caller)
{
	char *iobuf, **p_iobuf;
	uint32_t host_id = token->host_id;
	uint32_t sector_size = disk->sector_size;
	struct paxos_dblock *bk;
	uint64_t tmp_mbal = 0;
	int q, tmp_q = -1, rv, iobuf_len;

	iobuf_len = direct_align(disk);
	if (iobuf_len < 0)
		return iobuf_len;

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv)
		return rv;

	memset(iobuf, 0, iobuf_len);

	rv = read_iobuf(disk->fd, disk->offset, iobuf, iobuf_len, task);
	if (rv < 0)
		goto out;

	memcpy(leader_ret, iobuf, sizeof(struct leader_record));

	memcpy(our_dblock, iobuf + ((host_id + 1) * sector_size), sizeof(struct paxos_dblock));

	rv = verify_leader(token, disk, leader_ret, caller);
	if (rv < 0)
		goto out;

	for (q = 0; q < leader_ret->num_hosts; q++) {
		bk = (struct paxos_dblock *)(iobuf + ((2 + q) * sector_size));

		rv = verify_dblock(token, bk);
		if (rv < 0)
			goto out;

		if (!tmp_mbal || bk->mbal > tmp_mbal) {
			tmp_mbal = bk->mbal;
			tmp_q = q;
		}
	}
	*max_mbal = tmp_mbal;
	*max_q = tmp_q;

 out:
	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);
	return rv;
}

/* TODO: completely untested */

static int _lease_read_num(struct task *task,
			   struct token *token,
			   struct leader_record *leader_ret,
			   struct paxos_dblock *our_dblock,
			   uint64_t *max_mbal,
			   int *max_q,
			   const char *caller)
{
	struct paxos_dblock dblock_one;
	struct leader_record leader_one;
	struct leader_record *leaders;
	uint64_t tmp_mbal = 0;
	uint64_t mbal_one;
	int *leader_reps;
	int num_disks = token->r.num_disks;
	int leaders_len, leader_reps_len;
	int i, d, rv, found, num_reads, q_one, tmp_q = -1;

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

	memset(leaders, 0, leaders_len);
	memset(leader_reps, 0, leader_reps_len);

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = _lease_read_one(task, token, &token->disks[d], &leader_one,
				     &dblock_one, &mbal_one, &q_one, caller);
		if (rv < 0)
			continue;

		num_reads++;

		if (!tmp_mbal || mbal_one > tmp_mbal) {
			tmp_mbal = mbal_one;
			tmp_q = q_one;
			memcpy(our_dblock, &dblock_one, sizeof(struct paxos_dblock));
		}

		memcpy(&leaders[d], &leader_one, sizeof(struct leader_record));

		leader_reps[d] = 1;

		/* count how many times the same leader block repeats */

		for (i = 0; i < d; i++) {
			if (leaders_match(&leaders[d], &leaders[i])) {
				leader_reps[i]++;
				break;
			}
		}
	}
	*max_mbal = tmp_mbal;
	*max_q = tmp_q;

	if (!num_reads) {
		log_errot(token, "%s lease_read_num cannot read disks %d", caller, rv);
		rv = SANLK_DBLOCK_READ;
		goto out;
	}

	found = 0;

	for (d = 0; d < num_disks; d++) {
		if (!majority_disks(num_disks, leader_reps[d]))
			continue;

		/* leader on d is the same on a majority of disks,
		   leader becomes the prototype for new_leader */

		memcpy(leader_ret, &leaders[d], sizeof(struct leader_record));
		found = 1;
		break;
	}

	if (!found) {
		log_errot(token, "%s lease_read_num leader inconsistent", caller);
		rv = SANLK_LEADER_DIFF;
	}
 out:
	free(leaders);
	free(leader_reps);
	return rv;
}

/*
 * read all the initial values needed to start disk paxos:
 * - the leader record
 * - our own dblock
 * - the max mbal from all dblocks
 *
 * Read the entire lease area in one i/o and copy all those
 * values from it.
 */

static int paxos_lease_read(struct task *task, struct token *token,
			    struct leader_record *leader_ret,
			    uint64_t *max_mbal, const char *caller)
{
	struct paxos_dblock our_dblock;
	int rv, q = -1;

	if (token->r.num_disks > 1)
		rv = _lease_read_num(task, token,
				     leader_ret, &our_dblock, max_mbal, &q, caller);
	else
		rv = _lease_read_one(task, token, &token->disks[0],
				     leader_ret, &our_dblock, max_mbal, &q, caller);

	if (rv == SANLK_OK)
		log_token(token, "%s leader %llu owner %llu %llu %llu max mbal[%d] %llu "
			  "our_dblock %llu %llu %llu %llu %llu %llu",
			  caller,
			  (unsigned long long)leader_ret->lver,
			  (unsigned long long)leader_ret->owner_id,
			  (unsigned long long)leader_ret->owner_generation,
			  (unsigned long long)leader_ret->timestamp,
			  q,
			  (unsigned long long)*max_mbal,
			  (unsigned long long)our_dblock.mbal,
			  (unsigned long long)our_dblock.bal,
			  (unsigned long long)our_dblock.inp,
			  (unsigned long long)our_dblock.inp2,
			  (unsigned long long)our_dblock.inp3,
			  (unsigned long long)our_dblock.lver);

	return rv;
}

static int write_new_leader(struct task *task,
			    struct token *token,
			    struct leader_record *nl,
			    const char *caller)
{
	int num_disks = token->r.num_disks;
	int num_writes = 0;
	int error = SANLK_OK;
	int rv = 0, d;

	for (d = 0; d < num_disks; d++) {
		rv = write_leader(task, &token->disks[d], nl);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(num_disks, num_writes)) {
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

/*
 * i/o required to acquire a free lease
 * (1 disk in token, 512 byte sectors, default num_hosts of 2000)
 *
 * paxos_lease_acquire()
 * 	paxos_lease_read()	1 read   1 MB (entire lease area)
 * 	run_ballot()
 * 		write_dblock()	1 write  512 bytes (1 dblock sector)
 * 		read_iobuf()	1 read   1 MB (round up num_hosts + 2 sectors)
 * 		write_dblock()  1 write  512 bytes (1 dblock sector)
 * 		read_iobuf()	1 read   1 MB (round up num_hosts + 2 sectors)
 * 	write_new_leader()	1 write  512 bytes (1 leader sector)
 *
 * 				6 i/os = 3 1MB reads, 3 512 byte writes
 */

int paxos_lease_acquire(struct task *task,
			struct token *token,
			uint32_t flags,
		        struct leader_record *leader_ret,
		        uint64_t acquire_lver,
		        int new_num_hosts)
{
	struct sync_disk host_id_disk;
	struct leader_record host_id_leader;
	struct leader_record cur_leader;
	struct leader_record tmp_leader;
	struct leader_record new_leader;
	struct paxos_dblock dblock;
	struct host_status hs;
	uint64_t wait_start, now;
	uint64_t last_timestamp;
	uint64_t next_lver;
	uint64_t max_mbal;
	uint64_t num_mbal;
	uint64_t our_mbal;
	int copy_cur_leader = 0;
	int disk_open = 0;
	int error, rv, us;

	log_token(token, "paxos_acquire begin %x %llu %d",
		  flags, (unsigned long long)acquire_lver, new_num_hosts);
 restart:

	error = paxos_lease_read(task, token, &cur_leader, &max_mbal, "paxos_acquire");
	if (error < 0)
		goto out;

	if (flags & PAXOS_ACQUIRE_FORCE) {
		copy_cur_leader = 1;
		goto run;
	}

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
		copy_cur_leader = 1;
		goto run;
	}

	if (cur_leader.owner_id == token->host_id &&
	    cur_leader.owner_generation == token->host_generation) {
		log_token(token, "paxos_acquire already owner id %llu gen %llu",
			  (unsigned long long)token->host_id,
			  (unsigned long long)token->host_generation);
		copy_cur_leader = 1;
		goto run;
	}

	/*
	 * Check if current owner is alive based on its host_id renewals.
	 * If the current owner has been dead long enough we can assume that
	 * its watchdog has triggered and we can go for the paxos lease.
	 */

	if (!disk_open) {
		memset(&host_id_disk, 0, sizeof(host_id_disk));

		rv = lockspace_disk(cur_leader.space_name, &host_id_disk);
		if (rv < 0) {
			log_errot(token, "paxos_acquire no lockspace info %.48s",
			  	  cur_leader.space_name);
			error = SANLK_ACQUIRE_LOCKSPACE;
			goto out;
		}
		host_id_disk.fd = -1;

		rv = open_disks_fd(&host_id_disk, 1);
		if (rv < 0) {
			log_errot(token, "paxos_acquire open host_id_disk error %d", rv);
			error = SANLK_ACQUIRE_IDDISK;
			goto out;
		}
		disk_open = 1;
	}

	rv = host_info(cur_leader.space_name, cur_leader.owner_id, &hs);
	if (!rv && hs.last_check && hs.last_live &&
	    hs.owner_id == cur_leader.owner_id &&
	    hs.owner_generation == cur_leader.owner_generation) {
		wait_start = hs.last_live;
		last_timestamp = hs.timestamp;
	} else {
		wait_start = monotime();
		last_timestamp = 0;
	}

	log_token(token, "paxos_acquire owner %llu %llu %llu "
		  "host_status %llu %llu %llu wait_start %llu",
		  (unsigned long long)cur_leader.owner_id,
		  (unsigned long long)cur_leader.owner_generation,
		  (unsigned long long)cur_leader.timestamp,
		  (unsigned long long)hs.owner_id,
		  (unsigned long long)hs.owner_generation,
		  (unsigned long long)hs.timestamp,
		  (unsigned long long)wait_start);

	while (1) {
		error = delta_lease_leader_read(task, &host_id_disk,
						cur_leader.space_name,
						cur_leader.owner_id,
						&host_id_leader,
						"paxos_acquire");
		if (error < 0) {
			log_errot(token, "paxos_acquire owner %llu %llu %llu "
				  "delta read %d fd %d path %s off %llu ss %u",
				  (unsigned long long)cur_leader.owner_id,
				  (unsigned long long)cur_leader.owner_generation,
				  (unsigned long long)cur_leader.timestamp,
				  error, host_id_disk.fd, host_id_disk.path,
				  (unsigned long long)host_id_disk.offset,
				  host_id_disk.sector_size);
			goto out;
		}

		/* a host_id cannot become free in less than
		   host_dead_seconds after the final renewal because
		   a host_id must first be acquired before being freed,
		   and acquiring cannot take less than host_dead_seconds */

		if (host_id_leader.timestamp == LEASE_FREE) {
			log_token(token, "paxos_acquire owner %llu delta free",
				  (unsigned long long)cur_leader.owner_id);
			goto run;
		}

		/* another host has acquired the host_id of the host that
		   owned this paxos lease; acquiring a host_id also cannot be
		   done in less than host_dead_seconds, or

		   the host_id that owns this lease may be alive, but it
		   owned the lease in a previous generation without freeing it,
		   and no longer owns it */

		if (host_id_leader.owner_id != cur_leader.owner_id ||
		    host_id_leader.owner_generation > cur_leader.owner_generation) {
			log_token(token, "paxos_acquire owner %llu %llu %llu "
				  "delta %llu %llu %llu mismatch",
				  (unsigned long long)cur_leader.owner_id,
				  (unsigned long long)cur_leader.owner_generation,
				  (unsigned long long)cur_leader.timestamp,
				  (unsigned long long)host_id_leader.owner_id,
				  (unsigned long long)host_id_leader.owner_generation,
				  (unsigned long long)host_id_leader.timestamp);
			goto run;
		}

		if (!last_timestamp) {
			last_timestamp = host_id_leader.timestamp;
			goto skip_live_check;
		}

		/* the owner is renewing its host_id so it's alive */

		if (host_id_leader.timestamp != last_timestamp) {
			if (flags & PAXOS_ACQUIRE_QUIET_FAIL) {
				log_token(token, "paxos_acquire owner %llu "
					  "delta %llu %llu %llu alive",
					  (unsigned long long)cur_leader.owner_id,
					  (unsigned long long)host_id_leader.owner_id,
					  (unsigned long long)host_id_leader.owner_generation,
					  (unsigned long long)host_id_leader.timestamp);
			} else {
				log_errot(token, "paxos_acquire owner %llu "
					  "delta %llu %llu %llu alive",
					  (unsigned long long)cur_leader.owner_id,
					  (unsigned long long)host_id_leader.owner_id,
					  (unsigned long long)host_id_leader.owner_generation,
					  (unsigned long long)host_id_leader.timestamp);
			}
			memcpy(leader_ret, &cur_leader, sizeof(struct leader_record));
			error = SANLK_ACQUIRE_IDLIVE;
			goto out;
		}


		/* if the owner hasn't renewed its host_id lease for
		   host_dead_seconds then its watchdog should have fired
		   by now */

		now = monotime();

		if (now - wait_start > task->host_dead_seconds) {
			log_token(token, "paxos_acquire owner %llu %llu %llu "
				  "delta %llu %llu %llu dead %llu-%llu>%d",
				  (unsigned long long)cur_leader.owner_id,
				  (unsigned long long)cur_leader.owner_generation,
				  (unsigned long long)cur_leader.timestamp,
				  (unsigned long long)host_id_leader.owner_id,
				  (unsigned long long)host_id_leader.owner_generation,
				  (unsigned long long)host_id_leader.timestamp,
				  (unsigned long long)now,
				  (unsigned long long)wait_start,
				  task->host_dead_seconds);
			goto run;
		}

 skip_live_check:
		/* TODO: test with sleep(2) here */
		sleep(1);

		if (external_shutdown) {
			error = -1;
			goto out;
		}

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
	 *
	 * TODO: may not need to increase mbal if dblock.inp and inp2 match
	 * current host_id and generation?
	 */

	/* This next_lver assignment is based on the original cur_leader, not a
	   re-reading of the leader here, i.e. we cannot just re-read the leader
	   here, and make next_lver one more than that.  This is because another
	   node may have made us the owner of next_lver as it is now. */

	next_lver = cur_leader.lver + 1;

	if (!max_mbal) {
		our_mbal = token->host_id;
	} else {
		num_mbal = max_mbal - (max_mbal % cur_leader.max_hosts);
		our_mbal = num_mbal + cur_leader.max_hosts + token->host_id;
	}

 retry_ballot:

	if (copy_cur_leader) {
		/* reusing the initial read removes an iop in the common case */
		copy_cur_leader = 0;
		memcpy(&tmp_leader, &cur_leader, sizeof(struct leader_record));
	} else {
		error = paxos_lease_leader_read(task, token, &tmp_leader, "paxos_acquire");
		if (error < 0)
			goto out;
	}

	if (tmp_leader.lver == next_lver) {
		/*
		 * another host has commited a leader_record for next_lver,
		 * check which inp (owner_id) they commited (possibly us).
		 */

		if (tmp_leader.owner_id == token->host_id &&
		    tmp_leader.owner_generation == token->host_generation) {
			/* not a problem, but interesting to see, so use log_error */

			log_errot(token, "paxos_acquire %llu owner is our inp "
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

			log_errot(token, "paxos_acquire %llu owner is %llu %llu %llu",
				  (unsigned long long)next_lver,
				  (unsigned long long)tmp_leader.owner_id,
				  (unsigned long long)tmp_leader.owner_generation,
				  (unsigned long long)tmp_leader.timestamp);

			memcpy(leader_ret, &tmp_leader, sizeof(struct leader_record));
			error = SANLK_ACQUIRE_OWNED;
		}
		goto out;
	}

	if (tmp_leader.lver > next_lver) {
		/*
		 * A case where this was observed: for next_lver 65 we abort1, and delay.
		 * While sleeping, the lease v65 (which was acquired during our abort1) is
		 * released and then reacquired as v66.  When we goto retry_ballot, our
		 * next_lver is 65, but the current lver on disk is 66, causing us to
		 * we fail in the larger1 check.)
		 */
		log_token(token, "paxos_acquire stale next_lver %llu now %llu owner %llu %llu %llu",
			  (unsigned long long)next_lver,
			  (unsigned long long)tmp_leader.lver,
			  (unsigned long long)tmp_leader.owner_id,
			  (unsigned long long)tmp_leader.owner_generation,
			  (unsigned long long)tmp_leader.timestamp);
		goto restart;
	}

	if (memcmp(&cur_leader, &tmp_leader, sizeof(struct leader_record))) {
		/* I don't think this should ever happen. */
		log_errot(token, "paxos_acquire restart leader changed2");
		goto restart;
	}

	error = run_ballot(task, token, cur_leader.num_hosts, next_lver, our_mbal,
			   &dblock);

	if (error == SANLK_DBLOCK_MBAL) {
		us = get_rand(0, 1000000);
		if (us < 0)
			us = token->host_id * 100;

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
	new_leader.write_timestamp = monotime();

	if (new_num_hosts)
		new_leader.num_hosts = new_num_hosts;

	if (new_leader.owner_id == token->host_id) {
		/*
		 * The LFL_SHORT_HOLD flag is just a "hint" to help
		 * other nodes be more intelligent about retrying
		 * due to transient failures when acquiring shared
		 * leases.  Only modify SHORT_HOLD if we're commiting
		 * ourself as the new owner.  If we're commiting another
		 * host as owner, we don't know if they are acquiring
		 * shared or not.
		 */
		if (flags & PAXOS_ACQUIRE_SHARED)
			new_leader.flags |= LFL_SHORT_HOLD;
		else
			new_leader.flags &= ~LFL_SHORT_HOLD;
	}

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

		memcpy(leader_ret, &new_leader, sizeof(struct leader_record));
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

	new_leader.timestamp = monotime();
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
		log_errot(token, "paxos_release leader_read error %d", error);
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
	leader.write_timestamp = monotime();
	leader.flags &= ~LFL_SHORT_HOLD;
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
	struct request_record *rr;
	int iobuf_len;
	int sector_size;
	int align_size;
	int aio_timeout = 0;
	int rv, d;

	if (!num_hosts)
		num_hosts = DEFAULT_MAX_HOSTS;
	if (!max_hosts)
		max_hosts = DEFAULT_MAX_HOSTS;

	sector_size = token->disks[0].sector_size;

	align_size = direct_align(&token->disks[0]);
	if (align_size < 0)
		return align_size;

	if (sector_size * (2 + max_hosts) > align_size)
		return -E2BIG;

	iobuf_len = align_size;

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv)
		return rv;

	memset(iobuf, 0, iobuf_len);

	leader = (struct leader_record *)iobuf;
	leader->magic = PAXOS_DISK_MAGIC;
	leader->version = PAXOS_DISK_VERSION_MAJOR | PAXOS_DISK_VERSION_MINOR;
	leader->sector_size = sector_size;
	leader->num_hosts = num_hosts;
	leader->max_hosts = max_hosts;
	leader->timestamp = LEASE_FREE;
	strncpy(leader->space_name, token->r.lockspace_name, NAME_ID_SIZE);
	strncpy(leader->resource_name, token->r.name, NAME_ID_SIZE);
	leader->checksum = leader_checksum(leader);

	rr = (struct request_record *)(iobuf + sector_size);
	rr->magic = REQ_DISK_MAGIC;
	rr->version = REQ_DISK_VERSION_MAJOR | REQ_DISK_VERSION_MINOR;

	for (d = 0; d < token->r.num_disks; d++) {
		rv = write_iobuf(token->disks[d].fd, token->disks[d].offset,
				 iobuf, iobuf_len, task);

		if (rv == SANLK_AIO_TIMEOUT)
			aio_timeout = 1;

		if (rv < 0)
			return rv;
	}

	if (!aio_timeout)
		free(iobuf);

	return 0;
}

