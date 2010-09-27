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

#include "sm.h"
#include "sm_msg.h"
#include "disk_paxos.h"
#include "sm_options.h"
#include "log.h"
#include "crc32c.h"
#include "diskio.h"

/*
 * largely copied from vdsm.git/sync_manager/
 */

#define LEASE_FREE 0

#define NO_VAL 0

extern int cluster_mode;

int majority_disks(struct token *token, int num)
{
	int num_disks = token->num_disks;

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

static int write_dblock(struct sync_disk *disk, int host_id,
			struct paxos_dblock *pd)
{
	int rv;

	/* 1 leader block + 1 request block;
	   host_id N is block offset N-1 */

	rv = write_sector(disk, 2 + host_id - 1, (char *)pd,
			  sizeof(struct paxos_dblock), to.io_timeout_seconds,
			  "dblock");
	return rv;
}

static int write_request(struct sync_disk *disk, struct request_record *rr)
{
	int rv;

	rv = write_sector(disk, 1, (char *)rr, sizeof(struct request_record),
			  to.io_timeout_seconds, "request");
	return rv;
}

static int write_leader(struct sync_disk *disk, struct leader_record *lr)
{
	int rv;

	rv = write_sector(disk, 0, (char *)lr, sizeof(struct leader_record),
			  to.io_timeout_seconds, "leader");
	return rv;
}

static int read_dblock(struct sync_disk *disk, int host_id,
		       struct paxos_dblock *pd)
{
	int rv;

	/* 1 leader block + 1 request block; host_id N is block offset N-1 */

	rv = read_sectors(disk, 2 + host_id - 1, 1, (char *)pd,
			  sizeof(struct paxos_dblock),
			  to.io_timeout_seconds, "dblock");
	return rv;
}

static int read_dblocks(struct sync_disk *disk, struct paxos_dblock *pds,
			int pds_count)
{
	char *data;
	int data_len, rv, i;

	data_len = pds_count * disk->sector_size;

	data = malloc(data_len);
	if (!data) {
		log_error(NULL, "read_dblocks malloc %d %s",
			  data_len, disk->path);
		rv = -1;
		goto out;
	}

	/* 2 = 1 leader block + 1 request block */

	rv = read_sectors(disk, 2, pds_count, data, data_len,
			  to.io_timeout_seconds, "dblocks");
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

static int read_leader(struct sync_disk *disk, struct leader_record *lr)
{
	int rv;

	/* 0 = leader record is first sector */

	rv = read_sectors(disk, 0, 1, (char *)lr,
			  sizeof(struct leader_record),
			  to.io_timeout_seconds, "leader");

	return rv;
}


#if 0
static int read_request(struct sync_disk *disk, struct request_record *rr)
{
	int rv;

	/* 1 = request record is second sector */

	rv = read_sectors(disk, 1, (char *)rr, sizeof(struct request_record),
			  to.io_timeout_seconds, "request");

	return rv;
}
#endif

/* host_id and inp are both generally our_host_id */

static int run_disk_paxos(struct token *token, int host_id, uint64_t inp,
			  int num_hosts, uint64_t lver,
			  struct paxos_dblock *dblock_out)
{
	struct paxos_dblock bk[num_hosts];
	struct paxos_dblock bk_max;
	struct paxos_dblock dblock;
	int num_disks = token->num_disks;
	int num_writes, num_reads;
	int d, q, rv;

	if (!host_id) {
		log_error(token, "invalid host_id");
		return DP_INVAL;
	}

	if (!inp) {
		log_error(token, "invalid inp");
		return DP_INVAL;
	}

	/* read one of our own dblock's to get initial dblock values */

	memset(&dblock, 0, sizeof(struct paxos_dblock));

	for (d = 0; d < num_disks; d++) {
		rv = read_dblock(&token->disks[d], host_id, &dblock);
		if (rv < 0)
			continue;
		/* need only one dblock to get initial values */
		break;
	}

	if (rv < 0) {
		log_error(token, "no initial dblock found");
		return DP_OWN_DBLOCK;
	}

	log_debug(token, "initial dblock %u mbal %llu bal %llu inp %llu lver %llu", d,
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
		rv = write_dblock(&token->disks[d], host_id, &dblock);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_error(token, "cannot write dblock to majority of disks");
		return DP_WRITE1_DBLOCKS;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_dblocks(&token->disks[d], bk, num_hosts);
		if (rv < 0)
			continue;
		num_reads++;

		for (q = 0; q < num_hosts; q++) {
			if (bk[q].lver < dblock.lver)
				continue;

			if (bk[q].lver > dblock.lver) {
				log_error(token, "bk %d %d lver %llu dblock lver %llu",
					  d, q,
					  (unsigned long long)bk[q].lver,
					  (unsigned long long)dblock.lver);
				return DP_READ1_LVER;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk[q].mbal > dblock.mbal) {
				log_error(token, "bk %d %d mbal %llu dblock mbal %llu",
					  d, q,
					  (unsigned long long)bk[q].mbal,
					  (unsigned long long)dblock.mbal);
				return DP_READ1_MBAL;
			}

			/* see choosing inp for phase 2 in comment below */

			if (bk[q].inp == NO_VAL)
				continue;

			if (bk_max.bal == NO_VAL || bk[q].bal > bk_max.bal)
				bk_max = bk[q];
		}
	}

	if (!majority_disks(token, num_reads)) {
		log_error(token, "cannot read dblocks on majority of disks");
		return DP_READ1_DBLOCKS;
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

	log_debug(token, "bk_max inp %llu bal %llu",
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
		rv = write_dblock(&token->disks[d], host_id, &dblock);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_error(token, "cannot write dblock to majority of disks 2");
		return DP_WRITE2_DBLOCKS;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_dblocks(&token->disks[d], bk, num_hosts);
		if (rv < 0)
			continue;
		num_reads++;

		for (q = 0; q < num_hosts; q++) {
			if (bk[q].lver < dblock.lver)
				continue;

			if (bk[q].lver > dblock.lver) {
				log_error(token, "bk %d %d lver %llu dblock lver %llu",
					  d, q,
					  (unsigned long long)bk[q].lver,
					  (unsigned long long)dblock.lver);
				return DP_READ2_LVER;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk[q].mbal > dblock.mbal) {
				log_error(token, "bk %d %d mbal %llu dblock mbal %llu",
					  d, q,
					  (unsigned long long)bk[q].mbal,
					  (unsigned long long)dblock.mbal);
				return DP_READ2_MBAL;
			}
		}
	}

	if (!majority_disks(token, num_reads)) {
		log_error(token, "cannot read dblocks from majority of disks 2");
		return DP_READ2_DBLOCKS;
	}

	/* "When it completes phase 2, p has committed dblock[p].inp." */

	memcpy(dblock_out, &dblock, sizeof(struct paxos_dblock));

	return DP_OK;
}

static uint32_t leader_checksum(struct leader_record *lr)
{
	return crc32c((uint32_t)~1, (char *)lr, LEADER_CHECKSUM_LEN);
}

static int verify_leader(struct token *token, int d, struct leader_record *lr)
{
	if (lr->magic != PAXOS_DISK_MAGIC) {
		log_error(token, "disk %d leader has wrong magic number", d);
		return DP_BAD_MAGIC;
	}

	if ((lr->version & 0xFFFF0000) != PAXOS_DISK_VERSION_MAJOR) {
		log_error(token, "disk %d leader has wrong version %x", d,
			  lr->version);
		return DP_BAD_VERSION;
	}

	if (lr->cluster_mode != cluster_mode) {
		log_error(token, "disk %d leader has wrong cluster mode %d", d,
			  lr->cluster_mode);
		return DP_BAD_CLUSTERMODE;
	}

	if (lr->sector_size != token->disks[0].sector_size) {
		log_error(token, "disk %d leader has wrong sector size %d", d,
			  lr->sector_size);
		return DP_BAD_SECTORSIZE;
	}

	if (strncmp(lr->resource_name, token->resource_name, NAME_ID_SIZE)) {
		log_error(token, "disk %d leader has wrong resource id %s", d,
			  lr->resource_name);
		return DP_BAD_RESOURCEID;
	}

	if (lr->num_hosts < options.our_host_id) {
		log_error(token, "disk %d leader num_hosts too small %d", d,
			  (int)lr->num_hosts);
		return DP_BAD_NUMHOSTS;
	}

	if (leader_checksum(lr) != lr->checksum) {
		log_error(token, "disk %d leader has wrong checksum %x", d,
			   lr->checksum);
		return DP_BAD_CHECKSUM;
	}

	return 0;
}

static int leaders_match(struct leader_record *a, struct leader_record *b)
{
	if (!memcmp(a, b, LEADER_COMPARE_LEN))
		return 1;
	return 0;
}

static int get_prev_leader(struct token *token, int force,
			   struct leader_record *leader_out)
{
	struct leader_record prev_leader;
	struct leader_record tmp_leader;
	struct leader_record *leaders;
	struct request_record req;
	int *leader_reps;
	int leaders_len, leader_reps_len;
	int num_reads, num_writes, num_free, num_diff;
	int num_disks = token->num_disks;
	int rv, d, i, found;
	int error;

	leaders_len = num_disks * sizeof(struct leader_record);
	leader_reps_len = num_disks * sizeof(int);

	leaders = malloc(leaders_len);
	if (!leaders)
		return DP_NOMEM;

	leader_reps = malloc(leader_reps_len);
	if (!leader_reps) {
		free(leaders);
		return DP_NOMEM;
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
		rv = read_leader(&token->disks[d], &leaders[d]);
		if (rv < 0)
			continue;

		rv = verify_leader(token, d, &leaders[d]);
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
		log_error(token, "cannot read leader from majority of disks");
		error = DP_READ_LEADERS;
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
		log_error(token, "cannot find majority leader");
		error = DP_DIFF_LEADERS;
		goto fail;
	}

	log_debug(token, "prev_leader d %u reps %u", d, leader_reps[d]);

	log_debug(token, "prev_leader owner %llu lver %llu hosts %llu "
		  "time %llu res %s",
		  (unsigned long long)prev_leader.owner_id,
		  (unsigned long long)prev_leader.lver,
		  (unsigned long long)prev_leader.num_hosts,
		  (unsigned long long)prev_leader.timestamp,
		  prev_leader.resource_name);

	/*
	 * signal handover request to current leader (prev_leader);
	 * write request with highest leader version found + 1
	 * to at least one disk.
	 */

	memset(&req, 0, sizeof(struct request_record));
	req.lver = prev_leader.lver + 1;
	req.force_mode = force;

	log_debug(token, "write request lver %llu force %u",
		  (unsigned long long)req.lver, req.force_mode);

	num_writes = 0;

	for (d = 0; d < num_disks; d++) {
		rv = write_request(&token->disks[d], &req);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!num_writes) {
		log_error(token, "cannot write request to any disk");
		error = DP_WRITE_REQUESTS;
		goto fail;
	}

	/*
	 * check if current leader has released leadership by
	 * writing LEASE_FREE timestamp on majority of disks
	 * ref: check_lease_state()
	 */

	num_free = 0;

	for (d = 0; d < num_disks; d++) {
		if (!leaders_match(&prev_leader, &leaders[d]))
			continue;

		if (leaders[d].timestamp == LEASE_FREE)
			num_free++;
	}

	if (majority_disks(token, num_free)) {
		log_debug(token, "lease free on majority %d disks", num_free);
		goto out;
	}

	/*
	 * check if current leader fails to update lease
	 */

	log_debug(token, "wait lease_timeout_seconds %u",
		  to.lease_timeout_seconds);

	for (i = 0; i < to.lease_timeout_seconds; i++) {
		sleep(1);
		num_diff = 0;

		for (d = 0; d < num_disks; d++) {
			rv = read_leader(&token->disks[d], &tmp_leader);
			if (rv < 0)
				continue;

			if (memcmp(&leaders[d], &tmp_leader, sizeof(struct leader_record)))
				num_diff++;
		}

		if (majority_disks(token, num_diff)) {
			log_error(token, "lease renewed on majority %d disks",
				  num_diff);
			error = DP_LIVE_LEADER;
			goto fail;
		}
	}

	log_debug(token, "lease timeout on majority of disks");
 out:
	memcpy(leader_out, &prev_leader, sizeof(struct leader_record));
	return DP_OK;

 fail:
	free(leaders);
	free(leader_reps);
	return error;
}

static int write_new_leader(struct token *token, struct leader_record *nl)
{
	int num_disks = token->num_disks;
	int num_writes = 0;
	int error = DP_OK;
	int rv, d;

	for (d = 0; d < num_disks; d++) {
		rv = write_leader(&token->disks[d], nl);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_error(token, "cannot write leader to majority of disks");
		error = DP_WRITE_LEADERS;
	}

	return error;
}

/*
 * acquire a lease
 * ref: obtain()
 */

int disk_paxos_acquire(struct token *token, int force,
		       struct leader_record *leader_ret)
{
	struct leader_record prev_leader;
	struct leader_record new_leader;
	struct paxos_dblock dblock;
	int error;

	/*
	 * find a valid current/previous leader on which to base
	 * the new leader
	 */

	error = get_prev_leader(token, force, &prev_leader);
	if (error < 0) {
		log_error(token, "get_prev_leader error %d", error);
		goto out;
	}

	/*
	 * run disk paxos to reach consensus on a new leader
	 */

	memcpy(&new_leader, &prev_leader, sizeof(struct leader_record));
	new_leader.lver += 1; /* req.lver */

	error = run_disk_paxos(token, options.our_host_id, options.our_host_id,
			       new_leader.num_hosts, new_leader.lver, &dblock);
	if (error < 0) {
		log_error(token, "run_disk_paxos error %d", error);
		goto out;
	}

	log_debug(token, "paxos result dblock mbal %llu bal %llu inp %llu lver %llu",
		  (unsigned long long)dblock.mbal,
		  (unsigned long long)dblock.bal,
		  (unsigned long long)dblock.inp,
		  (unsigned long long)dblock.lver);

	/* the inp value we commited wasn't us */

	if (dblock.inp != options.our_host_id) {
		log_error(token, "paxos contention our_host_id %u "
			  "mbal %llu bal %llu inp %llu lver %llu",
			  options.our_host_id,
			  (unsigned long long)dblock.mbal,
			  (unsigned long long)dblock.bal,
			  (unsigned long long)dblock.inp,
			  (unsigned long long)dblock.lver);
		return DP_OTHER_INP;
	}

	/* dblock has the disk paxos result: consensus inp and lver */

	new_leader.owner_id = dblock.inp;
	new_leader.lver = dblock.lver;
	new_leader.timestamp = time(NULL);
	new_leader.checksum = leader_checksum(&new_leader);

	error = write_new_leader(token, &new_leader);
	if (error < 0)
		goto out;

	memcpy(leader_ret, &new_leader, sizeof(struct leader_record));
 out:
	return error;
}

int disk_paxos_renew(struct token *token,
		     struct leader_record *leader_last,
		     struct leader_record *leader_ret)
{
	struct leader_record new_leader;
	int rv, d;
	int error;

	for (d = 0; d < token->num_disks; d++) {
		memset(&new_leader, 0, sizeof(struct leader_record));

		rv = read_leader(&token->disks[d], &new_leader);
		if (rv < 0)
			continue;

		if (memcmp(&new_leader, leader_last,
			   sizeof(struct leader_record))) {
			log_error(token, "leader changed between renewals");
			return DP_BAD_LEADER;
		}
	}

	new_leader.timestamp = time(NULL);
	new_leader.checksum = leader_checksum(&new_leader);

	error = write_new_leader(token, &new_leader);
	if (error < 0)
		goto out;

	memcpy(leader_ret, &new_leader, sizeof(struct leader_record));
 out:
	return error;
}

int disk_paxos_release(struct token *token,
		       struct leader_record *leader_last,
		       struct leader_record *leader_ret)
{
	struct leader_record new_leader;
	int error;

	memcpy(&new_leader, leader_last, sizeof(struct leader_record));
	new_leader.timestamp = LEASE_FREE;
	new_leader.checksum = leader_checksum(&new_leader);

	error = write_new_leader(token, &new_leader);
	if (error < 0)
		goto out;

	memcpy(leader_ret, &new_leader, sizeof(struct leader_record));
 out:
	return error;
}

int disk_paxos_transfer(struct token *token GNUC_UNUSED,
			int hostid GNUC_UNUSED,
			struct leader_record *leader_last GNUC_UNUSED,
			struct leader_record *leader_ret GNUC_UNUSED)
{
	/* what to change for a transfer?  new hostid in leader blocks,
	   new dblocks?  new lver in leader and dblocks? */
	return -1;
}

int disk_paxos_init(struct token *token, int num_hosts, int max_hosts)
{
	struct leader_record leader;
	struct request_record req;
	struct paxos_dblock dblock;
	int d, q;

	memset(&leader, 0, sizeof(struct leader_record));
	memset(&req, 0, sizeof(struct request_record));
	memset(&dblock, 0, sizeof(struct paxos_dblock));

	leader.magic = PAXOS_DISK_MAGIC;
	leader.version = PAXOS_DISK_VERSION_MAJOR | PAXOS_DISK_VERSION_MINOR;
	leader.cluster_mode = cluster_mode;
	leader.sector_size = token->disks[0].sector_size;
	leader.num_hosts = num_hosts;
	leader.max_hosts = max_hosts;
	leader.timestamp = LEASE_FREE;
	strncpy(leader.resource_name, token->resource_name, NAME_ID_SIZE);
	leader.checksum = leader_checksum(&leader);

	for (d = 0; d < token->num_disks; d++) {
		write_leader(&token->disks[d], &leader);
		write_request(&token->disks[d], &req);
		for (q = 0; q < max_hosts; q++)
			write_dblock(&token->disks[d], q, &dblock);
	}

	/* TODO: return error if cannot initialize majority of disks */

	return 0;
}

