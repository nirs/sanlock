#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
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

#include "disk_paxos.h"

/*
 * largely copied from vdsm.git/sync_manager/
 */

#define LEASE_TIMEOUT_SEC 60

#define LEASE_FREE 0

#define BLOCK_SIZE 512

#define LEADER_COMPARE_LEN 80	/* through end of token_name */

#define NO_VAL 0

uint64_t our_host_id;
uint64_t num_hosts;

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

int write_block(struct paxos_disk *disk, off_t offset, char *data, int len)
{
	char *iobuf, **p_iobuf;
	off_t ret;
	int rv;

	ret = lseek(disk->fd, offset, SEEK_SET);
	if (ret != offset) {
		rv = -1;
		goto out;
	}

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), BLOCK_SIZE);
	if (rv) {
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, BLOCK_SIZE);
	memcpy(iobuf, data, len);

	rv = write(disk->fd, iobuf, BLOCK_SIZE);
	if (rv != BLOCK_SIZE) {
		rv = -1;
		goto out_free;
	}

	rv = 0;
 out_free:
	free(iobuf);
 out:
	return rv;
}

int write_dblock(struct paxos_disk *disk, int host_id, struct paxos_dblock *pd)
{
	int blocknr, rv;

	/* 1 leader block + 1 request block;
	   host_id N is block offset N-1 */

	blocknr = 2 + host_id - 1;

	rv = write_block(disk, blocknr * BLOCK_SIZE,
			 (char *)pd, sizeof(struct paxos_dblock));
	if (rv < 0)
		log_error("write_dblock error block %d %s",
			  blocknr, disk->path);

	return rv;
}

int write_request(struct paxos_disk *disk, struct request_record *rr)
{
	int rv;

	rv = write_block(disk, BLOCK_SIZE, (char *)rr,
			 sizeof(struct request_record));
	if (rv < 0)
		log_error("write_request error %s", disk->path);

	return rv;
}

int write_leader(struct paxos_disk *disk, struct leader_record *lr)
{
	int rv;

	rv = write_block(disk, 0, (char *)lr, sizeof(struct leader_record));
	if (rv < 0)
		log_error("write_leader error %s", disk->path);

	return rv;
}

int read_dblock(struct paxos_disk *disk, int host_id, struct paxos_dblock *pd)
{
	char *iobuf, **p_iobuf;
	off_t offset, ret;
	int blocknr, len, rv;

	/* 1 leader block + 1 request block; host_id N is block offset N-1 */

	blocknr = 2 + host_id - 1;
	offset = blocknr * BLOCK_SIZE;
	len = BLOCK_SIZE;

	ret = lseek(disk->fd, offset, SEEK_SET);
	if (ret != offset) {
		rv = -1;
		goto out;
	}

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), len);
	if (rv) {
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, len);

	rv = read(disk->fd, iobuf, len);
	if (rv != len) {
		rv = -1;
		goto out_free;
	}

	memcpy(pd, iobuf, sizeof(struct paxos_dblock));

	rv = 0;
 out_free:
	free(iobuf);
 out:
	if (rv < 0)
		log_error("read_dblock error block %d %s", blocknr, disk->path);
	return rv;
}

int read_dblocks(struct paxos_disk *disk, int num, struct paxos_dblock *pds)
{
	char *iobuf, **p_iobuf;
	off_t offset, ret;
	int blocknr, len, rv, i;

	/* 1 leader block + 1 request block */

	blocknr = 2;
	offset = blocknr * BLOCK_SIZE;
	len = num * BLOCK_SIZE;

	ret = lseek(disk->fd, offset, SEEK_SET);
	if (ret != offset) {
		rv = -1;
		goto out;
	}

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), len);
	if (rv) {
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, len);

	rv = read(disk->fd, iobuf, len);
	if (rv != len) {
		rv = -1;
		goto out_free;
	}

	for (i = 0; i < num; i++) {
		memcpy(&pds[i], iobuf + (i * BLOCK_SIZE),
		       sizeof(struct paxos_dblock));
	}

	rv = 0;
 out_free:
	free(iobuf);
 out:
	if (rv < 0)
		log_error("read_dblocks error %s", disk->path);
	return rv;
}

int read_leader(struct paxos_disk *disk, struct leader_record *lr)
{
	char *iobuf, **p_iobuf;
	off_t ret;
	int rv;

	ret = lseek(disk->fd, 0, SEEK_SET);
	if (ret != 0) {
		rv = -1;
		goto out;
	}

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), BLOCK_SIZE);
	if (rv) {
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, BLOCK_SIZE);

	rv = read(disk->fd, iobuf, BLOCK_SIZE);
	if (rv != BLOCK_SIZE) {
		rv = -1;
		goto out_free;
	}

	memcpy(lr, iobuf, sizeof(struct leader_record));

	rv = 0;
 out_free:
	free(iobuf);
 out:
	if (rv < 0)
		log_error("read_leader error %s", disk->path);
	return rv;
}

int read_request(struct paxos_disk *disk, struct request_record *rr)
{
	char *iobuf, **p_iobuf;
	off_t ret;
	int rv;

	ret = lseek(disk->fd, BLOCK_SIZE, SEEK_SET);
	if (ret != BLOCK_SIZE) {
		rv = -1;
		goto out;
	}

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), BLOCK_SIZE);
	if (rv) {
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, BLOCK_SIZE);

	rv = read(disk->fd, iobuf, BLOCK_SIZE);
	if (rv != BLOCK_SIZE) {
		rv = -1;
		goto out_free;
	}

	memcpy(rr, iobuf, sizeof(struct request_record));

	rv = 0;
 out_free:
	free(iobuf);
 out:
	if (rv < 0)
		log_error("read_request error %s", disk->path);
	return rv;
}

/* host_id and inp are both generally our_host_id */

int run_disk_paxos(uint64_t host_id, uint64_t inp, struct token *token,
		   int num_hosts, uint64_t lver,
		   struct paxos_dblock *dblock_out)
{
	struct paxos_dblock bk[MAX_HOSTS];
	struct paxos_dblock bk_max;
	struct paxos_dblock dblock;
	int num_disks = token->num_disks;
	int num_writes, num_reads;
	int d, q, rv;

	if (!host_id) {
		log_error("invalid host_id");
		return -1;
	}

	if (!inp) {
		log_error("invalid inp");
		return -1;
	}

	if (!token) {
		log_error("no token");
		return -1;
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
		log_error("no initial dblock found");
		return -1;
	}

	log_debug("initial dblock %u mbal %llu bal %llu inp %llu lver %llu", d,
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
		dblock.mbal += MAX_HOSTS; /* or num_hosts? */
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
		log_error("cannot write dblock to majority of disks");
		return -1;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_dblocks(&token->disks[d], num_hosts, bk);
		if (rv < 0)
			continue;
		num_reads++;

		for (q = 0; q < num_hosts; q++) {
			if (bk[q].lver < dblock.lver)
				continue;

			if (bk[q].lver > dblock.lver) {
				log_error("bk %d %d lver %llu dblock lver %llu",
					  d, q,
					  (unsigned long long)bk[q].lver,
					  (unsigned long long)dblock.lver);
				return -1;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk[q].mbal > dblock.mbal) {
				log_error("bk %d %d mbal %llu dblock mbal %llu",
					  d, q,
					  (unsigned long long)bk[q].mbal,
					  (unsigned long long)dblock.mbal);
				return -1;
			}

			/* see choosing inp for phase 2 in comment below */

			if (bk[q].inp == NO_VAL)
				continue;

			if (bk_max.bal == NO_VAL || bk[q].bal > bk_max.bal)
				bk_max = bk[q];
		}
	}

	if (!majority_disks(token, num_reads)) {
		log_error("cannot read dblocks on majority of disks");
		return -1;
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

	log_debug("bk_max inp %llu bal %llu",
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
		log_error("cannot write dblock to majority of disks 2");
		return -1;
	}

	num_reads = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_dblocks(&token->disks[d], num_hosts, bk);
		if (rv < 0)
			continue;
		num_reads++;

		for (q = 0; q < num_hosts; q++) {
			if (bk[q].lver < dblock.lver)
				continue;

			if (bk[q].lver > dblock.lver) {
				log_error("bk %d %d lver %llu dblock lver %llu",
					  d, q,
					  (unsigned long long)bk[q].lver,
					  (unsigned long long)dblock.lver);
				return -1;
			}

			/* see "It aborts the ballot" in comment above */

			if (bk[q].mbal > dblock.mbal) {
				log_error("bk %d %d mbal %llu dblock mbal %llu",
					  d, q,
					  (unsigned long long)bk[q].mbal,
					  (unsigned long long)dblock.mbal);
				return -1;
			}
		}
	}

	if (!majority_disks(token, num_reads)) {
		log_error("cannot read dblocks from majority of disks 2");
		return -1;
	}

	/* "When it completes phase 2, p has committed dblock[p].inp." */

	memcpy(dblock_out, &dblock, sizeof(struct paxos_dblock));

	return 0;
}

int leaders_match(struct leader_record *a, struct leader_record *b)
{
	if (!memcmp(a, b, LEADER_COMPARE_LEN))
		return 1;
	return 0;
}

int get_prev_leader(struct token *token, int force,
		    struct leader_record *leader_out)
{
	struct leader_record prev_leader;
	struct leader_record tmp_leader;
	struct leader_record *leaders;
	struct request_record req;
	int *leader_reps;
	int leaders_len, leader_reps_len;
	int num_reads, num_writes, num_free, num_timeout;
	int num_disks = token->num_disks;
	int rv, d, i, found;

	leaders_len = num_disks * sizeof(struct leader_record);
	leader_reps_len = num_disks * sizeof(int);

	leaders = malloc(leaders_len);
	if (!leaders)
		return -1;

	leader_reps = malloc(leader_reps_len);
	if (!leader_reps) {
		free(leaders);
		return -1;
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
		log_error("cannot read leader from majority of disks");
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
		log_error("cannot find majority leader");
		goto fail;
	}

	log_debug("prev_leader d %u reps %u", d, leader_reps[d]);

	log_debug("prev_leader owner %llu lver %llu hosts %llu time %llu "
		  "token %u %s",
		  (unsigned long long)prev_leader.owner_id,
		  (unsigned long long)prev_leader.lver,
		  (unsigned long long)prev_leader.num_hosts,
		  (unsigned long long)prev_leader.timestamp,
		  prev_leader.token_type, prev_leader.token_name);

	/* sanity check that the new leader token name is correct and that
	   our host_id is within the accepted range */

	if (token->type != prev_leader.token_type ||
	    strcmp(token->name, prev_leader.token_name)) {
		log_error("leader has wrong token name");
		goto fail;
	}

	if (prev_leader.num_hosts < our_host_id) {
		log_error("leader num_hosts too small");
		goto fail;
	}

	/*
	 * signal handover request to current leader (prev_leader);
	 * write request with highest leader version found + 1
	 * to at least one disk.
	 */

	memset(&req, 0, sizeof(struct request_record));
	req.lver = prev_leader.lver + 1;
	req.force_mode = force;

	log_debug("write request lver %llu force %u",
		  (unsigned long long)req.lver, req.force_mode);

	num_writes = 0;

	for (d = 0; d < num_disks; d++) {
		rv = write_request(&token->disks[d], &req);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!num_writes) {
		log_error("cannot write request to any disk");
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
		log_debug("lease free on majority %d disks", num_free);
		goto out;
	}

	/*
	 * check if current leader fails to update lease
	 */

	log_debug("wait %u sec for lease timeout...", LEASE_TIMEOUT_SEC);

	sleep(LEASE_TIMEOUT_SEC);

	num_timeout = 0;

	for (d = 0; d < num_disks; d++) {
		rv = read_leader(&token->disks[d], &tmp_leader);
		if (rv < 0)
			continue;

		if (!memcmp(&leaders[d], &tmp_leader,
			    sizeof(struct leader_record)))
			num_timeout++;
	}

	if (!majority_disks(token, num_timeout)) {
		log_error("no lease timeout on majority of disks");
		goto fail;
	}

	log_debug("lease timeout on majority %d disks", num_timeout);

 out:
	memcpy(leader_out, &prev_leader, sizeof(struct leader_record));
	return 0;

 fail:
	/* TODO: are there some errors where we don't want the
	   caller to retry? */

	free(leaders);
	free(leader_reps);
	return -1;
}

/*
 * token_lease - obtain the lease on the token
 * ref: obtain()
 */

int disk_paxos_acquire(struct token *token, int force, int wait_timeout,
		       struct leader_record *leader_ret)
{
	struct leader_record prev_leader;
	struct leader_record new_leader;
	struct paxos_dblock dblock;
	int num_disks = token->num_disks;
	int rv, d, num_writes;
	time_t start = time(NULL);

	/*
	 * find a valid current/previous leader on which to base
	 * the new leader
	 */

	while (1) {
		rv = get_prev_leader(token, force, &prev_leader);
		if (!rv)
			break;

		if (wait_timeout == -1)
			continue;

		if (!wait_timeout) {
			log_error("no leader found");
			goto fail;
		}

		if ((time(NULL) - start) < (wait_timeout - LEASE_TIMEOUT_SEC)) {
			log_error("time out finding leader");
			goto fail;
		}
	}

	/*
	 * run disk paxos to reach consensus on a new leader
	 */

	memset(&new_leader, 0, sizeof(struct leader_record));
	strncpy(new_leader.token_name, token->name, TOKEN_NAME_SIZE);
	new_leader.token_type = token->type;
	new_leader.lver = prev_leader.lver + 1; /* req.lver */
	new_leader.num_hosts = prev_leader.num_hosts;
	new_leader.num_alloc_slots = prev_leader.num_alloc_slots; /* ? */

	rv = run_disk_paxos(our_host_id, our_host_id, token,
			    new_leader.num_hosts, new_leader.lver, &dblock);
	if (rv) {
		log_error("run_disk_paxos error");
		goto fail;
	}

	log_debug("paxos result dblock mbal %llu bal %llu inp %llu lver %llu",
		  (unsigned long long)dblock.mbal,
		  (unsigned long long)dblock.bal,
		  (unsigned long long)dblock.inp,
		  (unsigned long long)dblock.lver);

	/* dblock has the disk paxos result: consensus inp and lver */

	new_leader.owner_id = dblock.inp;
	new_leader.lver = dblock.lver;
	new_leader.timestamp = time(NULL);

	/*
	 * write new leader to disks
	 */

	num_writes = 0;

	for (d = 0; d < num_disks; d++) {
		rv = write_leader(&token->disks[d], &new_leader);
		if (rv < 0)
			continue;
		num_writes++;
	}

	if (!majority_disks(token, num_writes)) {
		log_error("cannot write leader to majority of disks");
		goto fail;
	}

	/* got the lease */

	log_debug("new_leader owner %llu lver %llu hosts %llu time %llu "
		  "token %u %s",
		  (unsigned long long)new_leader.owner_id,
		  (unsigned long long)new_leader.lver,
		  (unsigned long long)new_leader.num_hosts,
		  (unsigned long long)new_leader.timestamp,
		  new_leader.token_type, new_leader.token_name);

	memcpy(leader_out, &new_leader, sizeof(struct leader_record));
	return 0;
 fail:
	return -1;
}

int disk_paxos_release(struct token *token, struct leader_record *leader_ret)
{
}

int disk_paxos_renew(struct token *token, struct leader_record *leader_ret)
{
}

int disk_paxos_transfer(struct token *token, uint64_t hostid,
			struct leader_record *leader_ret)
{
}

void token_status(struct token *token)
{
	struct leader_record leader;
	struct request_record req;
	struct paxos_dblock bk[MAX_HOSTS];
	struct paxos_disk *disk;
	int d, q, rv;

	for (d = 0; d < token->num_disks; d++) {
		disk = &token->disks[d];

		printf("disk %d offset %llu %s\n", d,
		       (unsigned long long)disk->offset, disk->path);

		memset(&leader, 0, sizeof(leader));

		rv = read_leader(disk, &leader);
		if (rv < 0)
			continue;

		printf("leader[%u].owner_id        %llu\n", d,
		       (unsigned long long)leader.owner_id);

		printf("leader[%u].lver            %llu\n", d,
		       (unsigned long long)leader.lver);

		printf("leader[%u].num_hosts       %llu\n", d,
		       (unsigned long long)leader.num_hosts);

		printf("leader[%u].num_alloc_slots %llu\n", d,
		       (unsigned long long)leader.num_alloc_slots);

		printf("leader[%u].cluster_mode    %u\n", d,
		       leader.cluster_mode);

		printf("leader[%u].version         %u\n", d, leader.version);

		printf("leader[%u].token_type      %u\n", d, leader.token_type);

		printf("leader[%u].token_name      %s\n", d, leader.token_name);

		printf("leader[%u].timestamp       %llu\n", d,
		       (unsigned long long)leader.timestamp);

		printf("leader[%u].checksum        %u\n", d, leader.checksum);

		memset(&req, 0, sizeof(req));

		rv = read_request(disk, &req);
		if (rv < 0)
			continue;

		printf("reques[%u].lver            %llu\n", d,
		       (unsigned long long)req.lver);

		printf("reques[%u].force_mode      %u\n", d, req.force_mode);

		memset(&bk, 0, sizeof(bk));

		rv = read_dblocks(disk, num_hosts, bk);
		if (rv < 0)
			continue;

		for (q = 0; q < num_hosts; q++) {
			printf("dblock[%u][%u].mbal %llu\n", d, q,
			       (unsigned long long)bk[q].mbal);
			printf("dblock[%u][%u].bal  %llu\n", d, q,
			       (unsigned long long)bk[q].bal);
			printf("dblock[%u][%u].inp  %llu\n", d, q,
			       (unsigned long long)bk[q].inp);
			printf("dblock[%u][%u].lver %llu\n", d, q,
			       (unsigned long long)bk[q].lver);
		}
	}
}

void token_init(struct token *token)
{
	struct leader_record leader;
	struct request_record req;
	struct paxos_dblock dblock;
	int d, q;

	/* zero all blocks */

	memset(&leader, 0, sizeof(struct leader_record));
	memset(&req, 0, sizeof(struct request_record));
	memset(&dblock, 0, sizeof(struct paxos_dblock));

	for (d = 0; d < token->num_disks; d++) {
		write_leader(&token->disks[d], &leader);
		write_request(&token->disks[d], &req);
		for (q = 0; q < MAX_HOSTS; q++)
			write_dblock(&token->disks[d], q, &dblock);
	}

	/* make local host id the leader */

	dblock.inp = our_host_id;
	dblock.lver = 1;
	dblock.mbal = our_host_id;
	dblock.bal = our_host_id;

	leader.owner_id = our_host_id;
	leader.lver = 1;
	leader.num_hosts = num_hosts;
	leader.timestamp = time(NULL);
	leader.token_type = token->type;
	strncpy(leader.token_name, token->name, TOKEN_NAME_SIZE);

	for (d = 0; d < token->num_disks; d++) {
		write_leader(&token->disks[d], &leader);
		write_dblock(&token->disks[d], our_host_id, &dblock);
	}
}

void print_usage(void)
{
	printf("disk_lease -n <name> -i <host_id> -h <num_hosts> /path/disk1 /path/disk2 ...\n");
	printf("-n <name>            name of object being leased\n");
	printf("-i <host_id>         local host id (1-254)\n");
	printf("-h <num_hosts>       number of hosts (1-254)\n");
	printf("optional:\n");
	printf("-o <bytes>           offset on disks (default 0)\n");
	printf("-f                   force\n");
	printf("-S                   show status only\n");
	printf("-I                   initialize disks, host id as leader\n");
}

/* TODO
   renew the lease (just update timestamp?)
   release the lease (just set LEASE_FREE timestamp?)
   give the lease to another node (set owner to their id?)
*/


int main(int argc, char *argv[])
{
	struct token *token;
	struct paxos_disk *disks, *disk;
	char name[TOKEN_NAME_SIZE];
	int timeout = 0;
	int force = 0;
	int offset = 0;
	int num_disks;
	int num_opened;
	int do_status = 0;
	int do_init = 0;
	int cont = 1;
	int optchar;
	int rv;

	if (argc < 2) {
		print_usage();
		return -1;
	}

	memset(name, 0, sizeof(name));

	while (cont) {
		optchar = getopt(argc, argv, "n:i:h:o:fSI");

		switch (optchar) {
		case 'n':
			snprintf(name, TOKEN_NAME_SIZE, "%s", optarg);
			break;
		case 'i':
			our_host_id = atoi(optarg);
			break;
		case 'h':
			num_hosts = atoi(optarg);
			break;
		case 'o':
			offset = atoi(optarg);
			break;
		case 'f':
			force = 1;
			break;
		case 'S':
			do_status = 1;
			break;
		case 'I':
			do_init = 1;
			break;
		case EOF:
			cont = 0;
			break;
		};
	}

	if (!name[0]) {
		log_error("name required");
		print_usage();
		return -1;
	}

	if (!our_host_id) {
		log_error("host id required");
		print_usage();
		return -1;
	}

	num_disks = argc - optind;
	if (!num_disks || num_disks > MAX_DISKS) {
		log_error("num_disks %d min 1 max %d", num_disks, MAX_DISKS);
		print_usage();
		return -1;
	}

	disks = malloc(num_disks * sizeof(struct paxos_disk));
	if (!disks)
		return -1;
	memset(disks, 0, num_disks * sizeof(struct paxos_disk));

	log_debug("num_disks %d", num_disks);

	disk = disks;
	while (optind < argc) {
		strncpy(disk->path, argv[optind], MAX_PATH_LEN);
		disk->offset = offset;
		log_debug("disk %s", disk->path);
		optind++;
		disk++;
	}

	token = malloc(sizeof(struct token));
	if (!token) {
		free(disks);
		return -1;
	}

	strncpy(token->name, name, TOKEN_NAME_SIZE);
	token->type = 0;
	token->disks = disks;
	token->num_disks = num_disks;

	num_opened = open_disks(token, offset);
	if (!majority_disks(token, num_opened)) {
		log_error("cannot open majority of disks");
		rv = -1;
		goto out;
	}

	if (do_status) {
		token_status(token);
		goto out_close;
	}

	if (do_init) {
		token_init(token);
		goto out_close;
	}

	/* default is to try to acquire the lease */

	rv = token_lease(token, force, timeout);

	/* TODO: add option for a renewal loop here ?
	   I believe we just rewrite the last leader block with
	   fresh timestamp every N seconds.  Second option to
	   watch for requests and release lease when we see one? */

 out_close:
	close_disks(token);
 out:
	free(disks);
	free(token);
	return rv;
}

