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
#include <pthread.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sanlock_internal.h"
#include "sanlock_admin.h"
#include "diskio.h"
#include "ondisk.h"
#include "log.h"
#include "resource.h"
#include "direct.h"
#include "paxos_lease.h"
#include "delta_lease.h"
#include "timeouts.h"
#include "rindex.h"

/*
 * the caller sets sd.offset to the location from the start of disk (in bytes) where
 * a data struct should be read and checked for sector/align sizes.
 */
static int direct_read_leader_sizes(struct task *task, struct sync_disk *sd,
				    int *sector_size, int *align_size)
{
	struct leader_record *lr_end;
	struct leader_record lr_in;
	char *data;
	int datalen;
	int rv;

	datalen = 4096;
	data = malloc(datalen);

	if (!data)
		return -ENOMEM;

	memset(data, 0, datalen);

	rv = read_sectors(sd, 4096, 0, 1, data, datalen, task, com.io_timeout, "read_sector_size");
	if (rv < 0) {
		free(data);
		return rv;
	}

	lr_end = (struct leader_record *)data;

	leader_record_in(lr_end, &lr_in);

	free(data);

	if ((lr_in.magic == DELTA_DISK_MAGIC) || (lr_in.magic == PAXOS_DISK_MAGIC)) {
		*sector_size = lr_in.sector_size;
		*align_size = leader_align_size_from_flag(lr_in.flags);
		if (!*align_size)
			*align_size = sector_size_to_align_size_old(*sector_size);
		return 0;
	}

	return -1;
}

/*
 * cli: sanlock direct init
 * cli: sanlock direct read_leader
 * cli: sanlock direct acquire
 * cli: sanlock direct release
 * lib: sanlock_direct_init()
 *
 *              direct.c:
 *              direct_init()
 *              direct_read_leader()
 *              direct_acquire()
 *              direct_release()
 * 	           do_paxos_action()
 * 	              paxos_lease.c:
 * 	              paxos_lease_init()
 * 	              paxos_lease_leader_read()
 * 	              paxos_lease_acquire()
 * 	              paxos_lease_release()
 *
 * cli: sanlock direct init
 * cli: sanlock direct read_leader
 * cli: sanlock direct acquire_id
 * cli: sanlock direct release_id
 * cli: sanlock direct renew_id
 * lib: sanlock_direct_init()
 *
 *              direct.c:
 *              direct_init()
 *              direct_read_leader()
 *              direct_acquire_id()
 *              direct_release_id()
 *              direct_renew_id()
 *                 do_delta_action()
 *                    delta_lease.c:
 *                    delta_lease_init()
 *                    delta_lease_leader_read()
 *                    delta_lease_acquire()
 *                    delta_lease_release()
 *                    delta_lease_renew()
 */

static int do_paxos_action(int action, struct task *task, int io_timeout, struct sanlk_resource *res,
			   int num_hosts, int write_clear,
			   uint64_t local_host_id, uint64_t local_host_generation,
			   struct leader_record *leader_in, struct leader_record *leader_ret)
{
	struct token *token;
	struct leader_record leader;
	struct paxos_dblock dblock;
	int sector_size = 0;
	int align_size = 0;
	int max_hosts = 0;
	int disks_len, token_len;
	int j, rv = 0;

	if (!io_timeout)
		io_timeout = com.io_timeout;

	rv = sizes_from_flags(res->flags, &sector_size, &align_size, &max_hosts, "RES");
	if (rv)
		return -1;

	disks_len = res->num_disks * sizeof(struct sync_disk);
	token_len = sizeof(struct token) + disks_len;

	token = malloc(token_len);
	if (!token)
		return -ENOMEM;
	memset(token, 0, token_len);
	token->io_timeout = io_timeout;
	token->disks = (struct sync_disk *)&token->r.disks[0];
	token->r.num_disks = res->num_disks;
	memcpy(token->r.lockspace_name, res->lockspace_name, SANLK_NAME_LEN);
	memcpy(token->r.name, res->name, SANLK_NAME_LEN);
	token->r.flags = res->flags;

	/* WARNING sync_disk == sanlk_disk */

	memcpy(token->disks, &res->disks, disks_len);

	for (j = 0; j < token->r.num_disks; j++) {
		token->disks[j].sector_size = 0;
		token->disks[j].fd = -1;
	}


	rv = open_disks(token->disks, token->r.num_disks);
	if (rv < 0) {
		free(token);
		return rv;
	}

	if (!sector_size && com.sector_size)
		sector_size = com.sector_size;

	if (!align_size && com.align_size)
		align_size = com.align_size;

	switch (action) {
	case ACT_DIRECT_INIT:
		/* paxos_lease_init looks at token->r.flags for sector/align flags */

		rv = paxos_lease_init(task, token, num_hosts, write_clear);
		break;

	case ACT_ACQUIRE:
		if (!sector_size || !align_size) {
			rv = direct_read_leader_sizes(task, &token->disks[0], &sector_size, &align_size);
			if (rv < 0)
				break;
		}
		token->sector_size = sector_size;
		token->align_size = align_size;

		token->host_id = local_host_id;
		token->host_generation = local_host_generation;

		rv = paxos_lease_acquire(task, token, 0, leader_ret, &dblock, 0, 0);
		break;

	case ACT_RELEASE:
		if (!sector_size)
			sector_size = 4096;
		if (!align_size)
			align_size = sector_size_to_align_size_old(sector_size);

		token->sector_size = sector_size;
		token->align_size = align_size;

		rv = paxos_lease_leader_read(task, token, &leader, "direct_release");
		if (rv < 0)
			break;

		sector_size = leader.sector_size;
		align_size = leader_align_size_from_flag(leader.flags);
		if (!align_size)
			align_size = sector_size_to_align_size_old(sector_size);

		token->sector_size = sector_size;
		token->align_size = align_size;

		rv = paxos_lease_release(task, token, NULL, &leader, leader_ret);
		break;

	case ACT_READ_LEADER:
		if (!sector_size)
			sector_size = 4096;
		if (!align_size)
			align_size = sector_size_to_align_size_old(sector_size);

		token->sector_size = sector_size;
		token->align_size = align_size;

		rv = paxos_lease_leader_read(task, token, &leader, "direct_read_leader");
		break;

	case ACT_WRITE_LEADER:
		sector_size = leader_in->sector_size;
		align_size = leader_align_size_from_flag(leader_in->flags);
		if (!align_size)
			align_size = sector_size_to_align_size_old(sector_size);

		token->sector_size = sector_size;
		token->align_size = align_size;

		rv = paxos_lease_leader_clobber(task, token, leader_in, "direct_clobber");
		break;
	}

	close_disks(token->disks, token->r.num_disks);
	free(token);

	if (rv == SANLK_OK)
		rv = 0;

	if (leader_ret)
		memcpy(leader_ret, &leader, sizeof(struct leader_record));

	return rv;
}

/*
 * sanlock direct acquire -i <local_host_id> -g <local_host_generation> -r RESOURCE
 * sanlock direct release -r RESOURCE
 */

int direct_acquire(struct task *task, int io_timeout,
		   struct sanlk_resource *res,
		   int num_hosts,
		   uint64_t local_host_id,
		   uint64_t local_host_generation,
		   struct leader_record *leader_ret)
{
	return do_paxos_action(ACT_ACQUIRE, task, io_timeout, res,
			       num_hosts, 0,
			       local_host_id, local_host_generation,
			       NULL, leader_ret);
}

int direct_release(struct task *task, int io_timeout,
		   struct sanlk_resource *res,
		   struct leader_record *leader_ret)
{
	return do_paxos_action(ACT_RELEASE, task, io_timeout, res,
			       0, 0,
			       0, 0,
			       NULL, leader_ret);
}

static int do_delta_action(int action,
			   struct task *task,
			   int io_timeout,
			   struct sanlk_lockspace *ls,
			   char *our_host_name,
			   struct leader_record *leader_in,
			   struct leader_record *leader_ret)
{
	struct leader_record leader;
	struct sync_disk sd;
	struct space space;
	char bitmap[HOSTID_BITMAP_SIZE];
	int sector_size = 0;
	int align_size = 0;
	int max_hosts = 0;
	int read_result;
	int rd_ms, wr_ms;
	int rv;

	memset(bitmap, 0, sizeof(bitmap));

	if (!io_timeout)
		io_timeout = com.io_timeout;

	rv = sizes_from_flags(ls->flags, &sector_size, &align_size, &max_hosts, "LSF");
	if (rv)
		return -1;

	memset(&leader, 0, sizeof(leader));

	/* for log_space in delta functions */
	memset(&space, 0, sizeof(space));
	space.io_timeout = io_timeout;

	if (!ls->host_id_disk.path[0])
		return -ENODEV;

	if ((action != ACT_DIRECT_INIT) && !ls->host_id)
		return -EINVAL;

	memset(&sd, 0, sizeof(struct sync_disk));
	memcpy(&sd, &ls->host_id_disk, sizeof(struct sanlk_disk));
	sd.fd = -1;

	rv = open_disk(&sd);
	if (rv < 0)
		return -ENODEV;

	if (!sector_size && com.sector_size)
		sector_size = com.sector_size;

	if (!align_size && com.align_size)
		align_size = com.align_size;

	switch (action) {
	case ACT_DIRECT_INIT:
		/* delta_lease_init looks at ls->flags for sector/align sizes */

		rv = delta_lease_init(task, ls, io_timeout, &sd);
		break;

	case ACT_ACQUIRE_ID:
		if (!sector_size || !align_size) {
			rv = direct_read_leader_sizes(task, &sd, &sector_size, &align_size);
			if (rv < 0)
				break;
		}

		space.sector_size = sector_size;
		space.align_size = align_size;

		rv = delta_lease_acquire(task, &space, &sd,
					 ls->name,
					 our_host_name,
					 ls->host_id,
					 &leader);
		break;
	case ACT_RENEW_ID:
		if (!sector_size || !align_size) {
			rv = direct_read_leader_sizes(task, &sd, &sector_size, &align_size);
			if (rv < 0)
				break;
		}

		space.sector_size = sector_size;
		space.align_size = align_size;

		rv = delta_lease_leader_read(task, sector_size, io_timeout, &sd,
					     ls->name,
					     ls->host_id,
					     &leader,
					     "direct_renew");
		if (rv < 0)
			return rv;

		rv = delta_lease_renew(task, &space, &sd,
				       ls->name,
				       bitmap,
				       NULL,
				       -1,
				       &read_result,
				       0,
				       &leader,
				       &leader,
				       &rd_ms, &wr_ms);
		break;
	case ACT_RELEASE_ID:
		if (!sector_size || !align_size) {
			rv = direct_read_leader_sizes(task, &sd, &sector_size, &align_size);
			if (rv < 0)
				break;
		}

		space.sector_size = sector_size;
		space.align_size = align_size;

		rv = delta_lease_leader_read(task, sector_size, io_timeout, &sd,
					     ls->name,
					     ls->host_id,
					     &leader,
					     "direct_release");
		if (rv < 0)
			return rv;

		rv = delta_lease_release(task, &space, &sd,
					 ls->name,
					 &leader,
					 &leader);
		break;
	case ACT_READ_LEADER:
		if (!sector_size || !align_size) {
			rv = direct_read_leader_sizes(task, &sd, &sector_size, &align_size);
			if (rv < 0)
				break;
		}

		rv = delta_lease_leader_read(task, sector_size, io_timeout, &sd,
					     ls->name,
					     ls->host_id,
					     &leader,
					     "direct_read");
		break;
	case ACT_WRITE_LEADER:
		rv = delta_lease_leader_clobber(task, io_timeout, &sd,
					        ls->host_id,
					        leader_in,
					        "direct_clobber");
	}

	close_disks(&sd, 1);

	if (rv == SANLK_OK)
		rv = 0;

	if (leader_ret)
		memcpy(leader_ret, &leader, sizeof(struct leader_record));

	return rv;
}

/* 
 * sanlock direct acquire_id|release_id|renew_id -s LOCKSPACE
 *
 * should be the equivalent of what the daemon would do for
 * sanlock client add_lockspace|rem_lockspace -s LOCKSPACE
 */

int direct_acquire_id(struct task *task, int io_timeout, struct sanlk_lockspace *ls,
		      char *our_host_name)
{
	return do_delta_action(ACT_ACQUIRE_ID, task, io_timeout, ls, our_host_name, NULL, NULL);
}

int direct_release_id(struct task *task, int io_timeout, struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_RELEASE_ID, task, io_timeout, ls, NULL, NULL, NULL);
}

int direct_renew_id(struct task *task, int io_timeout, struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_RENEW_ID, task, io_timeout, ls, NULL, NULL, NULL);
}

int direct_align(struct sync_disk *disk)
{
	if (disk->sector_size == 512)
		return 1024 * 1024;
	else if (disk->sector_size == 4096)
		return 8 * 1024 * 1024;
	else
		return -EINVAL;
}

/* io_timeout is written to leader record and used for the write call itself */
int direct_write_lockspace(struct task *task, struct sanlk_lockspace *ls,
			   uint32_t io_timeout)
{
	if (!ls)
		return -1;

	return do_delta_action(ACT_DIRECT_INIT, task, io_timeout, ls, NULL, NULL, NULL);
}

int direct_write_resource(struct task *task, struct sanlk_resource *res,
			  int num_hosts, int write_clear)
{
	if (!res)
		return -1;

	if (!res->num_disks)
		return -ENODEV;

	if (!res->disks[0].path[0])
		return -ENODEV;

	return do_paxos_action(ACT_DIRECT_INIT, task, 0, res,
			       num_hosts, write_clear,
			       0, 0,
			       NULL, NULL);
}

int direct_read_leader(struct task *task,
		       int io_timeout,
		       struct sanlk_lockspace *ls,
		       struct sanlk_resource *res,
		       struct leader_record *leader_ret)
{
	int rv = -1;

	if (ls && ls->host_id_disk.path[0])
		rv = do_delta_action(ACT_READ_LEADER, task, io_timeout, ls, NULL, NULL, leader_ret);

	else if (res)
		rv = do_paxos_action(ACT_READ_LEADER, task, io_timeout, res,
				     0, 0,
				     0, 0,
				     NULL, leader_ret);
	return rv;
}

int direct_write_leader(struct task *task,
		        int io_timeout,
		        struct sanlk_lockspace *ls,
		        struct sanlk_resource *res,
			struct leader_record *leader)
{
	int rv = -1;

	if (ls && ls->host_id_disk.path[0]) {
		rv = do_delta_action(ACT_WRITE_LEADER, task, io_timeout, ls, NULL, leader, NULL);

	} else if (res) {
		rv = do_paxos_action(ACT_WRITE_LEADER, task, io_timeout, res,
				     0, 0,
				     0, 0,
				     leader, NULL);
	}

	return rv;
}

int test_id_bit(int host_id, char *bitmap);

int direct_dump(struct task *task, char *dump_path, int force_mode)
{
	char *data, *bitmap;
	char *colon1 = NULL, *colon2 = NULL, *off_str = NULL, *size_str = NULL, *m;
	uint32_t magic;
	struct rindex_header *rh_end;
	struct rindex_header *rh;
	struct rindex_header rh_in;
	struct rindex_entry *re_end;
	struct rindex_entry *re;
	struct rindex_entry re_in;
	struct leader_record *lr_end;
	struct leader_record *lr;
	struct leader_record lr_in;
	struct request_record rr;
	struct mode_block mb;
	struct sync_disk sd;
	struct paxos_dblock dblock;
	char sname[NAME_ID_SIZE+1];
	char rname[NAME_ID_SIZE+1];
	uint64_t sector_nr;
	uint64_t start_offset = 0;
	uint64_t dump_size = 0;
	uint64_t end_sector_nr = 0;
	int sector_size = 0;
	int align_size = 0;
	int sector_count, datalen, max_hosts;
	int i, j, rv, b;

	memset(&sd, 0, sizeof(struct sync_disk));

	/*
	 * /path[:<offset>[:<size>]]
	 *
	 * If path contains a colon, the user would escape it with \\, e.g.
	 * device named /dev/foo:32 using offset 0 and lenth 1M would be
	 * /dev/foo\\:32:0:1M
	 */

	for (i = 0; i < strlen(dump_path); i++) {
		if (dump_path[i] == '\\') {
			i++;
			continue;
		}

		if (dump_path[i] == ':') {
			if (!colon1)
				colon1 = &dump_path[i];
			else if (!colon2)
				colon2 = &dump_path[i];
		}
	}

	if (colon1) {
		*colon1 = '\0';
		off_str = colon1 + 1;

		if (colon2) {
			*colon2 = '\0';
			size_str = colon2 + 1;
		}

		if ((m = strchr(off_str, 'M'))) {
			*m = '\0';
			start_offset = atoll(off_str) * 1024 * 1024;
		} else {
                        start_offset = atoll(off_str);
		}

		if (size_str) {
			if ((m = strchr(size_str, 'M'))) {
				*m = '\0';
				dump_size = atoll(size_str) * 1024 * 1024;
			} else {
				dump_size = atoll(size_str);
			}
		}
	}

	if (start_offset % 1048576)
		printf("WARNING: dump offset should be a multiple of 1048576 bytes.\n");

	sanlock_path_import(sd.path, dump_path, sizeof(sd.path));

	sd.fd = -1;

	rv = open_disk(&sd);
	if (rv < 0) {
		printf("Device %s not found.\n", sd.path);
		return -ENODEV;
	}

	if (com.sector_size)
		sector_size = com.sector_size;
        if (com.align_size)
                align_size = com.align_size;

	if (!sector_size || !align_size) {
		sd.offset = start_offset;
		for (i = 0; i < 1024; i++) {
			rv = direct_read_leader_sizes(task, &sd, &sector_size, &align_size);
			if (sector_size && align_size)
				break;

			/*
			 * search for a data structure that contains sector_size/align_size
			 * every 1MB, up to 1GB or dump_size.
			 */
			sd.offset += 1048576;

			if (dump_size && (sd.offset >= (start_offset + dump_size)))
				break;
		}
		if (!sector_size || !align_size) {
			printf("Cannot find sector_size and align_size, set with -A and -Z.\n");
			goto out_close;
		}
	}

	max_hosts = size_to_max_hosts(sector_size, align_size);

	sector_count = align_size / sector_size;
	datalen = align_size;

	data = malloc(datalen);
	if (!data) {
		rv = -ENOMEM;
		goto out_close;
	}
	memset(data, 0, datalen);

	printf("%8s %36s %48s %10s %4s %4s %s",
	       "offset",
	       "lockspace",
	       "resource",
	       "timestamp",
	       "own",
	       "gen",
	       "lver");

	if (force_mode)
		printf("/req/mode");

	printf("\n");

	sd.offset = start_offset;
	sector_nr = 0;
	if (dump_size)
		end_sector_nr = dump_size / sector_size;

	while (end_sector_nr == 0 || sector_nr < end_sector_nr) {
		memset(sname, 0, sizeof(rname));
		memset(rname, 0, sizeof(rname));
		memset(data, 0, sector_size);

		rv = read_sectors(&sd, sector_size, sector_nr, sector_count, data, datalen,
				  task, com.io_timeout, "dump");

		magic_in(data, &magic);

		if (magic == DELTA_DISK_MAGIC) {
			lr_end = (struct leader_record *)data;
			leader_record_in(lr_end, &lr_in);
			lr = &lr_in;

			for (i = 0; i < sector_count; i++) {
				lr_end = (struct leader_record *)(data + (i * sector_size));

				if (!lr_end->magic)
					continue;

				leader_record_in(lr_end, &lr_in);
				lr = &lr_in;

				/* has never been acquired, don't print */
				if (!lr->owner_id && !lr->owner_generation)
					continue;

				strncpy(sname, lr->space_name, NAME_ID_SIZE);
				strncpy(rname, lr->resource_name, NAME_ID_SIZE);

				printf("%08llu %36s %48s %010llu %04llu %04llu",
					(unsigned long long)(start_offset + ((sector_nr + i) * sector_size)),
					sname, rname,
					(unsigned long long)lr->timestamp,
					(unsigned long long)lr->owner_id,
					(unsigned long long)lr->owner_generation);

				if (force_mode) {
					bitmap = (char *)lr_end + LEADER_RECORD_MAX;
					for (b = 0; b < max_hosts; b++) {
						if (test_id_bit(b+1, bitmap))
							printf(" %d", b+1);
					}
				}
				printf("\n");
			}
		} else if (magic == PAXOS_DISK_MAGIC) {
			lr_end = (struct leader_record *)data;
			leader_record_in(lr_end, &lr_in);
			lr = &lr_in;

			strncpy(sname, lr->space_name, NAME_ID_SIZE);
			strncpy(rname, lr->resource_name, NAME_ID_SIZE);

			printf("%08llu %36s %48s %010llu %04llu %04llu %llu",
			       (unsigned long long)(start_offset + (sector_nr * sector_size)),
			       sname, rname,
			       (unsigned long long)lr->timestamp,
			       (unsigned long long)lr->owner_id,
			       (unsigned long long)lr->owner_generation,
			       (unsigned long long)lr->lver);

			if (force_mode) {
				struct request_record *rr_end = (struct request_record *)(data + sector_size);
				request_record_in(rr_end, &rr);
				printf("/%llu/%u",
				       (unsigned long long)rr.lver, rr.force_mode);
			}
			printf("\n");

			for (i = 0; i < lr->num_hosts; i++) {
				char *pd_end = data + ((2 + i) * sector_size);
				struct mode_block *mb_end = (struct mode_block *)(pd_end + MBLOCK_OFFSET);

				if (force_mode > 1) {
					paxos_dblock_in((struct paxos_dblock *)pd_end, &dblock);

					if (dblock.mbal || dblock.inp || dblock.lver) {
						printf("dblock[%04d] mbal %llu bal %llu inp %llu inp2 %llu inp3 %llu lver %llu sum %x\n",
						       i,
						       (unsigned long long)dblock.mbal,
					               (unsigned long long)dblock.bal,
					               (unsigned long long)dblock.inp,
					               (unsigned long long)dblock.inp2,
					               (unsigned long long)dblock.inp3,
					               (unsigned long long)dblock.lver,
					               dblock.checksum);
					}
				}

				mode_block_in(mb_end, &mb);

				if (!(mb.flags & MBLOCK_SHARED))
					continue;

				printf("                                                                                                          ");
				printf("%04u %04llu SH\n", i+1, (unsigned long long)mb.generation);
			}
		} else if (magic == RINDEX_DISK_MAGIC) {
			rh_end = (struct rindex_header *)data;
			rindex_header_in(rh_end, &rh_in);
			rh = &rh_in;

			strncpy(sname, rh->lockspace_name, NAME_ID_SIZE);

			printf("%08llu %36s rindex_header 0x%x %d %u %llu\n",
			       (unsigned long long)(start_offset + (sector_nr * sector_size)),
			       sname,
			       rh->flags, rh->sector_size, rh->max_resources,
			       (unsigned long long)rh->rx_offset);

			if (!force_mode)
				goto next;

			/* i begins with 1 to skip the first sector of the rindex which holds the header */

			for (i = 1; i < sector_count; i++) {
				int entry_size = sizeof(struct rindex_entry);
				int entries_per_sector = sector_size / entry_size;

				for (j = 0; j < entries_per_sector; j++) {
					re_end = (struct rindex_entry *)(data + (i * sector_size) + (j * entry_size));
					rindex_entry_in(re_end, &re_in);
					re = &re_in;

					if (!re->res_offset && !re->name[0])
						continue;

					printf("%08llu %36s rentry %s %llu\n",
			       			(unsigned long long)(start_offset + ((sector_nr * sector_size) + (i * sector_size) + (j * entry_size))),
			       			sname,
						re->name, (unsigned long long)re->res_offset);
				}
			}


		} else {
			if (end_sector_nr == 0)
				break;
		}
 next:
		sector_nr += sector_count;
	}

	rv = 0;
	free(data);
 out_close:
	close_disks(&sd, 1);
	return rv;
}

int direct_next_free(struct task *task, char *path)
{
	char *data;
	char *colon, *off_str;
	struct leader_record *lr_end;
	struct leader_record lr;
	struct sync_disk sd;
	uint64_t sector_nr;
	int sector_size, sector_count, datalen, align_size;
	int rv;

	memset(&sd, 0, sizeof(struct sync_disk));

	colon = strstr(path, ":");
	if (colon) {
		off_str = colon + 1;
		*colon = '\0';
		sd.offset = atoll(off_str);
	}

	strncpy(sd.path, path, SANLK_PATH_LEN);
	sd.fd = -1;

	rv = open_disk(&sd);
	if (rv < 0)
		return -ENODEV;

	if (com.sector_size)
		sector_size = com.sector_size;
        if (com.align_size)
                align_size = com.align_size;

	if (!sector_size || !align_size) {
		rv = direct_read_leader_sizes(task, &sd, &sector_size, &align_size);
		if (rv < 0)
			return rv;
	}

	sector_count = align_size / sector_size;
	datalen = sector_size;

	data = malloc(datalen);
	if (!data) {
		rv = -ENOMEM;
		goto out_close;
	}

	sector_nr = 0;
	rv = -ENOSPC;

	while (1) {
		memset(data, 0, sector_size);

		rv = read_sectors(&sd, sector_size, sector_nr, 1, data, datalen,
				  task, com.io_timeout, "next_free");

		lr_end = (struct leader_record *)data;

		leader_record_in(lr_end, &lr);

		if (lr.magic != DELTA_DISK_MAGIC && lr.magic != PAXOS_DISK_MAGIC && lr.magic != RINDEX_DISK_MAGIC) {
			printf("%llu\n", (unsigned long long)(sector_nr * sector_size));
			rv = 0;
			goto out_free;
		}

		sector_nr += sector_count;
	}
 out_free:
	free(data);
 out_close:
	close_disks(&sd, 1);
	return rv;
}


int direct_rindex_format(struct task *task, struct sanlk_rindex *ri)
{
	return rindex_format(task, ri);
}

int direct_rindex_rebuild(struct task *task, struct sanlk_rindex *ri,
			  uint32_t cmd_flags)
{
	return rindex_rebuild(task, ri, cmd_flags | SANLK_RX_NO_LOCKSPACE);
}

int direct_rindex_lookup(struct task *task, struct sanlk_rindex *ri,
			 struct sanlk_rentry *re, uint32_t cmd_flags)
{
	struct sanlk_rentry re_ret;
	int rv;

	rv = rindex_lookup(task, ri, re, &re_ret, cmd_flags | SANLK_RX_NO_LOCKSPACE);

	if (!rv)
		memcpy(re, &re_ret, sizeof(re_ret));

	return rv;
}

int direct_rindex_update(struct task *task, struct sanlk_rindex *ri,
			 struct sanlk_rentry *re, uint32_t cmd_flags)
{
	struct sanlk_rentry re_ret;
	int rv;

	rv = rindex_update(task, ri, re, &re_ret, cmd_flags | SANLK_RX_NO_LOCKSPACE);

	if (!rv)
		memcpy(re, &re_ret, sizeof(re_ret));

	return rv;
}

