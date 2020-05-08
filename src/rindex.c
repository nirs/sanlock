/*
 * Copyright 2018 Red Hat, Inc.
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
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sanlock_internal.h"
#include "sanlock_admin.h"
#include "diskio.h"
#include "ondisk.h"
#include "log.h"
#include "paxos_lease.h"
#include "lockspace.h"
#include "resource.h"
#include "task.h"
#include "timeouts.h"
#include "rindex_disk.h"
#include "rindex.h"
#include "paxos_dblock.h"
#include "leader.h"

struct rindex_info {
	struct sanlk_rindex *ri;    /* point to sanlk_rindex */
	struct sync_disk *disk;     /* points to sanlk_rindex.disk */
	struct rindex_header header;
};

/* this token is used for paxos_lease_acquire/release */

static struct token *setup_rindex_token(struct rindex_info *rx,
				        int sector_size,
				        int align_size,
					struct space_info *spi)
{
	struct token *token;
	int token_len;

	token_len = sizeof(struct token) + sizeof(struct sync_disk);
	token = malloc(token_len);
	if (!token)
		return NULL;

	memset(token, 0, token_len);
	memcpy(token->r.lockspace_name, rx->ri->lockspace_name, SANLK_NAME_LEN);
	strcpy(token->r.name, "rindex_lease");
	token->sector_size = sector_size;
	token->align_size = align_size;
	token->io_timeout = spi ? spi->io_timeout : DEFAULT_IO_TIMEOUT;
	token->r.num_disks = 1;
	token->r.flags |= sanlk_res_sector_size_to_flag(sector_size);
	token->r.flags |= sanlk_res_align_size_to_flag(align_size);

	token->disks = (struct sync_disk *)&token->r.disks[0]; /* shorthand */
	memcpy(token->disks[0].path, rx->disk->path, SANLK_PATH_LEN);
	token->disks[0].offset = rx->disk->offset + align_size;
	token->disks[0].fd = rx->disk->fd;

	if (spi) {
		token->host_id = spi->host_id;
		token->host_generation = spi->host_generation;
		token->space_id = spi->space_id;
		token->res_id = 1;
	}

	return token;
}

/* this token is only used for paxos_lease_init */

static struct token *setup_resource_token(struct rindex_info *rx,
					  char *res_name,
				          int sector_size,
					  int align_size,
					  struct space_info *spi)
{
	struct token *token;
	int token_len;

	token_len = sizeof(struct token) + sizeof(struct sync_disk);
	token = malloc(token_len);
	if (!token)
		return NULL;

	memset(token, 0, token_len);
	memcpy(token->r.lockspace_name, rx->ri->lockspace_name, SANLK_NAME_LEN);
	memcpy(token->r.name, res_name, SANLK_NAME_LEN);
	token->sector_size = sector_size;
	token->align_size = align_size;
	token->io_timeout = spi ? spi->io_timeout : DEFAULT_IO_TIMEOUT;
	token->r.num_disks = 1;
	token->r.flags |= sanlk_res_sector_size_to_flag(sector_size);
	token->r.flags |= sanlk_res_align_size_to_flag(align_size);

	token->disks = (struct sync_disk *)&token->r.disks[0]; /* shorthand */
	memcpy(token->disks[0].path, rx->disk->path, SANLK_PATH_LEN);
	token->disks[0].fd = rx->disk->fd;
	/* there is no offset yet, it is found and set later */

	return token;
}

/* max resource entries supported by each combination of sector/align size */

static uint32_t size_to_max_resources(int sector_size, int align_size)
{
	if ((sector_size == 512) && (align_size == ALIGN_SIZE_1M))
		return 16000;
	if ((sector_size == 4096) && (align_size == ALIGN_SIZE_1M))
		return 16000;
	if ((sector_size == 4096) && (align_size == ALIGN_SIZE_2M))
		return 32000;
	if ((sector_size == 4096) && (align_size == ALIGN_SIZE_4M))
		return 64000;
	if ((sector_size == 4096) && (align_size == ALIGN_SIZE_8M))
		return 128000;

	/* this shouldn't happen */
	return 16000;
}

static int search_entries(struct rindex_info *rx, char *rindex_iobuf,
		          uint64_t *ent_offset, uint64_t *res_offset,
			  int find_free, char *find_name)
{
	struct rindex_entry re;
	struct rindex_entry *re_end;
	uint64_t entry_offset_in_rindex;
	uint32_t max_resources = rx->header.max_resources;
	int sector_size = rx->header.sector_size;
	int align_size = rindex_header_align_size_from_flag(rx->header.flags);
	int i;

	if (!max_resources)
		max_resources = size_to_max_resources(sector_size, align_size);

	for (i = 0; i < max_resources; i++) {
		/* skip first sector which holds header */
		entry_offset_in_rindex = sector_size + (i * sizeof(struct rindex_entry));

		re_end = (struct rindex_entry *)(rindex_iobuf + entry_offset_in_rindex);

		rindex_entry_in(re_end, &re);

		if (find_free && (!re.res_offset && !re.name[0])) {
			*ent_offset = entry_offset_in_rindex;
			*res_offset = rx->disk->offset + (2 * align_size) + (i * align_size);
			return 0;
		}

		if (find_name && re.name[0] && !strncmp(re.name, find_name, SANLK_NAME_LEN)) {
			*ent_offset = entry_offset_in_rindex;
			*res_offset = rx->disk->offset + (2 * align_size) + (i * align_size);
			return 0;
		}
	}

	return -ENOENT;
}

static int update_rindex(struct task *task,
		         struct space_info *spi,
		         struct rindex_info *rx,
		         char *rindex_iobuf,
		         struct sanlk_rentry *re,
		         uint64_t ent_offset,
			 uint64_t res_offset,
			 int delete)
{
	struct rindex_entry re_new;
	struct rindex_entry re_end;
	char *sector_iobuf;
	char **p_iobuf;
	uint32_t sector_offset;
	uint32_t entry_offset_in_sector;
	int sector_size = rx->header.sector_size;
	int iobuf_len;
	int rv;

	/*
	 * ent_offset is the offset (in bytes) from the start of the rindex to
	 * the entry being updated.  (This includes the size of the header
	 * sector; no offsets are calculated from the end of the header
	 * sector.)
	 *
	 * sector_offset is the offset (in bytes) from the start of the rindex
	 * to the sector containing ent_offset.  The entire sector is written.
	 *
	 * entry_offset_in_sector is the offset (in bytes) from the start of
	 * the target sector to the entry being updated.
	 */

	sector_offset = (ent_offset / sector_size) * sector_size;
	entry_offset_in_sector = ent_offset % sector_size;

	iobuf_len = sector_size;

	p_iobuf = &sector_iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv)
		return rv;

	memset(sector_iobuf, 0, iobuf_len);

	memset(&re_new, 0, sizeof(struct rindex_entry));

	if (!delete) {
		memcpy(re_new.name, re->name, NAME_ID_SIZE);
		re_new.res_offset = res_offset;
	}

	rindex_entry_out(&re_new, &re_end);

	/* initialize new sector with existing index content */
	memcpy(sector_iobuf, rindex_iobuf + sector_offset, sector_size);

	/* replace the specific entry */
	memcpy(sector_iobuf + entry_offset_in_sector, &re_end, sizeof(struct rindex_entry));

	rv = write_iobuf(rx->disk->fd, rx->disk->offset + sector_offset, sector_iobuf, iobuf_len, task, spi->io_timeout, NULL);

	if (rv != SANLK_AIO_TIMEOUT)
		free(sector_iobuf);

	return rv;
}

static int read_rindex(struct task *task,
		       struct space_info *spi,
		       struct rindex_info *rx,
		       char **rindex_iobuf_ret)
{
	char *iobuf;
	char **p_iobuf;
	int align_size = rindex_header_align_size_from_flag(rx->header.flags);
	int iobuf_len;
	int rv;

	iobuf_len = align_size;

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv) {
		return rv;
	}

	memset(iobuf, 0, iobuf_len);

	rv = read_iobuf(rx->disk->fd, rx->disk->offset, iobuf, iobuf_len, task, spi->io_timeout, NULL);
	if (rv < 0) {
		free(iobuf);
		return rv;
	}

	*rindex_iobuf_ret = iobuf;
	return rv;
}

static int read_rindex_header(struct task *task,
			      struct space_info *spi,
			      struct rindex_info *rx)
{
	struct rindex_header *rh_end;
	char *iobuf;
	char **p_iobuf;
	int sector_size = spi->sector_size;
	int io_timeout = spi->io_timeout;
	int iobuf_len;
	int rv;

	if (!sector_size)
		sector_size = 4096;
	if (!io_timeout) {
		io_timeout = DEFAULT_IO_TIMEOUT;
		spi->io_timeout = io_timeout;
	}

	/*
	 * lockspace sector_size will usually be the same as rindex sector_size.
	 * use the lockspace sector size for reading the rindex header which
	 * officially gives us the rindex sector_size.
	 */

	iobuf_len = sector_size;

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv)
		return -ENOMEM;

	rv = read_iobuf(rx->disk->fd, rx->disk->offset, iobuf, iobuf_len, task, io_timeout, NULL);
	if (rv < 0)
		goto out;

	rh_end = (struct rindex_header *)iobuf;

	rindex_header_in(rh_end, &rx->header);

	if (rx->header.magic != RINDEX_DISK_MAGIC) {
		log_debug("rindex header bad magic %x vs %x on %s:%llu",
			  rx->header.magic,
			  RINDEX_DISK_MAGIC,
			  rx->disk->path,
			  (unsigned long long)rx->disk->offset);
		rv = SANLK_RINDEX_MAGIC;
		goto out;
	}

	if ((rx->header.version & 0xFFFF0000) != RINDEX_DISK_VERSION_MAJOR) {
		log_debug("rindex header bad version %x vs %x on %s:%llu",
			  rx->header.version,
			  RINDEX_DISK_VERSION_MAJOR,
			  rx->disk->path,
			  (unsigned long long)rx->disk->offset);
		rv = SANLK_RINDEX_VERSION;
		goto out;
	}

	if (strcmp(rx->header.lockspace_name, rx->ri->lockspace_name)) {
		log_debug("rindex header bad lockspace_name %.48s vs %.48s on %s:%llu",
			  rx->header.lockspace_name,
			  rx->ri->lockspace_name,
			  rx->disk->path,
			  (unsigned long long)rx->disk->offset);
		rv = SANLK_RINDEX_LOCKSPACE;
		goto out;
	}

	if (rx->header.rx_offset != rx->disk->offset) {
		log_debug("rindex header bad offset %llu on %s:%llu",
			  (unsigned long long)rx->header.rx_offset,
			  rx->disk->path,
			  (unsigned long long)rx->disk->offset);
		rv = SANLK_RINDEX_OFFSET;
		goto out;
	}
out:
	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);

	return rv;
}

/*
 * format rindex: write new rindex header, and initialize internal paxos lease
 * for protecting the rindex.
 */

int rindex_format(struct task *task, struct sanlk_rindex *ri)
{
	struct rindex_info rx;
	struct rindex_header rh;
	struct rindex_header rh_end;
	struct token *token;
	char *iobuf;
	char **p_iobuf;
	uint32_t max_resources;
	uint32_t max_resources_limit;
	int write_io_timeout;
	int sector_size = 0;
	int align_size = 0;
	int max_hosts = 0;
	int iobuf_len;
	int rv;

	memset(&rx, 0, sizeof(rx));
	rx.ri = ri;
	rx.disk = (struct sync_disk *)&ri->disk;

	rv = open_disk(rx.disk);
	if (rv < 0) {
		log_error("rindex_format open failed %d %s", rv, rx.disk->path);
		return rv;
	}

	rv = sizes_from_flags(ri->flags, &sector_size, &align_size, &max_hosts, "RIF");
	if (rv)
		return rv;

	if (!sector_size) {
		/* sector/align flags were not set, use historical defaults */
		sector_size = rx.disk->sector_size;
		align_size = sector_size_to_align_size_old(sector_size);
		max_hosts = DEFAULT_MAX_HOSTS;
	}

	/*
	 * When unspecified, default to 4096 to limit the amount of searching.
	 */
	max_resources = rx.ri->max_resources;
	if (!max_resources)
		max_resources = 4096;
	max_resources_limit = size_to_max_resources(sector_size, align_size);
	if (max_resources > max_resources_limit)
		max_resources = max_resources_limit;

	log_debug("rindex_format %.48s:%s:%llu %d %d max_res %u",
		  rx.ri->lockspace_name, rx.disk->path,
		  (unsigned long long)rx.disk->offset,
		  sector_size, align_size, max_resources);

	iobuf_len = align_size;

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv)
		goto out_close;

	memset(iobuf, 0, iobuf_len);

	memset(&rh, 0, sizeof(struct rindex_header));
	rh.magic = RINDEX_DISK_MAGIC;
	rh.version = RINDEX_DISK_VERSION_MAJOR | RINDEX_DISK_VERSION_MINOR;
	rh.flags = rindex_header_align_flag_from_size(align_size);
	rh.sector_size = sector_size;
	rh.max_resources = max_resources;
	rh.rx_offset = rx.disk->offset;
	strncpy(rh.lockspace_name, rx.ri->lockspace_name, NAME_ID_SIZE);

	memset(&rh_end, 0, sizeof(struct rindex_header));
	rindex_header_out(&rh, &rh_end);

	memcpy(iobuf, &rh_end, sizeof(struct rindex_header));

	if (com.write_init_io_timeout)
		write_io_timeout = com.write_init_io_timeout;
	else
		write_io_timeout = DEFAULT_IO_TIMEOUT;

	rv = write_iobuf(rx.disk->fd, rx.disk->offset, iobuf, iobuf_len, task, write_io_timeout, NULL);
	if (rv < 0) {
		log_error("rindex_format write failed %d %s", rv, rx.disk->path);
		goto out_iobuf;
	}

	token = setup_rindex_token(&rx, sector_size, align_size, NULL);
	if (!token) {
		rv = -ENOMEM;
		goto out_iobuf;
	}

	rv = paxos_lease_init(task, token, 0, 0);
	if (rv < 0) {
		log_error("rindex_format lease init failed %d", rv);
		goto out_token;
	}
	
	rv = 0;

 out_token:
	free(token);
 out_iobuf:
	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);
 out_close:
	close_disks(rx.disk, 1);
	return rv;
}

int rindex_create(struct task *task, struct sanlk_rindex *ri,
		  struct sanlk_rentry *re, struct sanlk_rentry *re_ret,
		  uint32_t max_hosts, uint32_t num_hosts)
{
	struct rindex_info rx;
	struct space_info spi;
	struct leader_record leader;
	struct paxos_dblock dblock;
	struct token *rx_token;
	struct token *res_token;
	char *rindex_iobuf = NULL;
	uint64_t ent_offset, res_offset;
	int sector_size, align_size;
	int rv;

	memset(&rx, 0, sizeof(rx));
	rx.ri = ri;
	rx.disk = (struct sync_disk *)&ri->disk;

	rv = open_disk(rx.disk);
	if (rv < 0) {
		log_error("rindex_create open failed %d %s", rv, rx.disk->path);
		return rv;
	}

	/*
	 * Allows only one rindex op for a given lockspace at a time.
	 * If there's already one in progress, this returns EBUSY.
	 * Also collects lockspace info at the same time.
	 */
	memset(&spi, 0, sizeof(spi));

	rv = lockspace_begin_rindex_op(ri->lockspace_name, RX_OP_CREATE, &spi);
	if (rv < 0) {
		log_error("rindex_create lockspace not available %d %.48s", rv, ri->lockspace_name);
		goto out_close;
	}

	rv = read_rindex_header(task, &spi, &rx);
	if (rv < 0) {
		log_error("rindex_create failed to read rindex header %d on %s:%llu",
			  rv, rx.disk->path, (unsigned long long)rx.disk->offset);
		goto out_clear;
	}

	sector_size = rx.header.sector_size;
	align_size = rindex_header_align_size_from_flag(rx.header.flags);

	log_debug("rindex_create %.48s:%s:%llu %d %d max_res %u",
		  rx.ri->lockspace_name, rx.disk->path,
		  (unsigned long long)rx.disk->offset,
		  sector_size, align_size, rx.header.max_resources);

	/* used to acquire the internal paxos lease protecting the rindex */
	rx_token = setup_rindex_token(&rx, sector_size, align_size, &spi);
	if (!rx_token) {
		rv = -ENOMEM;
		goto out_clear;
	}

	/* used to initialize the new paxos lease for the resource */
	res_token = setup_resource_token(&rx, re->name, sector_size, align_size, &spi);
	if (!res_token) {
		free(rx_token);
		rv = -ENOMEM;
		goto out_clear;
	}

	log_debug("rindex_create acquire offset %llu sector_size %d align_size %d",
		  (unsigned long long)rx_token->disks[0].offset,
		  rx_token->sector_size, rx_token->align_size);

	rv = paxos_lease_acquire(task, rx_token,
			         PAXOS_ACQUIRE_OWNER_NOWAIT | PAXOS_ACQUIRE_QUIET_FAIL,
			         &leader, &dblock, 0, 0);
	if (rv < 0) {
		/* TODO: sleep and retry if this fails because it's held by another host? */
		log_error("rindex_create failed to acquire rindex lease %d", rv);
		goto out_token;
	}

	rv = read_rindex(task, &spi, &rx, &rindex_iobuf);
	if (rv < 0) {
		log_error("rindex_create failed to read rindex %d", rv);
		goto out_lease;
	}

	rv = search_entries(&rx, rindex_iobuf, &ent_offset, &res_offset, 1, NULL);
	if (rv < 0) {
		log_error("rindex_create failed to find free offset %d", rv);
		goto out_iobuf;
	}

	/* set the location of the new paxos lease */

	log_debug("rindex_create found offset %llu for %.48s:%.48s",
		  (unsigned long long)res_offset,
		  rx.ri->lockspace_name, re->name);

	res_token->disks[0].offset = res_offset;

	/* write the new paxos lease */

	rv = paxos_lease_init(task, res_token, num_hosts, 0);
	if (rv < 0) {
		log_error("rindex_create failed to init new lease %d", rv);
		goto out_iobuf;
	}

	rv = update_rindex(task, &spi, &rx, rindex_iobuf, re, ent_offset, res_offset, 0);
	if (rv < 0) {
		log_error("rindex_create failed to update rindex %d", rv);
		goto out_iobuf;
	}

	log_debug("rindex_create updated rindex entry %llu for %.48s %llu",
		  (unsigned long long)ent_offset,
		  re->name,
		  (unsigned long long)res_offset);

	re_ret->offset = res_offset;
	rv = 0;

 out_iobuf:
	free(rindex_iobuf);
 out_lease:
	paxos_lease_release(task, rx_token, NULL, &leader, &leader);
 out_token:
	free(rx_token);
	free(res_token);
 out_clear:
	lockspace_clear_rindex_op(ri->lockspace_name);
 out_close:
	close_disks(rx.disk, 1);
	return rv;
}

/*
 * clear the rindex entry for a given resource lease name and offset
 * first the rentry is cleared, then the resource lease is cleared
 */

int rindex_delete(struct task *task, struct sanlk_rindex *ri,
		  struct sanlk_rentry *re, struct sanlk_rentry *re_ret)
{
	struct rindex_info rx;
	struct space_info spi;
	struct leader_record leader;
	struct paxos_dblock dblock;
	struct token *rx_token;
	struct token *res_token;
	char *rindex_iobuf = NULL;
	uint64_t res_offset = re->offset;
	uint64_t ent_offset;
	int sector_size, align_size;
	int rv;

	memset(&rx, 0, sizeof(rx));
	rx.ri = ri;
	rx.disk = (struct sync_disk *)&ri->disk;

	rv = open_disk(rx.disk);
	if (rv < 0) {
		log_error("rindex_create open failed %d %s", rv, rx.disk->path);
		return rv;
	}

	/*
	 * Allows only one rindex op for a given lockspace at a time.
	 * If there's already one in progress, this returns EBUSY.
	 * Also collects lockspace info at the same time.
	 */
	memset(&spi, 0, sizeof(spi));

	rv = lockspace_begin_rindex_op(ri->lockspace_name, RX_OP_DELETE, &spi);
	if (rv < 0) {
		log_error("rindex_delete lockspace not available %d %.48s", rv, ri->lockspace_name);
		goto out_close;
	}

	rv = read_rindex_header(task, &spi, &rx);
	if (rv < 0) {
		log_error("rindex_delete failed to read rindex header %d on %s:%llu",
			  rv, rx.disk->path, (unsigned long long)rx.disk->offset);
		goto out_clear;
	}

	sector_size = rx.header.sector_size;
	align_size = rindex_header_align_size_from_flag(rx.header.flags);

	/* resource lease locations must use the same alignment as the rindex */
	if (re->offset && (re->offset % align_size)) {
		rv = SANLK_RINDEX_OFFSET;
		goto out_clear;
	}

	/* used to acquire the internal paxos lease protecting the rindex */
	rx_token = setup_rindex_token(&rx, sector_size, align_size, &spi);
	if (!rx_token) {
		rv = -ENOMEM;
		goto out_clear;
	}

	/* used to write the cleared paxos lease for the resource */
	res_token = setup_resource_token(&rx, re->name, sector_size, align_size, &spi);
	if (!res_token) {
		free(rx_token);
		rv = -ENOMEM;
		goto out_clear;
	}

	rv = paxos_lease_acquire(task, rx_token,
			         PAXOS_ACQUIRE_OWNER_NOWAIT | PAXOS_ACQUIRE_QUIET_FAIL,
			         &leader, &dblock, 0, 0);
	if (rv < 0) {
		/* TODO: sleep and retry if this fails because it's held by another host? */
		log_error("rindex_create failed to acquire rindex lease %d", rv);
		goto out_token;
	}

	rv = read_rindex(task, &spi, &rx, &rindex_iobuf);
	if (rv < 0) {
		log_error("rindex_delete failed to read rindex %d", rv);
		goto out_lease;
	}

	/* find the entry */

	rv = search_entries(&rx, rindex_iobuf, &ent_offset, &res_offset, 0, re->name);
	if (rv < 0) {
		log_error("rindex_delete failed to find entry '%s': %d", re->name, rv);
		goto out_iobuf;
	}

	rv = update_rindex(task, &spi, &rx, rindex_iobuf, re, ent_offset, res_offset, 1);
	if (rv < 0) {
		log_error("rindex_delete failed to update rindex %d", rv);
		goto out_iobuf;
	}

	/* clear the paxos lease */

	res_token->disks[0].offset = res_offset;

	rv = paxos_lease_init(task, res_token, 0, 1);
	if (rv < 0) {
		log_error("rindex_delete failed to init new lease %d", rv);
		goto out_iobuf;
	}

	log_debug("rindex_delete updated rindex entry %llu for %.48s %llu",
		  (unsigned long long)ent_offset,
		  re->name,
		  (unsigned long long)res_offset);

	re_ret->offset = 0;

	rv = 0;

 out_iobuf:
	free(rindex_iobuf);
 out_lease:
	paxos_lease_release(task, rx_token, NULL, &leader, &leader);
 out_token:
	free(rx_token);
	free(res_token);
 out_clear:
	lockspace_clear_rindex_op(ri->lockspace_name);
 out_close:
	close_disks(rx.disk, 1);
	return rv;
}

int rindex_lookup(struct task *task, struct sanlk_rindex *ri,
		  struct sanlk_rentry *re, struct sanlk_rentry *re_ret, uint32_t cmd_flags)
{
	struct rindex_info rx;
	struct space_info spi;
	struct rindex_entry re_in;
	struct rindex_entry *re_end;
	char *rindex_iobuf = NULL;
	uint64_t ent_offset, res_offset;
	int entry_num;
	int sector_size, align_size;
	int nolock = cmd_flags & SANLK_RX_NO_LOCKSPACE;
	int rv;

	memset(&rx, 0, sizeof(rx));
	rx.ri = ri;
	rx.disk = (struct sync_disk *)&ri->disk;

	rv = open_disk(rx.disk);
	if (rv < 0) {
		return rv;
	}

	memset(&spi, 0, sizeof(spi));

	if (!nolock) {
		rv = lockspace_begin_rindex_op(ri->lockspace_name, RX_OP_LOOKUP, &spi);
		if (rv < 0) {
			goto out_close;
		}
	}

	rv = read_rindex_header(task, &spi, &rx);
	if (rv < 0) {
		goto out_clear;
	}

	sector_size = rx.header.sector_size;
	align_size = rindex_header_align_size_from_flag(rx.header.flags);

	rv = read_rindex(task, &spi, &rx, &rindex_iobuf);
	if (rv < 0) {
		goto out_clear;
	}

	if (re->offset && (re->offset % align_size)) {
		rv = SANLK_RINDEX_OFFSET;
		goto out_clear;
	}

	if (!re->name[0] && !re->offset) {
		/* find the first free resource lease offset */

		rv = search_entries(&rx, rindex_iobuf, &ent_offset, &res_offset, 1, NULL);
		if (rv < 0) {
			goto out_iobuf;
		}

		memset(re_ret->name, 0, SANLK_NAME_LEN);
		re_ret->offset = res_offset;
		rv = 0;

	} else if (!re->name[0] && re->offset) {
		/* find the name of the resource lease that the index has recorded
		   for the given resource lease offset */

		res_offset = re->offset;
		entry_num = (res_offset - rx.disk->offset - (2 * align_size)) / align_size;
		ent_offset = sector_size + (entry_num * sizeof(struct rindex_entry));

		re_end = (struct rindex_entry *)(rindex_iobuf + ent_offset);

		rindex_entry_in(re_end, &re_in);

		memcpy(re_ret->name, re_in.name, SANLK_NAME_LEN);
		re_ret->offset = res_offset;
		rv = 0;

	} else if (re->name[0] && !re->offset) {
		/* search the rindex entries for a given resource lease name and
		   if found return the offset of the resource lease */

		rv = search_entries(&rx, rindex_iobuf, &ent_offset, &res_offset, 0, re->name);
		if (rv < 0) {
			goto out_iobuf;
		}

		memcpy(re_ret->name, re->name, SANLK_NAME_LEN);
		re_ret->offset = res_offset;
		rv = 0;

	} else if (re->name[0] && re->offset) {
		/* find the name of the resource lease that the index has recorded
		   for the given resource lease offset, and if it doesn't match
		   the specified name, then it's an error */

		res_offset = re->offset;
		entry_num = (res_offset - rx.disk->offset - (2 * align_size)) / align_size;
		ent_offset = sector_size + (entry_num * sizeof(struct rindex_entry));

		re_end = (struct rindex_entry *)(rindex_iobuf + ent_offset);

		rindex_entry_in(re_end, &re_in);

		if (strncmp(re->name, re_in.name, SANLK_NAME_LEN))
			rv = SANLK_RINDEX_DIFF;
		else
			rv = 0;

		memcpy(re_ret->name, re_in.name, SANLK_NAME_LEN);
		re_ret->offset = res_offset;
	}


 out_iobuf:
	free(rindex_iobuf);
 out_clear:
	if (!nolock)
		lockspace_clear_rindex_op(ri->lockspace_name);
 out_close:
	close_disks(rx.disk, 1);
	return rv;
}

int rindex_update(struct task *task, struct sanlk_rindex *ri,
		  struct sanlk_rentry *re, struct sanlk_rentry *re_ret,
		  uint32_t cmd_flags)
{
	struct rindex_info rx;
	struct space_info spi;
	char *rindex_iobuf = NULL;
	uint64_t ent_offset, res_offset;
	int entry_num;
	int sector_size, align_size;
	int op_remove = 0, op_add = 0;
	int nolock = cmd_flags & SANLK_RX_NO_LOCKSPACE;
	int rv;

	memset(&rx, 0, sizeof(rx));
	rx.ri = ri;
	rx.disk = (struct sync_disk *)&ri->disk;

	rv = open_disk(rx.disk);
	if (rv < 0) {
		return rv;
	}

	memset(&spi, 0, sizeof(spi));

	if (!nolock) {
		rv = lockspace_begin_rindex_op(ri->lockspace_name, RX_OP_UPDATE, &spi);
		if (rv < 0) {
			goto out_close;
		}
	}

	rv = read_rindex_header(task, &spi, &rx);
	if (rv < 0) {
		goto out_clear;
	}

	rv = read_rindex(task, &spi, &rx, &rindex_iobuf);
	if (rv < 0) {
		goto out_clear;
	}

	sector_size = rx.header.sector_size;
	align_size = rindex_header_align_size_from_flag(rx.header.flags);

	if (re->offset && (re->offset % align_size)) {
		rv = SANLK_RINDEX_OFFSET;
		goto out_clear;
	}

	res_offset = re->offset;
	entry_num = (res_offset - rx.disk->offset - (2 * align_size)) / align_size;
	ent_offset = sector_size + (entry_num * sizeof(struct rindex_entry));

	if ((cmd_flags & SANLK_RXUP_REM) && re->offset) {
		op_remove = 1;
	} else if ((cmd_flags & SANLK_RXUP_ADD) && re->name[0] && re->offset) {
		op_add = 1;
	} else {
		rv = -EINVAL;
		goto out_iobuf;
	}

	rv = update_rindex(task, &spi, &rx, rindex_iobuf, re, ent_offset, res_offset, op_remove);
	if (rv < 0) {
		log_error("rindex_update failed to update rindex %d", rv);
		goto out_iobuf;
	}
	rv = 0;

	if (op_remove) {
		memset(re_ret->name, 0, SANLK_NAME_LEN);
		re_ret->offset = 0;
	}
	if (op_add) {
		memcpy(re_ret->name, re->name, SANLK_NAME_LEN);
		re_ret->offset = res_offset;
	}

 out_iobuf:
	free(rindex_iobuf);
 out_clear:
	if (!nolock)
		lockspace_clear_rindex_op(ri->lockspace_name);
 out_close:
	close_disks(rx.disk, 1);
	return rv;
}

int rindex_rebuild(struct task *task, struct sanlk_rindex *ri, uint32_t cmd_flags)
{
	struct rindex_info rx;
	struct rindex_entry re_new;
	struct rindex_entry re_end;
	struct space_info spi;
	struct leader_record leader;
	struct paxos_dblock dblock;
	struct token *rx_token;
	struct token *res_token;
	struct sanlk_resource res;
	char off_str[16];
	char *rindex_iobuf = NULL;
	uint64_t res_offset;
	uint64_t ent_offset;
	uint32_t max_resources;
	int sector_size, align_size;
	int nolock = cmd_flags & SANLK_RX_NO_LOCKSPACE;
	int i, rv;

	memset(&rx, 0, sizeof(rx));
	rx.ri = ri;
	rx.disk = (struct sync_disk *)&ri->disk;

	rv = open_disk(rx.disk);
	if (rv < 0) {
		log_error("rindex_rebuild open failed %d %s", rv, rx.disk->path);
		return rv;
	}

	/*
	 * Allows only one rindex op for a given lockspace at a time.
	 * If there's already one in progress, this returns EBUSY.
	 * Also collects lockspace info at the same time.
	 */
	memset(&spi, 0, sizeof(spi));

	if (!nolock) {
		rv = lockspace_begin_rindex_op(ri->lockspace_name, RX_OP_REBUILD, &spi);
		if (rv < 0) {
			log_error("rindex_rebuild lockspace not available %d %.48s", rv, ri->lockspace_name);
			goto out_close;
		}
	}

	rv = read_rindex_header(task, &spi, &rx);
	if (rv < 0) {
		log_error("rindex_rebuild failed to read rindex header %d on %s:%llu",
			  rv, rx.disk->path, (unsigned long long)rx.disk->offset);
		goto out_clear;
	}

	sector_size = rx.header.sector_size;
	align_size = rindex_header_align_size_from_flag(rx.header.flags);
	max_resources = rx.header.max_resources;

	if (!max_resources)
		max_resources = size_to_max_resources(sector_size, align_size);

	log_debug("rindex_rebuild %.48s:%s:%llu %d %d max_res %u",
		  rx.ri->lockspace_name, rx.disk->path,
		  (unsigned long long)rx.disk->offset,
		  sector_size, align_size, max_resources);

	/* used to acquire the internal paxos lease protecting the rindex */
	rx_token = setup_rindex_token(&rx, sector_size, align_size, &spi);
	if (!rx_token) {
		rv = -ENOMEM;
		goto out_clear;
	}

	memset(&res, 0, sizeof(res));

	res_token = setup_resource_token(&rx, res.name, sector_size, align_size, &spi);
	if (!res_token) {
		free(rx_token);
		rv = -ENOMEM;
		goto out_clear;
	}

	if (!nolock) {
		rv = paxos_lease_acquire(task, rx_token,
					 PAXOS_ACQUIRE_OWNER_NOWAIT | PAXOS_ACQUIRE_QUIET_FAIL,
					 &leader, &dblock, 0, 0);
		if (rv < 0) {
			/* TODO: sleep and retry if this fails because it's held by another host? */
			log_error("rindex_rebuild failed to acquire rindex lease %d", rv);
			goto out_token;
		}
	}

	rv = read_rindex(task, &spi, &rx, &rindex_iobuf);
	if (rv < 0) {
		log_error("rindex_rebuild failed to read rindex %d", rv);
		goto out_lease;
	}

	/*
	 * Zero all the entries after the header sector.  Entries will be
	 * recreated in the zeroed space if corresponding resource leases are
	 * found.
	 */
	memset(rindex_iobuf + sector_size, 0, align_size - sector_size);

	/*
	 * We read each potential resource lease offset to check if a
	 * lease exists there.  It's ok if there is none, and we don't
	 * want to log errors if none is found.
	 */
	res_token->flags |= T_CHECK_EXISTS;

	/*
	 * Read each potential resource lease area and add an rindex entry
	 * for each one that's found.  Resource leases begin after
	 * the rindex area and the rindex lease area.
	 */
	res_offset = rx.disk->offset + (2 * align_size);

	for (i = 0; i < max_resources; i++) {
		memset(&re_new, 0, sizeof(re_new));
		memset(&re_end, 0, sizeof(re_end));
		memset(&res, 0, sizeof(res));
		memset(res_token->r.name, 0, SANLK_NAME_LEN);
		res_token->disks[0].offset = res_offset;

		rv = paxos_read_resource(task, res_token, &res);

		offset_to_str(res_offset, sizeof(off_str), off_str);

		/* end of device */
		if (rv == -EMSGSIZE) {
			log_debug("rindex_rebuild reached end of device at %d %s", i, off_str);
			break;
		}

		if (rv == SANLK_OK) {
			log_debug("rindex_rebuild found %.48s at %d %s",
			  	  res.name, i, off_str);

			re_new.res_offset = res_offset;
			memcpy(re_new.name, res.name, SANLK_NAME_LEN);
			rindex_entry_out(&re_new, &re_end);

			/* Within rindex, entries begin after the header sector */
			ent_offset = sector_size + (i * sizeof(struct rindex_entry));

			memcpy(rindex_iobuf + ent_offset, &re_end, sizeof(re_end));
		} else if ((i + 1) == max_resources) {
			log_debug("rindex_rebuild found no resource at last %d %s %d",
			  	  i, off_str, rv);
		}

		res_offset += align_size;
	}

	rv = write_iobuf(rx.disk->fd, rx.disk->offset, rindex_iobuf, align_size, task, spi.io_timeout, NULL);
	if (rv < 0) {
		if (rv != SANLK_AIO_TIMEOUT)
			free(rindex_iobuf);
		log_error("rindex_rebuild write failed %d %s", rv, rx.disk->path);
		goto out_lease;
	}

	rv = 0;

	free(rindex_iobuf);
 out_lease:
	if (!nolock)
		paxos_lease_release(task, rx_token, NULL, &leader, &leader);
 out_token:
	free(rx_token);
	free(res_token);
 out_clear:
	if (!nolock)
		lockspace_clear_rindex_op(ri->lockspace_name);
 out_close:
	close_disks(rx.disk, 1);
	return rv;
}

