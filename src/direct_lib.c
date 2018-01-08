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
#include <errno.h>

#define EXTERN
#include "sanlock_internal.h"
#include "sanlock_direct.h"
#include "sanlock_admin.h"
#include "diskio.h"
#include "direct.h"
#include "task.h"
#include "timeouts.h"

void log_level(uint32_t space_id GNUC_UNUSED, uint32_t res_id GNUC_UNUSED,
	       char *name GNUC_UNUSED,
	       int level GNUC_UNUSED, const char *fmt GNUC_UNUSED, ...);

void log_level(uint32_t space_id GNUC_UNUSED, uint32_t res_id GNUC_UNUSED,
	       char *name GNUC_UNUSED,
	       int level GNUC_UNUSED, const char *fmt GNUC_UNUSED, ...)
{
}

int lockspace_begin_rindex_op(char *space_name GNUC_UNUSED, int rindex_op GNUC_UNUSED, struct space_info *spi GNUC_UNUSED);
int lockspace_begin_rindex_op(char *space_name GNUC_UNUSED, int rindex_op GNUC_UNUSED, struct space_info *spi GNUC_UNUSED)
{
	return -1;
}

int lockspace_clear_rindex_op(char *space_name GNUC_UNUSED);
int lockspace_clear_rindex_op(char *space_name GNUC_UNUSED)
{
	return -1;
}

int lockspace_disk(char *space_name GNUC_UNUSED, struct sync_disk *disk GNUC_UNUSED);

int lockspace_disk(char *space_name GNUC_UNUSED, struct sync_disk *disk GNUC_UNUSED)
{
	return -1;
}

int host_info(char *space_name, uint64_t host_id, struct host_status *hs_out);

int host_info(char *space_name GNUC_UNUSED, uint64_t host_id GNUC_UNUSED, struct host_status *hs_out GNUC_UNUSED)
{
	return -1;
}

struct token;

void check_mode_block(struct token *token GNUC_UNUSED, int q GNUC_UNUSED, char *dblock GNUC_UNUSED);

void check_mode_block(struct token *token GNUC_UNUSED, int q GNUC_UNUSED, char *dblock GNUC_UNUSED)
{
}

/* copied from host_id.c */

int test_id_bit(int host_id, char *bitmap);

int test_id_bit(int host_id, char *bitmap)
{
	char *byte = bitmap + ((host_id - 1) / 8);
	unsigned int bit = (host_id - 1) % 8;
	char mask;

	mask = 1 << bit;

	return (*byte & mask);
}

int get_rand(int a, int b);

int get_rand(int a, int b)
{
	return a + (int) (((float)(b - a + 1)) * random() / (RAND_MAX+1.0));
}

static void setup_task_lib(struct task *task, int use_aio)
{
	memset(task, 0, sizeof(struct task));
	setup_task_aio(task, use_aio, LIB_AIO_CB_SIZE);
	sprintf(task->name, "%s", "lib");
}


int sanlock_direct_write_lockspace(struct sanlk_lockspace *ls, int max_hosts,
                                   uint32_t flags GNUC_UNUSED, uint32_t io_timeout)
{
	struct task task;
	int rv;

	setup_task_lib(&task, 1);

	rv = direct_write_lockspace(&task, ls, max_hosts, io_timeout);

	close_task_aio(&task);

	return rv;
}

int sanlock_direct_write_resource(struct sanlk_resource *res,
                                  int max_hosts, int num_hosts,
				  uint32_t flags)
{
	struct task task;
	int rv;

	setup_task_lib(&task, 1);

	rv = direct_write_resource(&task, res, max_hosts, num_hosts,
				   (flags & SANLK_WRITE_CLEAR) ? 1 : 0);

	close_task_aio(&task);

	return rv;
}

int sanlock_direct_init(struct sanlk_lockspace *ls,
			struct sanlk_resource *res,
			int max_hosts, int num_hosts, int use_aio)
{
	struct task task;
	int rv;

	setup_task_lib(&task, use_aio);

	if (ls)
		rv = direct_write_lockspace(&task, ls, max_hosts, 0);
	else
		rv = direct_write_resource(&task, res, max_hosts, num_hosts, 0);

	close_task_aio(&task);

	return rv;
}

int sanlock_direct_align(struct sanlk_disk *disk_in)
{
	struct sync_disk disk;
	int align_size, rv;

	memset(&disk, 0, sizeof(disk));

	memcpy(disk.path, disk_in->path, SANLK_PATH_LEN);

	rv = open_disk(&disk);
	if (rv < 0)
		return rv;

	align_size = direct_align(&disk);

	close(disk.fd);

	return align_size;
}

