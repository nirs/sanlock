/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __DISKIO_H__
#define __DISKIO_H__

void close_disks(struct sync_disk *disks, int num_disks);
int open_disks(struct sync_disk *disks, int num_disks);
int open_disks_fd(struct sync_disk *disks, int num_disks);

int write_iobuf(int fd, uint64_t offset, char *iobuf, int iobuf_len,
		struct task *task);

int write_sector(const struct sync_disk *disk, uint64_t sector_nr,
		 const char *data, int data_len,
		 struct task *task, const char *blktype);

int write_sectors(const struct sync_disk *disk, uint64_t sector_nr,
		  uint32_t sector_count, const char *data, int data_len,
		  struct task *task, const char *blktype);

int read_sectors(const struct sync_disk *disk, uint64_t sector_nr,
	 	 uint32_t sector_count, char *data, int data_len,
		 struct task *task, const char *blktype);
#endif
