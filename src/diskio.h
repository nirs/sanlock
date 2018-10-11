/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __DISKIO_H__
#define __DISKIO_H__

void offset_to_str(unsigned long long offset, int buflen, char *off_str);

void close_disks(struct sync_disk *disks, int num_disks);
int open_disk(struct sync_disk *disks);
int open_disks(struct sync_disk *disks, int num_disks);
int open_disks_fd(struct sync_disk *disks, int num_disks);
int majority_disks(int num_disks, int num);

/*
 * iobuf functions require the caller to allocate iobuf using posix_memalign
 * and pass it into the function
 */

int write_iobuf(int fd, uint64_t offset, char *iobuf, int iobuf_len,
		struct task *task, int ioto, int *wr_ms);

int read_iobuf(int fd, uint64_t offset, char *iobuf, int iobuf_len,
	       struct task *task, int ioto, int *rd_ms);

int read_iobuf_reap(int fd, uint64_t offset, char *iobuf, int iobuf_len,
		    struct task *task, uint32_t ioto_msec);

/*
 * sector functions allocate an iobuf themselves, copy into it for read, use it
 * for io, copy out of it for write, and free it
 */

int write_sector(const struct sync_disk *disk, int sector_size, uint64_t sector_nr,
		 const char *data, int data_len,
		 struct task *task, int ioto,
		 const char *blktype);

int write_sectors(const struct sync_disk *disk, int sector_size, uint64_t sector_nr,
		  uint32_t sector_count, const char *data, int data_len,
		  struct task *task, int ioto,
		  const char *blktype);

int read_sectors(const struct sync_disk *disk, int sector_size, uint64_t sector_nr,
	 	 uint32_t sector_count, char *data, int data_len,
		 struct task *task, int ioto,
		 const char *blktype);
#endif
