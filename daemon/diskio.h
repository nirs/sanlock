#ifndef __DISKIO_H__
#define __DISKIO_H__

void close_disks(struct sync_disk *disks, int num_disks);
int open_disks(struct sync_disk *disks, int num_disks);

int write_sector(const struct sync_disk *disk, uint64_t sector_nr,
		 const char *data, int data_len, int io_timeout_seconds,
		 int use_aio, const char *blktype);

int write_sectors(const struct sync_disk *disk, uint64_t sector_nr,
		  uint32_t sector_count, const char *data, int data_len,
		  int io_timeout_seconds, int use_aio, const char *blktype);

int read_sectors(const struct sync_disk *disk, uint64_t sector_nr,
	 	 uint32_t sector_count, char *data, int data_len,
		 int io_timeout_seconds, int use_aio, const char *blktype);
#endif
