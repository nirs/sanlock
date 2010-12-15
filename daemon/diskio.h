#ifndef __DISKIO_H__
#define __DISKIO_H__

/* for paxos_lease sync_disk + offset:
   points to 1 leader_record + 1 request_record + MAX_HOSTS paxos_dblock's =
   256 blocks = 128KB, ref: lease_item_record */

struct sync_disk {
	/* mirror external sanlk_disk */
	char path[DISK_PATH_LEN];
	uint64_t offset;
	uint32_t units;

	/* internal */
	uint32_t sector_size;
	int fd;
};

void close_disks(struct sync_disk *disks, int num_disks);
int open_disks(struct sync_disk *disks, int num_disks);

int write_sector(const struct sync_disk *disk, uint32_t sector_nr,
		 const char *data, int data_len, int io_timeout_seconds,
		 int use_aio, const char *blktype);

int write_sectors(const struct sync_disk *disk, uint32_t sector_nr,
		  uint32_t sector_count, const char *data, int data_len,
		  int io_timeout_seconds, int use_aio, const char *blktype);

int read_sectors(const struct sync_disk *disk, uint32_t sector_nr,
	 	 uint32_t sector_count, char *data, int data_len,
		 int io_timeout_seconds, int use_aio, const char *blktype);
#endif