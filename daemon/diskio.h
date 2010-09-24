#ifndef __DISKIO_H__
#define __DISKIO_H__

void close_disks(struct paxos_disk *disks, int num_disks);
int open_disks(struct paxos_disk *disks, int num_disks);

int write_sector(struct paxos_disk *disk, uint32_t sector_nr,
		 const char *data, int data_len, const char *blktype);

int read_sectors(struct paxos_disk *disk, uint32_t sector_nr,
		 uint32_t sector_count, char *data, int data_len,
		 const char *blktype);
#endif
