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
#include <blkid/blkid.h>

#include "sm.h"
#include "sm_msg.h"
#include "disk_paxos.h"
#include "sm_options.h"
#include "log.h"
#include "crc32c.h"
#include "diskio.h"

static int set_disk_properties(struct paxos_disk *disk)
{
	blkid_probe probe;
	blkid_topology topo;
	uint32_t sector_size, ss_logical, ss_physical;

	probe = blkid_new_probe_from_filename(disk->path);
	if (!probe) {
		log_error(NULL, "cannot get blkid probe %s", disk->path);
		return -1;
	}

	topo = blkid_probe_get_topology(probe);
	if (!topo) {
		log_error(NULL, "cannot get blkid topology %s", disk->path);
		blkid_free_probe(probe);
		return -1;
	}

	sector_size = blkid_probe_get_sectorsize(probe);
	ss_logical = blkid_topology_get_logical_sector_size(topo);
	ss_physical = blkid_topology_get_physical_sector_size(topo);

	blkid_free_probe(probe);

	if ((sector_size != ss_logical) ||
	    (sector_size != ss_physical) ||
	    (sector_size % 512)) {
		log_error(NULL, "invalid disk sector size %u logical %u "
			  "physical %u %s", sector_size, ss_logical,
			  ss_physical, disk->path);
		return -1;
	}

	disk->sector_size = sector_size;
	return 0;
}

void close_disks(struct paxos_disk *disks, int num_disks)
{
	int d;

	for (d = 0; d < num_disks; d++)
		close(disks[d].fd);
}

/* return number of opened disks */

int open_disks(struct paxos_disk *disks, int num_disks)
{
	struct paxos_disk *disk;
	int num_opens = 0;
	int d, fd, rv;
	uint32_t ss = 0;

	for (d = 0; d < num_disks; d++) {
		disk = &disks[d];
		fd = open(disk->path, O_RDWR | O_DIRECT | O_SYNC, 0);
		if (fd < 0) {
			log_error(NULL, "open error %d %s", fd, disk->path);
			continue;
		}

		rv = set_disk_properties(disk);
		if (rv < 0) {
			close(fd);
			continue;
		}

		if (!ss) {
			ss = disk->sector_size;
		} else if (ss != disk->sector_size) {
			log_error(NULL, "inconsistent sector sizes %u %u %s",
				  ss, disk->sector_size, disk->path);
			goto fail;
		}

		if (disk->offset % disk->sector_size) {
			log_error(NULL, "invalid offset %lluu sector size %u %s",
				  (unsigned long long)disk->offset,
				  disk->sector_size, disk->path);
			goto fail;
		}

		disk->fd = fd;
		num_opens++;
	}
	return num_opens;

 fail:
	close_disks(disks, num_disks);
	return 0;
}

/* sector_nr is logical sector number within the paxos_disk.
   the paxos_disk itself begins at disk->offset (in bytes) from
   the start of the block device identified by disk->path */

int write_sector(struct paxos_disk *disk, uint32_t sector_nr,
		 const char *data, int data_len, const char *blktype)
{
	char *iobuf, **p_iobuf;
	uint64_t offset;
	off_t ret;
	int iobuf_len = disk->sector_size;
	int rv;

	if (data_len > iobuf_len) {
		log_error(NULL, "write_sector %s data_len %d max %d %s",
			  blktype, data_len, iobuf_len, disk->path);
		rv = -1;
		goto out;
	}

	offset = disk->offset + (sector_nr * disk->sector_size);

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv) {
		log_error(NULL, "write_sector %s posix_memalign rv %d %s",
			  blktype, rv, disk->path);
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, iobuf_len);
	memcpy(iobuf, data, data_len);

#ifdef USE_AIO
	rv = sm_aio_write(disk->fd, iobuf, iobuf_len);
#else
	ret = lseek(disk->fd, offset, SEEK_SET);
	if (ret != offset) {
		log_error(NULL, "write_sector %s lseek errno %d offset %llu %s",
			  blktype, errno, (unsigned long long)offset, disk->path);
		rv = -1;
		goto out;
	}

	rv = write(disk->fd, iobuf, iobuf_len);
#endif
	if (rv != iobuf_len) {
		log_error(NULL, "write_sector %s write errno %d offset %llu %s",
			  blktype, errno, (unsigned long long)offset, disk->path);
		rv = -1;
		goto out_free;
	}

	rv = 0;
 out_free:
	free(iobuf);
 out:
	return rv;
}

/* read sector_count sectors starting with sector_nr, where sector_nr
   is a logical sector number within the paxos_disk.  the caller will
   generally want to look at the first N bytes of each sector.
   when reading multiple sectors, data_len will generally equal iobuf_len,
   but when reading one sector, data_len may be less than iobuf_len. */

int read_sectors(struct paxos_disk *disk, uint32_t sector_nr,
	 	 uint32_t sector_count, char *data, int data_len,
		 const char *blktype)
{
	char *iobuf, **p_iobuf;
	uint64_t offset;
	off_t ret;
	int iobuf_len = sector_count * disk->sector_size;
	int rv;

	offset = disk->offset + (sector_nr * disk->sector_size);

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv) {
		log_error(NULL, "read_sectors %s posix_memalign rv %d %s",
			  blktype, rv, disk->path);
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, iobuf_len);

#ifdef USE_AIO
	rv = sm_aio_read(disk->fd, iobuf, iobuf_len);
#else
	ret = lseek(disk->fd, offset, SEEK_SET);
	if (ret != offset) {
		log_error(NULL, "read_sectors %s lseek errno %d offset %llu %s",
			  blktype, errno, (unsigned long long)offset, disk->path);
		rv = -1;
		goto out;
	}

	rv = read(disk->fd, iobuf, iobuf_len);
#endif
	if (rv != iobuf_len) {
		log_error(NULL, "read_sectors %s read errno %d offset %llu %s",
			  blktype, errno, (unsigned long long)offset, disk->path);
		rv = -1;
		goto out_free;
	}

	memcpy(data, iobuf, data_len);

	rv = 0;
 out_free:
	free(iobuf);
 out:
	return rv;
}

