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
#include <aio.h>
#include <blkid/blkid.h>

#include "sanlock_internal.h"
#include "diskio.h"
#include "log.h"

static int set_disk_properties(struct sync_disk *disk)
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

void close_disks(struct sync_disk *disks, int num_disks)
{
	int d;

	for (d = 0; d < num_disks; d++)
		close(disks[d].fd);
}

/* return number of opened disks */

int open_disks(struct sync_disk *disks, int num_disks)
{
	struct sync_disk *disk;
	int num_opens = 0;
	int d, fd, rv;
	uint32_t ss = 0;
	uint64_t orig_offset;

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

		orig_offset = disk->offset;

		switch (disk->units) {
		case SANLK_UNITS_BYTES:
			break;
		case SANLK_UNITS_SECTORS:
			disk->offset = orig_offset * ss;
			break;
		case SANLK_UNITS_KB:
			disk->offset = orig_offset * 1024;
			break;
		case SANLK_UNITS_MB:
			disk->offset = orig_offset * 1024 * 1024;
			break;
		default:
			log_error(NULL, "invalid offset units %d", disk->units);
			goto fail;
		}

		if (disk->offset % disk->sector_size) {
			log_error(NULL, "invalid offset %llu sector size %u %s",
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

static int do_write(int fd, uint64_t offset, const char *buf, int len)
{
	off_t ret;
	int rv;
	int pos = 0;

	ret = lseek(fd, offset, SEEK_SET);
	if (ret != offset)
		return -errno;

 retry:
	rv = write(fd, buf + pos, len);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0)
		return -errno;

	/* if (rv != len && len == sector_size) return error?
	   partial sector writes should not happen AFAIK, and
	   some uses depend on atomic single sector writes */

	if (rv != len) {
		len -= rv;
		pos += rv;
		goto retry;
	}

	return 0;
}

static int do_read(int fd, uint64_t offset, char *buf, int len)
{
	off_t ret;
	int rv, pos = 0;

	ret = lseek(fd, offset, SEEK_SET);
	if (ret != offset)
		return -errno;

	while (pos < len) {
		rv = read(fd, buf + pos, len - pos);
		if (rv == 0)
			return -1;
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0)
			return -errno;
		pos += rv;
	}

	return 0;
}

static int do_write_aio(int fd, uint64_t offset, char *buf, int len,
                        int io_timeout_seconds)
{
	struct timespec ts;
	struct aiocb cb;
	struct aiocb const *p_cb;
	int rv;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = io_timeout_seconds;

	memset(&cb, 0, sizeof(struct aiocb));
	p_cb = &cb;

	cb.aio_fildes = fd;
	cb.aio_buf = buf;
	cb.aio_nbytes = len;
	cb.aio_offset = offset;

	rv = aio_write(&cb);
	if (rv < 0)
		return -errno;

	rv = aio_suspend(&p_cb, 1, &ts);
	if (!rv)
		return 0;

	/* the write timed out, try to cancel it... */

	rv = aio_cancel(fd, &cb);
	if (rv < 0)
		return -errno;

	if (rv == AIO_ALLDONE)
		return 0;

	if (rv == AIO_CANCELED)
		return -EIO;

	/* Functions that depend on the timeout might consider
	 * the action failed even if it will complete if that
	 * happened after the alloted time frame */

	if (rv == AIO_NOTCANCELED)
		return -EIO;

	/* undefined error condition */
	return -1;
}

static int do_read_aio(int fd, uint64_t offset, char *buf, int len, int io_timeout_seconds)
{
	struct timespec ts;
	struct aiocb cb;
	struct aiocb const *p_cb;
	int rv;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = io_timeout_seconds;

	memset(&cb, 0, sizeof(struct aiocb));
	p_cb = &cb;

	cb.aio_fildes = fd;
	cb.aio_buf = buf;
	cb.aio_nbytes = len;
	cb.aio_offset = offset;

	rv = aio_read(&cb);
	if (rv < 0)
		return -errno;

	rv = aio_suspend(&p_cb, 1, &ts);
	if (!rv)
		return 0;

	/* the read timed out, try to cancel it... */

	rv = aio_cancel(fd, &cb);
	if (rv < 0)
		return -errno;

	if (rv == AIO_ALLDONE)
		return 0;

	if (rv == AIO_CANCELED)
		return -EIO;

	if (rv == AIO_NOTCANCELED)
		/* Functions that depend on the timeout might consider
		 * the action failed even if it will complete if that
		 * happened apter the alloted time frame */
		return -EIO;

	/* undefined error condition */
	return -1;
}

static int _write_sectors(const struct sync_disk *disk, uint64_t sector_nr,
			  uint32_t sector_count GNUC_UNUSED,
			  const char *data, int data_len,
			  int iobuf_len, int io_timeout_seconds, int use_aio,
			  const char *blktype)
{
	char *iobuf, **p_iobuf;
	uint64_t offset;
	int rv;

	offset = disk->offset + (sector_nr * disk->sector_size);

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv) {
		log_error(NULL, "write_sectors %s posix_memalign rv %d %s",
			  blktype, rv, disk->path);
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, iobuf_len);
	memcpy(iobuf, data, data_len);

	if (use_aio)
		rv = do_write_aio(disk->fd, offset, iobuf, iobuf_len, io_timeout_seconds);
	else
		rv = do_write(disk->fd, offset, iobuf, iobuf_len);

	if (rv < 0)
		log_error(NULL, "write_sectors %s offset %llu rv %d %s",
			  blktype, (unsigned long long)offset, rv, disk->path);
	free(iobuf);
 out:
	return rv;
}

/* sector_nr is logical sector number within the sync_disk.
   the sync_disk itself begins at disk->offset (in bytes) from
   the start of the block device identified by disk->path,
   data_len must be <= sector_size */

int write_sector(const struct sync_disk *disk, uint64_t sector_nr,
		 const char *data, int data_len, int io_timeout_seconds,
		 int use_aio, const char *blktype)
{
	int iobuf_len = disk->sector_size;

	if (data_len > iobuf_len) {
		log_error(NULL, "write_sector %s data_len %d max %d %s",
			  blktype, data_len, iobuf_len, disk->path);
		return -1;
	}

	return _write_sectors(disk, sector_nr, 1, data, data_len,
			      iobuf_len, io_timeout_seconds, use_aio, blktype);
}

/* write multiple complete sectors, data_len must be multiple of sector size */

int write_sectors(const struct sync_disk *disk, uint64_t sector_nr,
		  uint32_t sector_count, const char *data, int data_len,
		  int io_timeout_seconds, int use_aio, const char *blktype)
{
	int iobuf_len = data_len;

	if (data_len != sector_count * disk->sector_size) {
		log_error(NULL, "write_sectors %s data_len %d sector_count %d %s",
			  blktype, data_len, sector_count, disk->path);
		return -1;
	}

	return _write_sectors(disk, sector_nr, sector_count, data, data_len,
			      iobuf_len, io_timeout_seconds, use_aio, blktype);
}

/* read sector_count sectors starting with sector_nr, where sector_nr
   is a logical sector number within the sync_disk.  the caller will
   generally want to look at the first N bytes of each sector.
   when reading multiple sectors, data_len will generally equal iobuf_len,
   but when reading one sector, data_len may be less than iobuf_len. */

int read_sectors(const struct sync_disk *disk, uint64_t sector_nr,
	 	 uint32_t sector_count, char *data, int data_len,
		 int io_timeout_seconds, int use_aio, const char *blktype)
{
	char *iobuf, **p_iobuf;
	uint64_t offset;
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

	if (use_aio)
		rv = do_read_aio(disk->fd, offset, iobuf, iobuf_len, io_timeout_seconds);
	else
		rv = do_read(disk->fd, offset, iobuf, iobuf_len);

	if (!rv) {
		memcpy(data, iobuf, data_len);
	} else {
		log_error(NULL, "read_sectors %s offset %llu rv %d %s",
			  blktype, (unsigned long long)offset, rv, disk->path);
	}

	free(iobuf);
 out:
	return rv;
}

