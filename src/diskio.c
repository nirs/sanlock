/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
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
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <blkid/blkid.h>

#include <libaio.h> /* linux aio */
#include <aio.h>    /* posix aio */

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
		log_error("cannot get blkid probe %s", disk->path);
		return -1;
	}

	topo = blkid_probe_get_topology(probe);
	if (!topo) {
		log_error("cannot get blkid topology %s", disk->path);
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
		log_error("invalid disk sector size %u logical %u "
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

	for (d = 0; d < num_disks; d++) {
		if (disks[d].fd == -1) {
			log_error("close fd -1");
			continue;
		}
		close(disks[d].fd);
		disks[d].fd = -1;
	}
}

int open_disks_fd(struct sync_disk *disks, int num_disks)
{
	struct sync_disk *disk;
	int num_opens = 0;
	int d, fd;

	for (d = 0; d < num_disks; d++) {
		disk = &disks[d];

		if (disk->fd != -1) {
			log_error("open fd %d exists %s", disk->fd, disk->path);
			return 0;
		}

		fd = open(disk->path, O_RDWR | O_DIRECT | O_SYNC, 0);
		if (fd < 0) {
			log_error("open error %d %s", fd, disk->path);
			continue;
		}

		disk->fd = fd;
		num_opens++;
	}
	return num_opens;
}

/* return number of opened disks */

int open_disks(struct sync_disk *disks, int num_disks)
{
	struct sync_disk *disk;
	int num_opens = 0;
	int d, fd, rv;
	uint32_t ss = 0;
	uint64_t orig_offset;
	struct stat st;

	for (d = 0; d < num_disks; d++) {
		disk = &disks[d];

		if (disk->fd != -1) {
			log_error("open fd %d exists %s", disk->fd, disk->path);
			return 0;
		}

		fd = open(disk->path, O_RDWR | O_DIRECT | O_SYNC, 0);
		if (fd < 0) {
			log_error("open error %d %s", fd, disk->path);
			continue;
		}

		if (fstat(fd, &st) < 0) {
			log_error("fstat error %d %s", fd, disk->path);
			close(fd);
			continue;
		}

		if (S_ISREG(st.st_mode)) {
			disk->sector_size = 512;
		} else {
		        rv = set_disk_properties(disk);
			if (rv < 0) {
				close(fd);
				continue;
			}
		}

		if (!ss) {
			ss = disk->sector_size;
		} else if (ss != disk->sector_size) {
			log_error("inconsistent sector sizes %u %u %s",
				  ss, disk->sector_size, disk->path);
			close(fd);
			goto fail;
		}

		orig_offset = disk->offset;

		if (disk->offset % disk->sector_size) {
			log_error("invalid offset %llu sector size %u %s",
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

static int do_write(int fd, uint64_t offset, const char *buf, int len, struct task *task)
{
	off_t ret;
	int rv;
	int pos = 0;

	if (task)
		task->io_count++;

	ret = lseek(fd, offset, SEEK_SET);
	if (ret != offset)
		return -1;

 retry:
	rv = write(fd, buf + pos, len);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0)
		return -1;

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

static int do_read(int fd, uint64_t offset, char *buf, int len, struct task *task)
{
	off_t ret;
	int rv, pos = 0;

	if (task)
		task->io_count++;

	ret = lseek(fd, offset, SEEK_SET);
	if (ret != offset)
		return -1;

	while (pos < len) {
		rv = read(fd, buf + pos, len - pos);
		if (rv == 0)
			return -1;
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0)
			return -1;
		pos += rv;
	}

	return 0;
}

static struct aicb *find_callback_slot(struct task *task)
{
	struct timespec ts;
	struct io_event event;
	int cleared = 0;
	int rv;
	int i;

 find:
	for (i = 0; i < task->cb_size; i++) {
		if (task->callbacks[i].used)
			continue;
		return &task->callbacks[i];
	}

	if (cleared++)
		return NULL;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = task->io_timeout_seconds;
 retry:
	memset(&event, 0, sizeof(event));

	rv = io_getevents(task->aio_ctx, 1, 1, &event, &ts);
	if (rv == -EINTR)
		goto retry;
	if (rv < 0)
		return NULL;
	if (rv == 1) {
		struct iocb *ev_iocb = event.obj;
		struct aicb *ev_aicb = container_of(ev_iocb, struct aicb, iocb);

		ev_aicb->used = 0;
		goto find;
	}
	return NULL;
}

static int do_linux_aio(int fd, uint64_t offset, char *buf, int len,
			struct task *task, int cmd)
{
	struct timespec ts;
	struct aicb *aicb;
	struct iocb *iocb;
	struct io_event event;
	int rv;

	/* I expect this pre-emptively catches the io_submit EAGAIN case */

	aicb = find_callback_slot(task);
	if (!aicb)
		return -ENOENT;

	iocb = &aicb->iocb;

	memset(iocb, 0, sizeof(struct iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = cmd;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = len;
	iocb->u.c.offset = offset;

	rv = io_submit(task->aio_ctx, 1, &iocb);
	if (rv < 0) {
		log_error("aio %s io_submit error %d", task->name, rv);
		goto out;
	}

	task->io_count++;

	/* don't reuse aicb->iocb until we reap the event for it */
	aicb->used = 1;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = task->io_timeout_seconds;
 retry:
	memset(&event, 0, sizeof(event));

	rv = io_getevents(task->aio_ctx, 1, 1, &event, &ts);
	if (rv == -EINTR)
		goto retry;
	if (rv < 0) {
		log_error("aio %s io_getevents error %d", task->name, rv);
		goto out;
	}
	if (rv == 1) {
		struct iocb *ev_iocb = event.obj;
		struct aicb *ev_aicb = container_of(ev_iocb, struct aicb, iocb);

		ev_aicb->used = 0;

		if (ev_iocb != iocb) {
			log_error("aio %s other iocb %p event result %ld %ld",
				  task->name, ev_iocb, event.res, event.res2);
			goto retry;
		}
		if ((int)event.res < 0) {
			log_error("aio %s event result %ld %ld",
				  task->name, event.res, event.res2);
			rv = event.res;
			goto out;
		}
		if (event.res != len) {
			log_error("aio %s event len %d result %lu %lu",
				  task->name, len, event.res, event.res2);
			rv = -EMSGSIZE;
			goto out;
		}

		/* standard success case */
		rv = 0;
		goto out;
	}

	/* Timed out waiting for result.  If cancel fails, we could try retry
	   io_getevents indefinately, but that removes the whole point of using
	   aio, which is the timeout.  So, we need to be prepared to reap the
	   event the next time we call io_getevents for a different i/o.  We
	   can't reuse the iocb for this timed out io until we get an event for
	   it because we need to compare the iocb to event.obj to distinguish
	   events for separate submissions.

	   <phro> dct: io_cancel doesn't work, in general.  you are very
	   likely going to get -EINVAL from that call */

	task->to_count++;

	log_error("aio %s iocb %p timeout %u io_count %u", task->name, iocb,
		  task->to_count, task->io_count);

	rv = io_cancel(task->aio_ctx, iocb, &event);
	if (!rv) {
		rv = -ECANCELED;
	} else if (rv > 0) {
		rv = -EILSEQ;
	}
 out:
	return rv;
}

static int do_write_aio_linux(int fd, uint64_t offset, char *buf, int len, struct task *task)
{
	return do_linux_aio(fd, offset, buf, len, task, IO_CMD_PWRITE);
}
static int do_read_aio_linux(int fd, uint64_t offset, char *buf, int len, struct task *task)
{
	return do_linux_aio(fd, offset, buf, len, task, IO_CMD_PREAD);
}

static int do_write_aio_posix(int fd, uint64_t offset, char *buf, int len, struct task *task)
{
	struct timespec ts;
	struct aiocb cb;
	struct aiocb const *p_cb;
	int rv;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = task->io_timeout_seconds;

	memset(&cb, 0, sizeof(struct aiocb));
	p_cb = &cb;

	cb.aio_fildes = fd;
	cb.aio_buf = buf;
	cb.aio_nbytes = len;
	cb.aio_offset = offset;

	rv = aio_write(&cb);
	if (rv < 0)
		return -1;

	rv = aio_suspend(&p_cb, 1, &ts);
	if (!rv)
		return 0;

	/* the write timed out, try to cancel it... */

	rv = aio_cancel(fd, &cb);
	if (rv < 0)
		return -1;

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

static int do_read_aio_posix(int fd, uint64_t offset, char *buf, int len, struct task *task)
{
	struct timespec ts;
	struct aiocb cb;
	struct aiocb const *p_cb;
	int rv;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = task->io_timeout_seconds;

	memset(&cb, 0, sizeof(struct aiocb));
	p_cb = &cb;

	cb.aio_fildes = fd;
	cb.aio_buf = buf;
	cb.aio_nbytes = len;
	cb.aio_offset = offset;

	rv = aio_read(&cb);
	if (rv < 0)
		return -1;

	rv = aio_suspend(&p_cb, 1, &ts);
	if (!rv)
		return 0;

	/* the read timed out, try to cancel it... */

	rv = aio_cancel(fd, &cb);
	if (rv < 0)
		return -1;

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

/* write aligned io buffer */

int write_iobuf(int fd, uint64_t offset, char *iobuf, int iobuf_len, struct task *task)
{
	if (task && task->use_aio == 1)
		return do_write_aio_linux(fd, offset, iobuf, iobuf_len, task);
	else if (task && task->use_aio == 2)
		return do_write_aio_posix(fd, offset, iobuf, iobuf_len, task);
	else
		return do_write(fd, offset, iobuf, iobuf_len, task);
}

static int _write_sectors(const struct sync_disk *disk, uint64_t sector_nr,
			  uint32_t sector_count GNUC_UNUSED,
			  const char *data, int data_len,
			  int iobuf_len, struct task *task, const char *blktype)
{
	char *iobuf, **p_iobuf;
	uint64_t offset;
	int rv;

	if (!disk->sector_size)
		return -EINVAL;

	offset = disk->offset + (sector_nr * disk->sector_size);

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv) {
		log_error("write_sectors %s posix_memalign rv %d %s",
			  blktype, rv, disk->path);
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, iobuf_len);
	memcpy(iobuf, data, data_len);

	rv = write_iobuf(disk->fd, offset, iobuf, iobuf_len, task);
	if (rv < 0)
		log_error("write_sectors %s offset %llu rv %d %s",
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
		 const char *data, int data_len, struct task *task,
		 const char *blktype)
{
	int iobuf_len = disk->sector_size;

	if (data_len > iobuf_len) {
		log_error("write_sector %s data_len %d max %d %s",
			  blktype, data_len, iobuf_len, disk->path);
		return -1;
	}

	return _write_sectors(disk, sector_nr, 1, data, data_len,
			      iobuf_len, task, blktype);
}

/* write multiple complete sectors, data_len must be multiple of sector size */

int write_sectors(const struct sync_disk *disk, uint64_t sector_nr,
		  uint32_t sector_count, const char *data, int data_len,
		  struct task *task, const char *blktype)
{
	int iobuf_len = data_len;

	if (data_len != sector_count * disk->sector_size) {
		log_error("write_sectors %s data_len %d sector_count %d %s",
			  blktype, data_len, sector_count, disk->path);
		return -1;
	}

	return _write_sectors(disk, sector_nr, sector_count, data, data_len,
			      iobuf_len, task, blktype);
}

/* read sector_count sectors starting with sector_nr, where sector_nr
   is a logical sector number within the sync_disk.  the caller will
   generally want to look at the first N bytes of each sector.
   when reading multiple sectors, data_len will generally equal iobuf_len,
   but when reading one sector, data_len may be less than iobuf_len. */

int read_sectors(const struct sync_disk *disk, uint64_t sector_nr,
	 	 uint32_t sector_count, char *data, int data_len,
		 struct task *task, const char *blktype)
{
	char *iobuf, **p_iobuf;
	uint64_t offset;
	int iobuf_len = sector_count * disk->sector_size;
	int rv;

	if (!disk->sector_size)
		return -EINVAL;

	offset = disk->offset + (sector_nr * disk->sector_size);

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv) {
		log_error("read_sectors %s posix_memalign rv %d %s",
			  blktype, rv, disk->path);
		rv = -1;
		goto out;
	}

	memset(iobuf, 0, iobuf_len);

	if (task && task->use_aio == 1)
		rv = do_read_aio_linux(disk->fd, offset, iobuf, iobuf_len, task);
	else if (task && task->use_aio == 2)
		rv = do_read_aio_posix(disk->fd, offset, iobuf, iobuf_len, task);
	else
		rv = do_read(disk->fd, offset, iobuf, iobuf_len, task);

	if (!rv) {
		memcpy(data, iobuf, data_len);
	} else {
		log_error("read_sectors %s offset %llu rv %d %s",
			  blktype, (unsigned long long)offset, rv, disk->path);
	}

	free(iobuf);
 out:
	return rv;
}

