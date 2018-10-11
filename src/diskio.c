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
#include "direct.h"
#include "log.h"

static int set_disk_properties(struct sync_disk *disk)
{
	blkid_probe probe;
	uint32_t sector_size;

	probe = blkid_new_probe_from_filename(disk->path);
	if (!probe) {
		log_error("cannot get blkid probe %s", disk->path);
		return -1;
	}

	sector_size = blkid_probe_get_sectorsize(probe);

	blkid_free_probe(probe);

	disk->sector_size = sector_size;
	return 0;
}

void close_disks(struct sync_disk *disks, int num_disks)
{
	int d;

	for (d = 0; d < num_disks; d++) {
		if (disks[d].fd == -1)
			continue;
		close(disks[d].fd);
		disks[d].fd = -1;
	}
}

int majority_disks(int num_disks, int num)
{
	if (num_disks == 1 && !num)
		return 0;

	/* odd number of disks */

	if (num_disks % 2)
		return num >= ((num_disks / 2) + 1);

	/* even number of disks */

	if (num > (num_disks / 2))
		return 1;

	if (num < (num_disks / 2))
		return 0;

	/* TODO: half of disks are majority if tiebreaker disk is present */
	return 0;
}

/* 
 * set fd in each disk
 * returns 0 if majority of disks were opened successfully, -EXXX otherwise
 */

int open_disks_fd(struct sync_disk *disks, int num_disks)
{
	struct sync_disk *disk;
	int num_opens = 0;
	int d, fd, rv = -1;

	for (d = 0; d < num_disks; d++) {
		disk = &disks[d];

		if (disk->fd != -1) {
			log_error("open fd %d exists %s", disk->fd, disk->path);
			rv = -1;
			goto fail;
		}

		fd = open(disk->path, O_RDWR | O_DIRECT | O_SYNC, 0);
		if (fd < 0) {
			rv = -errno;
			if (rv == -EACCES) {
				log_error("open error %d EACCES: no permission to open %s", rv, disk->path);
				log_error("check that daemon user %s %d group %s %d has access to disk or file.",
					  com.uname, com.uid, com.gname, com.gid);
			} else
				log_error("open error %d %s", fd, disk->path);
			continue;
		}

		disk->fd = fd;
		num_opens++;
	}

	if (!majority_disks(num_disks, num_opens)) {
		/* rv is open errno */
		goto fail;
	}

	return 0;

 fail:
	close_disks(disks, num_disks);
	return rv;
}

/* 
 * set fd and sector_size
 * verify offset is correctly aligned
 * returns 0 for success or -EXXX
 */

int open_disk(struct sync_disk *disk)
{
	struct stat st;
	int fd, rv;

	fd = open(disk->path, O_RDWR | O_DIRECT | O_SYNC, 0);
	if (fd < 0) {
		rv = -errno;
		if (rv == -EACCES) {
			log_error("open error %d EACCES: no permission to open %s", rv, disk->path);
			log_error("check that daemon user %s %d group %s %d has access to disk or file.",
				  com.uname, com.uid, com.gname, com.gid);
		} else
			log_error("open error %d %s", rv, disk->path);
		goto fail;
	}

	if (fstat(fd, &st) < 0) {
		rv = -errno;
		log_error("fstat error %d %s", rv, disk->path);
		close(fd);
		goto fail;
	}

	if (S_ISREG(st.st_mode)) {
		disk->sector_size = 512;
	} else {
		rv = set_disk_properties(disk);
		if (rv < 0) {
			close(fd);
			goto fail;
		}
	}

	disk->fd = fd;
	return 0;

 fail:
	if (rv >= 0)
		rv = -1;
	return rv;
}

/*
 * set fd and sector_size in each disk
 * verify all sector_size's match
 * returns 0 if majority of disks were opened successfully, -EXXX otherwise
 */

int open_disks(struct sync_disk *disks, int num_disks)
{
	struct sync_disk *disk;
	int num_opens = 0;
	int d, err, rv = -1;
	uint32_t ss = 0;

	for (d = 0; d < num_disks; d++) {
		disk = &disks[d];

		if (disk->fd != -1) {
			log_error("open fd %d exists %s", disk->fd, disk->path);
			rv = -ENOTEMPTY;
			goto fail;
		}

		err = open_disk(disk);
		if (err < 0) {
			rv = err;
			continue;
		}

		if (!ss) {
			ss = disk->sector_size;
		} else if (ss != disk->sector_size) {
			log_error("inconsistent sector sizes %u %u %s",
				  ss, disk->sector_size, disk->path);
		}

		num_opens++;
	}

	if (!majority_disks(num_disks, num_opens)) {
		/* rv is from open err */
		goto fail;
	}

	return 0;

 fail:
	close_disks(disks, num_disks);
	return rv;
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

static struct aicb *find_callback_slot(struct task *task, int ioto)
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
	ts.tv_sec = ioto;
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
		int op = ev_iocb ? ev_iocb->aio_lio_opcode : -1;
		const char *op_str;

		if (op == IO_CMD_PREAD)
			op_str = "RD";
		else if (op == IO_CMD_PWRITE)
			op_str = "WR";
		else
			op_str = "UK";

		log_taskw(task, "aio collect %s %p:%p:%p result %ld:%ld old free",
			  op_str, ev_aicb, ev_iocb, ev_aicb->buf, event.res, event.res2);
		ev_aicb->used = 0;
		free(ev_aicb->buf);
		ev_aicb->buf = NULL;
		goto find;
	}
	return NULL;
}

void offset_to_str(unsigned long long offset, int buflen, char *off_str)
{
	uint64_t num_mb;

	if (!offset) {
		strncpy(off_str, "0", buflen);
	} else if (!(offset % 1048576)) {
		num_mb = offset / 1048576;
		snprintf(off_str, buflen, "%uM", (uint32_t)num_mb);
	} else {
		snprintf(off_str, buflen, "%llu", (unsigned long long)offset);
	}
}

/*
 * If this function returns SANLK_AIO_TIMEOUT, it means the io has timed out
 * and the event for the timed out io has not been reaped; the caller cannot
 * free the buf it passed in.  It will be freed by a subsequent call when the
 * event is reaped.  (Using my own error value here because I'm not certain
 * what values we might return from event.res.)
 */

static int do_linux_aio(int fd, uint64_t offset, char *buf, int len,
			struct task *task, int ioto, int cmd, int *ms)
{
	struct timespec ts;
	struct aicb *aicb;
	struct iocb *iocb;
	struct io_event event;
	struct timespec begin, end, diff;
	const char *op_str;
	const char *len_str;
	char ms_str[8];
	char off_str[16];
	int rv;

	if (!ioto) {
		log_taske(task, "aio %d zero io timeout", cmd);
		return -EINVAL;
	}

	/* I expect this pre-emptively catches the io_submit EAGAIN case */

	aicb = find_callback_slot(task, ioto);
	if (!aicb)
		return -ENOENT;

	iocb = &aicb->iocb;

	memset(iocb, 0, sizeof(struct iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = cmd;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = len;
	iocb->u.c.offset = offset;

	if (cmd == IO_CMD_PREAD)
		op_str = "RD";
	else if (cmd == IO_CMD_PWRITE)
		op_str = "WR";
	else
		op_str = "UK";

	if (com.debug_io_submit) {
		len_str = align_size_debug_str(len);
		offset_to_str(offset, sizeof(off_str), off_str);

		if (len_str)
			log_taskd(task, "%s %s at %s", op_str, len_str, off_str);
		else
			log_taskd(task, "%s %d at %s", op_str, len, off_str);
	}

	if (ms)
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	rv = io_submit(task->aio_ctx, 1, &iocb);
	if (rv < 0) {
		log_taske(task, "aio submit %d %p:%p:%p rv %d fd %d",
			  cmd, aicb, iocb, buf, rv, fd);
		goto out;
	}

	task->io_count++;

	/* don't reuse aicb->iocb or free the buf until we reap the event */
	aicb->used = 1;
	aicb->buf = buf;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = ioto;
 retry:
	memset(&event, 0, sizeof(event));

	rv = io_getevents(task->aio_ctx, 1, 1, &event, &ts);
	if (rv == -EINTR)
		goto retry;
	if (rv < 0) {
		log_taske(task, "aio getevent %p:%p:%p rv %d",
			  aicb, iocb, buf, rv);
		goto out;
	}
	if (rv == 1) {
		struct iocb *ev_iocb = event.obj;
		struct aicb *ev_aicb = container_of(ev_iocb, struct aicb, iocb);
		int op = ev_iocb ? ev_iocb->aio_lio_opcode : -1;

		if (op == IO_CMD_PREAD)
			op_str = "RD";
		else if (op == IO_CMD_PWRITE)
			op_str = "WR";
		else
			op_str = "UK";

		if (ms) {
			clock_gettime(CLOCK_MONOTONIC_RAW, &end);
			ts_diff(&begin, &end, &diff);
			*ms = (diff.tv_sec * 1000) + (diff.tv_nsec / 1000000);
		}

		ev_aicb->used = 0;

		if (ev_iocb != iocb) {
			log_taskw(task, "aio collect %s %p:%p:%p result %ld:%ld other free",
				  op_str, ev_aicb, ev_iocb, ev_aicb->buf, event.res, event.res2);
			free(ev_aicb->buf);
			ev_aicb->buf = NULL;
			goto retry;
		}
		if ((int)event.res < 0) {
			log_taskw(task, "aio collect %s %p:%p:%p result %ld:%ld match res",
				  op_str, ev_aicb, ev_iocb, ev_aicb->buf, event.res, event.res2);
			rv = event.res;
			goto out;
		}
		if (event.res != len) {
			log_taskw(task, "aio collect %s %p:%p:%p result %ld:%ld match len %d",
				  op_str, ev_aicb, ev_iocb, ev_aicb->buf, event.res, event.res2, len);
			rv = -EMSGSIZE;
			goto out;
		}

		/* standard success case */

		if (com.debug_io_complete) {
			len_str = align_size_debug_str(len);
			offset_to_str(offset, sizeof(off_str), off_str);

			if (ms) {
				memset(ms_str, 0, sizeof(ms_str));
				snprintf(ms_str, 7, "%u", *ms);
			}

			if (len_str)
				log_taskd(task, "%s %s at %s done %s",
					  op_str, len_str, off_str, ms ? ms_str : "");
			else
				log_taskd(task, "%s %d at %s done %s",
					  op_str, len, off_str, ms ? ms_str : "");
		}

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

	if (cmd == IO_CMD_PREAD)
		op_str = "RD";
	else if (cmd == IO_CMD_PWRITE)
		op_str = "WR";
	else
		op_str = "UK";

	log_taskw(task, "aio timeout %s %p:%p:%p ioto %d to_count %d",
		  op_str, aicb, iocb, buf, ioto, task->to_count);

	rv = io_cancel(task->aio_ctx, iocb, &event);
	if (!rv) {
		aicb->used = 0;
		rv = -ECANCELED;
	} else {
		/* aicb->used and aicb->buf both remain set */
		rv = SANLK_AIO_TIMEOUT;

		if (cmd == IO_CMD_PREAD)
			task->read_iobuf_timeout_aicb = aicb;
	}
 out:
	return rv;
}

static int do_write_aio_linux(int fd, uint64_t offset, char *buf, int len,
			      struct task *task, int ioto, int *wr_ms)
{
	return do_linux_aio(fd, offset, buf, len, task, ioto, IO_CMD_PWRITE, wr_ms);
}

static int do_read_aio_linux(int fd, uint64_t offset, char *buf, int len,
			     struct task *task, int ioto, int *rd_ms)
{
	return do_linux_aio(fd, offset, buf, len, task, ioto, IO_CMD_PREAD, rd_ms);
}

static int do_write_aio_posix(int fd, uint64_t offset, char *buf, int len,
			      struct task *task GNUC_UNUSED, int ioto)
{
	struct timespec ts;
	struct aiocb cb;
	struct aiocb const *p_cb;
	int rv;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = ioto;

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

static int do_read_aio_posix(int fd, uint64_t offset, char *buf, int len,
			     struct task *task GNUC_UNUSED, int ioto)
{
	struct timespec ts;
	struct aiocb cb;
	struct aiocb const *p_cb;
	int rv;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = ioto;

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

int write_iobuf(int fd, uint64_t offset, char *iobuf, int iobuf_len,
		struct task *task, int ioto, int *wr_ms)
{
	if (task && task->use_aio == 1)
		return do_write_aio_linux(fd, offset, iobuf, iobuf_len, task, ioto, wr_ms);
	else if (task && task->use_aio == 2)
		return do_write_aio_posix(fd, offset, iobuf, iobuf_len, task, ioto);
	else
		return do_write(fd, offset, iobuf, iobuf_len, task);
}

static int _write_sectors(const struct sync_disk *disk, int sector_size, uint64_t sector_nr,
			  uint32_t sector_count GNUC_UNUSED,
			  const char *data, int data_len, int iobuf_len,
			  struct task *task, int ioto,
			  const char *blktype)
{
	char *iobuf, **p_iobuf;
	uint64_t offset;
	int rv;

	offset = disk->offset + (sector_nr * sector_size);

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv) {
		log_error("write_sectors %s posix_memalign rv %d %s",
			  blktype, rv, disk->path);
		rv = -ENOMEM;
		goto out;
	}

	memset(iobuf, 0, iobuf_len);
	memcpy(iobuf, data, data_len);

	rv = write_iobuf(disk->fd, offset, iobuf, iobuf_len, task, ioto, NULL);
	if (rv < 0) {
		log_error("write_sectors %s offset %llu rv %d %s",
			  blktype, (unsigned long long)offset, rv, disk->path);
	}

	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);
 out:
	return rv;
}

/* sector_nr is logical sector number within the sync_disk.
   the sync_disk itself begins at disk->offset (in bytes) from
   the start of the block device identified by disk->path,
   data_len must be <= sector_size */

int write_sector(const struct sync_disk *disk, int sector_size, uint64_t sector_nr,
		 const char *data, int data_len,
		 struct task *task, int ioto,
		 const char *blktype)
{
	int iobuf_len = sector_size;

	if ((sector_size != 4096) && (sector_size != 512)) {
		log_error("write_sector bad sector_size %d", sector_size);
		return -EINVAL;
	}

	if (data_len > iobuf_len) {
		log_error("write_sector %s data_len %d max %d %s",
			  blktype, data_len, iobuf_len, disk->path);
		return -1;
	}

	return _write_sectors(disk, sector_size, sector_nr, 1, data, data_len,
			      iobuf_len, task, ioto, blktype);
}

/* write multiple complete sectors, data_len must be multiple of sector size */

int write_sectors(const struct sync_disk *disk, int sector_size, uint64_t sector_nr,
		  uint32_t sector_count, const char *data, int data_len,
		  struct task *task, int ioto,
		  const char *blktype)
{
	int iobuf_len = data_len;

	if ((sector_size != 4096) && (sector_size != 512)) {
		log_error("write_sectors bad sector_size %d", sector_size);
		return -EINVAL;
	}

	if (data_len != sector_count * sector_size) {
		log_error("write_sectors %s data_len %d sector_count %d %s",
			  blktype, data_len, sector_count, disk->path);
		return -1;
	}

	return _write_sectors(disk, sector_size, sector_nr, sector_count, data, data_len,
			      iobuf_len, task, ioto, blktype);
}

/* read aligned io buffer */

int read_iobuf(int fd, uint64_t offset, char *iobuf, int iobuf_len,
	       struct task *task, int ioto, int *rd_ms)
{
	if (task && task->use_aio == 1)
		return do_read_aio_linux(fd, offset, iobuf, iobuf_len, task, ioto, rd_ms);
	else if (task && task->use_aio == 2)
		return do_read_aio_posix(fd, offset, iobuf, iobuf_len, task, ioto);
	else
		return do_read(fd, offset, iobuf, iobuf_len, task);
}

/* read sector_count sectors starting with sector_nr, where sector_nr
   is a logical sector number within the sync_disk.  the caller will
   generally want to look at the first N bytes of each sector.
   when reading multiple sectors, data_len will generally equal iobuf_len,
   but when reading one sector, data_len may be less than iobuf_len. */

int read_sectors(const struct sync_disk *disk, int sector_size, uint64_t sector_nr,
	 	 uint32_t sector_count, char *data, int data_len,
		 struct task *task, int ioto,
		 const char *blktype)
{
	char *iobuf, **p_iobuf;
	uint64_t offset;
	int iobuf_len;
	int rv;

	if ((sector_size != 512) && (sector_size != 4096)) {
		log_error("read_sectors %s bad sector_size %d", blktype, sector_size);
		return -EINVAL;
	}

	iobuf_len = sector_count * sector_size;
	offset = disk->offset + (sector_nr * sector_size);

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv) {
		log_error("read_sectors %s posix_memalign rv %d %s",
			  blktype, rv, disk->path);
		rv = -ENOMEM;
		goto out;
	}

	memset(iobuf, 0, iobuf_len);

	rv = read_iobuf(disk->fd, offset, iobuf, iobuf_len, task, ioto, NULL);
	if (!rv) {
		memcpy(data, iobuf, data_len);
	} else {
		log_error("read_sectors %s offset %llu rv %d %s",
			  blktype, (unsigned long long)offset, rv, disk->path);
	}

	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);
 out:
	return rv;
}

/* Try to reap the event of a previously timed out read_iobuf.
   The aicb used in a task's last timed out read_iobuf is
   task->read_iobuf_timeout_aicb . */

int read_iobuf_reap(int fd, uint64_t offset, char *iobuf, int iobuf_len,
		    struct task *task, uint32_t ioto_msec)
{
	struct timespec ts;
	struct aicb *aicb;
	struct iocb *iocb;
	struct io_event event;
	int rv;

	aicb = task->read_iobuf_timeout_aicb;
	iocb = &aicb->iocb;

	if (!aicb->used)
		return -EINVAL;
	if (iocb->aio_fildes != fd)
		return -EINVAL;
	if (iocb->u.c.buf != iobuf)
		return -EINVAL;
	if (iocb->u.c.nbytes != iobuf_len)
		return -EINVAL;
	if (iocb->u.c.offset != offset)
		return -EINVAL;
	if (iocb->aio_lio_opcode != IO_CMD_PREAD)
		return -EINVAL;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = ioto_msec / 1000;
	ts.tv_nsec = (ioto_msec % 1000) * 1000000;
 retry:
	memset(&event, 0, sizeof(event));

	rv = io_getevents(task->aio_ctx, 1, 1, &event, &ts);
	if (rv == -EINTR)
		goto retry;
	if (rv < 0) {
		log_taske(task, "aio getevent %p:%p:%p rv %d r",
			  aicb, iocb, iobuf, rv);
		goto out;
	}
	if (rv == 1) {
		struct iocb *ev_iocb = event.obj;
		struct aicb *ev_aicb = container_of(ev_iocb, struct aicb, iocb);
		int op = ev_iocb ? ev_iocb->aio_lio_opcode : -1;
		const char *op_str;

		if (op == IO_CMD_PREAD)
			op_str = "RD";
		else if (op == IO_CMD_PWRITE)
			op_str = "WR";
		else
			op_str = "UK";

		ev_aicb->used = 0;

		if (ev_iocb != iocb) {
			log_taskw(task, "aio collect %s %p:%p:%p result %ld:%ld other free r",
				  op_str, ev_aicb, ev_iocb, ev_aicb->buf, event.res, event.res2);
			free(ev_aicb->buf);
			ev_aicb->buf = NULL;
			goto retry;
		}
		if ((int)event.res < 0) {
			log_taskw(task, "aio collect %s %p:%p:%p result %ld:%ld match res r",
				  op_str, ev_aicb, ev_iocb, ev_aicb->buf, event.res, event.res2);
			rv = event.res;
			goto out;
		}
		if (event.res != iobuf_len) {
			log_taskw(task, "aio collect %s %p:%p:%p result %ld:%ld match len %d r",
				  op_str, ev_aicb, ev_iocb, ev_aicb->buf, event.res, event.res2, iobuf_len);
			rv = -EMSGSIZE;
			goto out;
		}

		log_taskw(task, "aio collect %s %p:%p:%p result %ld:%ld match reap",
			  op_str, ev_aicb, ev_iocb, ev_aicb->buf, event.res, event.res2);

		rv = 0;
		goto out;
	}

	/* timed out again */
	rv = SANLK_AIO_TIMEOUT;
 out:
	return rv;
}

