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
#include <sys/socket.h>
#include <sys/un.h>

#include "sanlock_internal.h"
#include "sanlock_sock.h"
#include "log.h"
#include "lockfile.h"

int lockfile(const char *dir, const char *name)
{
	char path[PATH_MAX];
	char buf[16];
	struct flock lock;
	mode_t old_umask;
	int fd, rv;

	old_umask = umask(0022);
	rv = mkdir(SANLK_RUN_DIR, 0777);
	if (rv < 0 && errno != EEXIST) {
		umask(old_umask);
		return rv;
	}
	umask(old_umask);

	snprintf(path, PATH_MAX, "%s/%s", dir, name);

	fd = open(path, O_CREAT|O_WRONLY|O_CLOEXEC, 0666);
	if (fd < 0) {
		log_error("lockfile open error %s: %s",
			  path, strerror(errno));
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	rv = fcntl(fd, F_SETLK, &lock);
	if (rv < 0) {
		log_error("lockfile setlk error %s: %s",
			  path, strerror(errno));
		goto fail;
	}

	rv = ftruncate(fd, 0);
	if (rv < 0) {
		log_error("lockfile truncate error %s: %s",
			  path, strerror(errno));
		goto fail;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d\n", getpid());

	rv = write(fd, buf, strlen(buf));
	if (rv <= 0) {
		log_error("lockfile write error %s: %s",
			  path, strerror(errno));
		goto fail;
	}

	return fd;
 fail:
	close(fd);
	return -1;
}

void unlink_lockfile(int fd, const char *dir, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", dir, name);
	unlink(path);
	close(fd);
}

