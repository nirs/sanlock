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
#include <pthread.h>
#include <time.h>
#include <dirent.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "sanlock_internal.h"
#include "log.h"
#include "watchdog.h"

/*
 * Purpose of watchdog: to forcibly reset the host in the case where a
 * supervised pid is running but sanlock daemon does not renew its lease
 * and does not kill the pid (or it kills the pid but the pid does not
 * exit).  So, just before the pid begins running with granted leases,
 * /dev/watchdog needs to be armed to reboot the host if things go bad right
 * after the pid goes ahead.
 */

#ifdef USE_WDMD

#include "../wdmd/wdmd.h"

static int daemon_wdmd_con;

void update_watchdog_file(struct space *sp, uint64_t timestamp)
{
	int rv;

	if (!options.use_watchdog)
		return;

	rv = wdmd_test_live(sp->wd_fd, timestamp, timestamp + to.host_id_renewal_fail_seconds);
	if (rv < 0)
		log_erros(sp, "wdmd_test_live failed %d", rv);
}

int create_watchdog_file(struct space *sp, uint64_t timestamp)
{
	char name[WDMD_NAME_SIZE];
	int con, rv;

	if (!options.use_watchdog)
		return 0;

	con = wdmd_connect();
	if (con < 0) {
		log_erros(sp, "wdmd connect failed %d", con);
		goto fail;
	}

	memset(name, 0, sizeof(name));

	snprintf(name, WDMD_NAME_SIZE - 1, "sanlock_%s_hostid%llu",
		 sp->space_name, (unsigned long long)sp->host_id);

	rv = wdmd_register(con, name);
	if (rv < 0) {
		log_erros(sp, "wdmd register failed %d", rv);
		goto fail_close;
	}

	rv = wdmd_test_live(con, timestamp, timestamp + to.host_id_renewal_fail_seconds);
	if (rv < 0) {
		log_erros(sp, "wdmd_test_live failed %d", rv);
		goto fail_close;
	}

	sp->wd_fd = con;
	return 0;

 fail_close:
	close(con);
 fail:
	return -1;
}

void unlink_watchdog_file(struct space *sp)
{
	int rv;

	if (!options.use_watchdog)
		return;

	rv = wdmd_test_live(sp->wd_fd, 0, 0);
	if (rv < 0)
		log_erros(sp, "wdmd_test_live failed %d", rv);
}

void close_watchdog_file(struct space *sp)
{
	if (!options.use_watchdog)
		return;

	close(sp->wd_fd);
}

void close_watchdog(void)
{
	if (!options.use_watchdog)
		return;

	wdmd_refcount_clear(daemon_wdmd_con);
	close(daemon_wdmd_con);
}

/* TODO: add wdmd connection as client so poll detects if it fails? */

int setup_watchdog(void)
{
	char name[WDMD_NAME_SIZE];
	int test_interval, fire_timeout;
	uint64_t last_keepalive;
	int con, rv;

	if (!options.use_watchdog)
		return 0;

	memset(name, 0, sizeof(name));

	snprintf(name, WDMD_NAME_SIZE - 1, "%s", "sanlock_daemon");

	con = wdmd_connect();
	if (con < 0) {
		log_error("wdmd connect failed for watchdog handling");
		goto fail;
	}

	rv = wdmd_register(con, name);
	if (rv < 0) {
		log_error("wdmd register failed");
		goto fail_close;
	}

	rv = wdmd_refcount_set(con);
	if (rv < 0) {
		log_error("wdmd refcount failed");
		goto fail_close;
	}

	rv = wdmd_status(con, &test_interval, &fire_timeout, &last_keepalive);
	if (rv < 0) {
		log_error("wdmd status failed");
		goto fail_clear;
	}

	log_debug("wdmd test_interval %d fire_timeout %d last_keepalive %llu",
		  test_interval, fire_timeout,
		  (unsigned long long)last_keepalive);

	if (to.host_id_renewal_fail_seconds + fire_timeout !=
	    to.host_id_timeout_seconds) {
		log_error("invalid timeout settings "
			  "host_id_renewal_fail %d "
			  "fire_timeout %d "
			  "host_id_timeout %d",
			  to.host_id_renewal_fail_seconds,
			  fire_timeout,
			  to.host_id_timeout_seconds);
		goto fail_clear;
	}

	daemon_wdmd_con = con;
	return 0;

 fail_clear:
	wdmd_refcount_clear(con);
 fail_close:
	close(con);
 fail:
	return -1;
}

int do_wdtest(void)
{
	return -1;
}

#else

#define BUF_SIZE 128

static int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

 retry:
	rv = write(fd, (char *)buf + off, count);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0) {
		return -errno;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}

void update_watchdog_file(struct space *sp, uint64_t timestamp)
{
	char buf[BUF_SIZE];

	if (!options.use_watchdog)
		return;

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "renewal %llu expire %llu\n",
		 (unsigned long long)timestamp,
		 (unsigned long long)timestamp + to.host_id_renewal_fail_seconds);

	lseek(sp->wd_fd, 0, SEEK_SET);

	do_write(sp->wd_fd, buf, sizeof(buf));
}

int create_watchdog_file(struct space *sp, uint64_t timestamp)
{
	char buf[BUF_SIZE];
	int rv, fd;

	if (!options.use_watchdog)
		return 0;

	snprintf(sp->wdtest_path, PATH_MAX, "%s/%s_hostid%llu",
		 SANLK_WDTEST_DIR, sp->space_name,
		 (unsigned long long)sp->host_id);

	/* If this open fails with EEXIST I don't think it's safe to unlink
	 * watchdog_path and try again.  If the daemon had failed while pid's
	 * remained running, then the daemon is restarted (before watchdog
	 * triggers) and we start renewing host_id again and get here.  If we
	 * were to unlink the wd file right here, and then the daemon failed
	 * again, we'd possibly be left with pid's running that had been
	 * connected to the previous daemon instance, and the watchdog file
	 * unlinked, so the watchdog won't reset us.
	 *
	 * If the open fails with EEXIST we could open the existing file and go
	 * on, although there's currently no mechanism to reattach to any
	 * running pid's we're supposed to be supervising. */

	fd = open(sp->wdtest_path, O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK, 0666);
	if (fd < 0) {
		log_erros(sp, "create_watchdog_file open %s error %d",
			  sp->wdtest_path, errno);
		return fd;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "renewal %llu expire %llu\n",
		 (unsigned long long)timestamp,
		 (unsigned long long)timestamp + to.host_id_renewal_fail_seconds);

	rv = do_write(fd, buf, sizeof(buf));
	if (rv < 0) {
		log_erros(sp, "create_watchdog_file write error %d", rv);
		close(fd);
		return rv;
	}

	sp->wd_fd = fd;
	return 0;
}

void unlink_watchdog_file(struct space *sp)
{
	if (!options.use_watchdog)
		return;

	unlink(sp->wdtest_path);
}

void close_watchdog_file(struct space *sp)
{
	close(sp->wd_fd);
}

void close_watchdog(void)
{
}

int setup_watchdog(void)
{
	DIR *d;
	struct dirent *de;
	int rv = 0;

	if (!options.use_watchdog)
		return 0;

	d = opendir(SANLK_WDTEST_DIR);
	if (!d)
		return 0;

	while ((de = readdir(d))) {
		if (de->d_name[0] == '.')
			continue;

		log_error("stale wdtest file: %s/%s",
			  SANLK_WDTEST_DIR, de->d_name);
		rv = -1;
	}
	closedir(d);

	return rv;
}

int do_wdtest(void)
{		
	DIR *d;
	struct dirent *de;
	char path[PATH_MAX];
	char buf[BUF_SIZE];
	unsigned long long renewal = 0, expire = 0;
	time_t t;
	int fail_count = 0;
	int rv, fd;

	openlog("sanlock_wdtest", LOG_CONS | LOG_PID, LOG_USER);

	d = opendir(SANLK_WDTEST_DIR);
	if (!d)
		return 0;

	while ((de = readdir(d))) {
		if (de->d_name[0] == '.')
			continue;

		snprintf(path, PATH_MAX-1, "%s/%s",
			 SANLK_WDTEST_DIR, de->d_name);

		fd = open(path, O_RDONLY|O_NONBLOCK, 0666);
		if (fd < 0) {
			syslog(LOG_ERR, "open error %s", path);
			continue;
		}

		memset(buf, 0, sizeof(buf));
		rv = read(fd, buf, sizeof(buf));
		if (rv < 0) {
			syslog(LOG_ERR, "read error %s", path);
			close(fd);
			continue;
		}

		close(fd);

		sscanf(buf, "renewal %llu expire %llu", &renewal, &expire);

		t = time(NULL);

		/* TODO: remove this line, just for debugging */
		syslog(LOG_ERR, "%s renewal %llu expire %llu now %llu",
		       path,
	       	       (unsigned long long)renewal,
		       (unsigned long long)expire,
	               (unsigned long long)t);

		if (t < expire)
			continue;

		syslog(LOG_CRIT, "%s test fail renewal %llu expire %llu now %llu",
		       path,
		       (unsigned long long)renewal,
		       (unsigned long long)expire,
		       (unsigned long long)t);

		fail_count++;
	}
	closedir(d);

	if (fail_count)
		return -1;
	return 0;
}
#endif
