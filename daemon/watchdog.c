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
 * watchdogd needs to be armed to reboot the host if things go bad right
 * after the pid goes ahead.
 *
 * The initial timestamp in the wd file should be set to the acquire_time
 * just before the daemon allows any pids to go ahead running with leases.
 *
 * If the daemon acquires its lease, creates the wd file containing
 * acquire_time, grants lease to a pid, fails to ever update the wd file,
 * and cannot kill the pid, watchdogd will reboot the host before
 * acquire_time + host_id_timeout_seconds, when another host could acquire
 * the lease.
 *
 * lease acquired at time AT
 * wd file created containing AT
 * pid starts running with granted lease
 * ...
 *
 * things go bad:
 * host_id_thread cannot renew lease
 * main thread cannot kill pid
 * watchdogd will reset host in AT + X seconds
 *
 * things go good:
 * host_id_thread renews lease at time RT
 * host_id_thread writes RT to wd file
 * watchdogd sees recent timestamp, pets wd device, host is not reset
 *
 * things go ok:
 * host_id_thread cannot renew lease
 * main thread kills pid
 * pid exits
 * stop_host_id unlinks wd file and stops host_id_thread
 * watchdogd does not see wd file with old time and does not reset host
 */

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

	lseek(sp->wdtest_fd, 0, SEEK_SET);

	do_write(sp->wdtest_fd, buf, sizeof(buf));
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
		log_error(NULL, "create_watchdog_file open %s error %d",
			  sp->wdtest_path, errno);
		return fd;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "renewal %llu expire %llu\n",
		 (unsigned long long)timestamp,
		 (unsigned long long)timestamp + to.host_id_renewal_fail_seconds);

	rv = do_write(fd, buf, sizeof(buf));
	if (rv < 0) {
		log_error(NULL, "create_watchdog_file write error %d", rv);
		close(fd);
		return rv;
	}

	sp->wdtest_fd = fd;
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
	close(sp->wdtest_fd);
}

int check_watchdog_file(void)
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

		log_error(NULL, "stale wdtest file: %s/%s",
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

