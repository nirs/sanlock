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
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sm.h"
#include "watchdog.h"

/* 
 * Purpose of watchdog: to forcibly reset the host in the case where a
 * supervised pid is running but sync_manager does not renew its lease
 * and does not kill the pid (or it kills the pid but the pid does not
 * exit).  So, just before the pid begins running, watchdogd needs to be
 * armed to reboot the host if things go bad right after the pid starts.
 *
 * The initial timestamp in the wd file should be set to the acquire_time
 * just before sm forks the supervised pid.  If sm acquires the lease,
 * creates the wd file containing acquire_time, forks the pid, fails to
 * ever update the wd file, and cannot kill the pid, watchdogd will reboot
 * the host before acquire_time + lease_timeout_seconds, when another host
 * could acquire the lease.
 *
 * lease acquired at time AT
 * wd file created containing AT
 * pid forked
 * ...
 *
 * things go bad:
 * lease_thread cannot renew lease
 * main thread cannot kill pid
 * watchdogd will reset host in AT + X seconds
 *
 * things go good:
 * lease_thread renews lease at time RT
 * lease_thread writes RT to wd file
 * watchdogd sees recent timestamp and does not reset host
 *
 * things go ok:
 * lease_thread cannot renew lease
 * main thread kills pid
 * pid exits
 * stop_all_leases stops lease_thread
 * lease_thread unlinks wd file
 * watchdogd does not check unlinked wd file and does not reset host
 */

static char watchdog_path[PATH_MAX];
static int watchdog_fd;

static int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

 retry:
	rv = write(fd, (char *)buf + off, count);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0) {
		return rv;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}

void update_watchdog_file(uint64_t timestamp)
{
	char buf[16];

	if (!options.use_watchdog)
		return;

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%llu", (unsigned long long)timestamp);

	lseek(watchdog_fd, 0, SEEK_SET);

	do_write(watchdog_fd, buf, sizeof(buf));
}

int create_watchdog_file(uint64_t timestamp)
{
	char buf[16];
	int rv, fd;

	if (!options.use_watchdog)
		return 0;

	snprintf(watchdog_path, PATH_MAX, "%s/%s",
		 DAEMON_WATCHDOG_DIR, DAEMON_NAME);

	fd = open(watchdog_path, O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK, 0666);
	if (fd < 0)
		return fd;

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%llu", (unsigned long long)timestamp);

	rv = do_write(fd, buf, sizeof(buf));
	if (rv < 0) {
		close(fd);
		return rv;
	}

	watchdog_fd = fd;
	return 0;
}

void unlink_watchdog_file(void)
{
	if (!options.use_watchdog)
		return;

	unlink(watchdog_path);
	close(watchdog_fd);
}

