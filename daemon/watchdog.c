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
#include "sm_msg.h"
#include "watchdog.h"
#include "token_manager.h"
#include "disk_paxos.h"
#include "sm_options.h"
#include "log.h"

struct wd_file {
	int token_id;
	int fd;
	struct lease_status last_status;
};

struct wd_status {
	int token_id;
	int unlinked;
	int write_result;
	time_t write_time;
	char resource_name[NAME_ID_SIZE + 1];
};

/* wd_files[] is internal to wd_thread and is not locked,
   wd_status[], wd_thread_stop, wd_new_token_id are shared
   and protected by wd_mutex */

static pthread_t wd_thread;
static int wd_thread_stop;
static int wd_new_token_id;
static struct wd_file wd_files[MAX_LEASES];
static struct wd_status wd_status[MAX_LEASES];
static pthread_mutex_t wd_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wd_cond = PTHREAD_COND_INITIALIZER;

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
 * wd_thread writes RT to wd file
 * watchdogd sees recent timestamp and does not reset host
 *
 * things go ok:
 * lease_thread cannot renew lease
 * main thread kills pid
 * pid exits
 * wd file unlinked
 * watchdogd does not check unlinked wd file and does not reset host
 */

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

/* wd_mutex must be held */

static int _token_id_to_index(int token_id, int *idx)
{
	int i;

	for (i = 0; i < MAX_LEASES; i++) {
		if (wd_status[i].token_id != token_id)
			continue;
		*idx = i;
		return 0;
	}
	return -1;
}

static int set_wd_status(int token_id, int idx, char *resource_name, int rv)
{
	pthread_mutex_lock(&wd_mutex);
	if (wd_status[idx].token_id &&
	    wd_status[idx].token_id != token_id) {
		pthread_mutex_unlock(&wd_mutex);
		/* error, it should be zero on first set or the same */
		log_error(NULL, "set_wd_status");
		return -1;
	}
	if (resource_name)
		strncpy(wd_status[idx].resource_name, resource_name, NAME_ID_SIZE);
	wd_status[idx].token_id = token_id;
	wd_status[idx].write_result = rv;
	wd_status[idx].write_time = time(NULL);
	pthread_mutex_unlock(&wd_mutex);
	return 0;
}

static int set_wd_status_unlinked(int token_id)
{
	int rv, idx;

	pthread_mutex_lock(&wd_mutex);
	rv = _token_id_to_index(token_id, &idx);
	if (rv < 0) {
		pthread_mutex_unlock(&wd_mutex);
		log_error(NULL, "set_wd_status_unlinked");
		return -1;
	}
	wd_status[idx].unlinked = 1;
	pthread_cond_broadcast(&wd_cond);
	pthread_mutex_unlock(&wd_mutex);
	return 0;
}

static void clear_wd_status(int token_id, int idx)
{
	pthread_mutex_lock(&wd_mutex);
	if (wd_status[idx].token_id != token_id) {
		pthread_mutex_unlock(&wd_mutex);
		log_error(NULL, "clear_wd_status");
		return;
	}
	memset(&wd_status[idx], 0, sizeof(struct wd_status));
	pthread_mutex_unlock(&wd_mutex);
}

/* return -1 if token_id not found */

static int get_wd_status(int token_id, int idx_in, struct wd_status *wstat,
			 int *stop)
{
	int idx = idx_in;
	int rv;

	pthread_mutex_lock(&wd_mutex);
	*stop = wd_thread_stop;

	if (idx == -1) {
		rv = _token_id_to_index(token_id, &idx);
		if (rv < 0) {
			/* this is used to wait for clear_wd_status */
			pthread_mutex_unlock(&wd_mutex);
			return -1;
		}
	}

	if (wd_status[idx].token_id != token_id) {
		pthread_mutex_unlock(&wd_mutex);
		log_error(NULL, "get_wd_status");
		return -1;
	}

	memcpy(wstat, &wd_status[idx], sizeof(struct wd_status));
	pthread_mutex_unlock(&wd_mutex);
	return 0;
}

static void *watchdog_thread(void *arg GNUC_UNUSED)
{
	struct timespec update_time;
	struct lease_status status;
	struct wd_status wstat;
	char path[PATH_MAX];
	char buf[32];
	int i, rv, fd, stop, unused;
	int new_token_id;

	clock_gettime(CLOCK_REALTIME, &update_time);

	while (1) {
		pthread_mutex_lock(&wd_mutex);
		update_time.tv_sec += to.wd_update_seconds;
		rv = 0;
		while (!wd_thread_stop && rv == 0) {
			rv = pthread_cond_timedwait(&wd_cond, &wd_mutex,
						    &update_time);
		}
		stop = wd_thread_stop;
		new_token_id = wd_new_token_id;
		wd_new_token_id = 0;
		pthread_mutex_unlock(&wd_mutex);
		if (stop)
			break;

		/* update time stamp in wd files */

		clock_gettime(CLOCK_REALTIME, &update_time);

		for (i = 0; i < MAX_LEASES; i++) {
			if (!wd_files[i].token_id)
				continue;

			memset(&status, 0, sizeof(struct lease_status));

			get_lease_status(wd_files[i].token_id, &status);

			if (status.renewal_good_time ==
			    wd_files[i].last_status.renewal_good_time)
				continue;

			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), "%llu",
				 (unsigned long long)status.renewal_good_time);

			rv = do_write(fd, buf, sizeof(buf));
			if (rv < 0) {
				log_error(NULL, "wd write %d", rv);
				continue;
			}

			memcpy(&wd_files[i].last_status, &status,
			       sizeof(struct lease_status));

			set_wd_status(wd_files[i].token_id, i, NULL, rv);
		}

		/* check for wd files that have been unlinked */

		for (i = 0; i < MAX_LEASES; i++) {
			if (!wd_files[i].token_id)
				continue;

			rv = get_wd_status(wd_files[i].token_id, i, &wstat, &unused);
			if (rv < 0)
				continue;

			if (wstat.unlinked) {
				close(wd_files[i].fd);
				memset(&wd_files[i], 0, sizeof(struct wd_file));
				clear_wd_status(wstat.token_id, i);
			}
		}

		/* check for new token that needs a wd file */

		if (new_token_id) {
			/* get resource_name, index and acquire_time */
			get_lease_status(new_token_id, &status);

			i = status.token_idx;

			if (wd_files[i].token_id) {
				log_error(NULL, "wd idx %d used", i);
				continue;
			}

			/* open the wd file, write time */

			snprintf(path, PATH_MAX, "%s/%s_%d",
				 DAEMON_WATCHDOG_DIR, options.sm_id,
				 new_token_id);

			fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK, 0666);
			if (fd < 0) {
			}

			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), "%llu",
				 (unsigned long long)status.renewal_good_time);

			rv = do_write(fd, buf, sizeof(buf));
			if (rv < 0) {
				log_error(NULL, "wd write %d", rv);
				continue;
			}

			wd_files[i].token_id = new_token_id;
			wd_files[i].fd = fd;
			memcpy(&wd_files[i].last_status, &status,
			       sizeof(struct lease_status));

			set_wd_status(wd_files[i].token_id, i,
				      status.resource_name, rv);
		}

		/* TODO: warn here if current time is too far beyond
		   update_time */
	}
	return NULL;
}

/* ask wd thread to create the file containing acquire time,
 * wait for the thread to complete before returning */

/* this is called from both main thread and cmd_acquire_thread, in both
 * cases this is called after waiting for the lease to be acquired */

int create_watchdog_file(int token_id)
{
	struct wd_status wstat;
	int rv, stop;

	if (!options.opt_watchdog)
		return 0;

	/* ask wd thread to create the file for this token */
	pthread_mutex_lock(&wd_mutex);
	if (wd_new_token_id) {
		log_error(NULL, "create_watchdog_file collision %d %d",
			  wd_new_token_id, token_id);
		pthread_mutex_unlock(&wd_mutex);
		return -1;
	}
	wd_new_token_id = token_id;
	pthread_cond_broadcast(&wd_cond);
	pthread_mutex_unlock(&wd_mutex);

	memset(&wstat, 0, sizeof(struct wd_status));

	/* wait for wd thread to finish writing the wd file */
	while (1) {
		rv = get_wd_status(token_id, -1, &wstat, &stop);
		if (stop)
			return -1;

		if (!rv && wstat.write_time)
			break;

		usleep(500000);
	}

	return wstat.write_result;
}

/* called from cmd_acquire_thread */

void unlink_watchdog_file(int token_id)
{
	char path[PATH_MAX];
	struct wd_status wstat;
	int stop, rv;

	if (!options.opt_watchdog)
		return;

	snprintf(path, PATH_MAX, "%s/%s_%d", DAEMON_WATCHDOG_DIR,
		 options.sm_id, token_id);

	unlink(path);

	/* ask wd thread to clean up the wd_file for this token */

	set_wd_status_unlinked(token_id);

	/* wait for wd thread to finish cleaning up the wd file */

	memset(&wstat, 0, sizeof(struct wd_status));

	while (1) {
		rv = get_wd_status(token_id, -1, &wstat, &stop);
		if (stop)
			return;

		if (rv == -1)
			break;

		usleep(500000);
	}
}

void unlink_all_watchdogs(void)
{
	char path[PATH_MAX];
	int i;

	if (!options.opt_watchdog)
		return;

	pthread_mutex_lock(&wd_mutex);
	for (i = 0; i < MAX_LEASES; i++) {
		snprintf(path, PATH_MAX, "%s/%s_%d", DAEMON_WATCHDOG_DIR,
			 options.sm_id, wd_status[i].token_id);

		unlink(path);
	}
	pthread_mutex_unlock(&wd_mutex);
}

void stop_watchdog_thread(void)
{
	void *ret;

	if (!options.opt_watchdog)
		return;

	pthread_mutex_lock(&wd_mutex);
	wd_thread_stop = 1;
	pthread_cond_broadcast(&wd_cond);
	pthread_mutex_unlock(&wd_mutex);
	pthread_join(wd_thread, &ret);
}

int start_watchdog_thread(void)
{
	pthread_attr_t attr;
	int rv;

	if (!options.opt_watchdog)
		return 0;

	pthread_attr_init(&attr);
	rv = pthread_create(&wd_thread, &attr, watchdog_thread, NULL);
	pthread_attr_destroy(&attr);
	if (rv < 0) {
		log_error(NULL, "create wd_thread failed %d", rv);
		return rv;
	}
	return 0;
}

