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
#include "disk_paxos.h"
#include "token_manager.h"
#include "watchdog.h"
#include "lockfile.h"
#include "log.h"
#include "diskio.h"
#include "host_id.h"
#include "delta_lease.h"

struct lease_status {
	int acquire_last_result;
	int renewal_last_result;
	int release_last_result;
	uint64_t acquire_last_time;
	uint64_t acquire_good_time;
	uint64_t renewal_last_time;
	uint64_t renewal_good_time;
	uint64_t release_last_time;
	uint64_t release_good_time;
};

static struct lease_status our_lease_status;
static pthread_t our_host_id_thread;
static pthread_mutex_t host_id_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t host_id_cond = PTHREAD_COND_INITIALIZER;
static int our_host_id_thread_stop;
static struct sync_disk host_id_disk;

/*
 * read lease of host_id, see if it has been renewed within timeout
 */

int host_id_alive(uint64_t host_id)
{
	uint64_t last_good, sec;
	int rv;

	rv = delta_lease_read_timestamp(&host_id_disk, host_id, &last_good);
	if (rv < 0)
		return rv;

	sec = time(NULL) - last_good;

	if (sec >= to.host_id_timeout_seconds) {
		return 0;
	}

	return 1;
}

/*
 * check if our_host_id_thread has renewed within timeout
 */

int our_host_id_renewed(void)
{
	uint64_t last_good, sec;

	pthread_mutex_lock(&host_id_mutex);
	last_good = our_lease_status.renewal_last_time;
	pthread_mutex_unlock(&host_id_mutex);

	sec = time(NULL) - last_good;

	if (sec >= to.host_id_renewal_fail_seconds) {
		return 0;
	}

	return 1;
}

static void *host_id_thread(void *arg GNUC_UNUSED)
{
	struct timespec ts;
	uint64_t t;
	int rv, stop;

	rv = delta_lease_acquire(&host_id_disk, options.our_host_id);

	t = time(NULL);

	pthread_mutex_lock(&host_id_mutex);
	our_lease_status.acquire_last_result = rv;
	our_lease_status.acquire_last_time = t;
	if (rv == 1)
		our_lease_status.acquire_good_time = t;
	our_lease_status.renewal_last_result = rv;
	our_lease_status.renewal_last_time = t;
	if (rv == 1)
		our_lease_status.renewal_good_time = t;
	pthread_cond_broadcast(&host_id_cond);
	pthread_mutex_unlock(&host_id_mutex);

	if (rv < 0)
		goto out;

	/* create_watchdog_file(t); */

	while (1) {
		pthread_mutex_lock(&host_id_mutex);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += to.host_id_renewal_seconds;
		rv = 0;
		while (!our_host_id_thread_stop && rv == 0) {
			rv = pthread_cond_timedwait(&host_id_cond,
						    &host_id_mutex, &ts);
		}
		stop = our_host_id_thread_stop;
		pthread_mutex_unlock(&host_id_mutex);
		if (stop)
			break;

		rv = delta_lease_renew(&host_id_disk, options.our_host_id);

		pthread_mutex_lock(&host_id_mutex);
		our_lease_status.renewal_last_result = rv;
		our_lease_status.renewal_last_time = t;
		if (rv == 1)
			our_lease_status.renewal_good_time = t;
		pthread_mutex_unlock(&host_id_mutex);

		if (rv < 0) {
			continue;
		}

		/* update_watchdog_file(t); */
	}

	/* unlink_watchdog_file(); */

	delta_lease_release(&host_id_disk, options.our_host_id);
 out:
	return NULL;
}

/* 
 * - create host_id_thread for our_host_id
 * - wait for host_id_thread delta_lease_acquire result
 */

int start_host_id(void)
{
	int rv, result;

	memset(&host_id_disk, 0, sizeof(struct sync_disk));

	strncpy(host_id_disk.path, options.host_id_path, DISK_PATH_LEN);
	host_id_disk.offset = options.host_id_offset;

	rv = open_disks(&host_id_disk, 1);
	if (rv != 1) {
		return -1;
	}

	memset(&our_lease_status, 0, sizeof(struct lease_status));

	log_debug(NULL, "start_host_id %d host_id_path %s offset %d",
		  options.our_host_id, options.host_id_path, options.host_id_offset);

	rv = pthread_create(&our_host_id_thread, NULL, host_id_thread, NULL);
	if (rv)
		return -1;

	pthread_mutex_lock(&host_id_mutex);
	while (!our_lease_status.acquire_last_result) {
		pthread_cond_wait(&host_id_cond, &host_id_mutex);
	}
	result = our_lease_status.acquire_last_result;
	pthread_mutex_unlock(&host_id_mutex);

	if (result == 1)
		return 0;
	return -1;
}

void stop_host_id(void)
{
	pthread_mutex_lock(&host_id_mutex);
	our_host_id_thread_stop = 1;
	pthread_cond_broadcast(&host_id_cond);
	pthread_mutex_unlock(&host_id_mutex);
	pthread_join(our_host_id_thread, NULL);
	close_disks(&host_id_disk, 1);
}

