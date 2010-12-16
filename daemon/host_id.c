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

#include "sanlock_internal.h"
#include "diskio.h"
#include "leader.h"
#include "log.h"
#include "delta_lease.h"
#include "host_id.h"
#include "watchdog.h"

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
	uint64_t last_good;
	uint32_t sec;

	pthread_mutex_lock(&host_id_mutex);
	last_good = our_lease_status.renewal_good_time;
	pthread_mutex_unlock(&host_id_mutex);

	/* host_id hasn't been started yet */
	if (!last_good)
		return 1;

	sec = time(NULL) - last_good;

	if (sec >= to.host_id_renewal_fail_seconds) {
		log_error(NULL, "our_host_id_renewed failed %u", sec);
		return 0;
	}

	return 1;
}

static void *host_id_thread(void *arg_in)
{
	struct timespec renew_time;
	uint64_t t;
	uint64_t *arg = (uint64_t *)arg_in;
	uint64_t host_id_in = (uint64_t)(*arg);
	int rv, stop, result, dl_result;

	free(arg);

	result = delta_lease_acquire(&host_id_disk, host_id_in, &t);

	dl_result = result;

	/* we need to start the watchdog after we acquire the host_id but
	   before we allow any pid's to begin running */

	if (result == DP_OK) {
		rv = create_watchdog_file(t);
		if (rv < 0) {
			log_error(NULL, "create_watchdog failed %d", rv);
			result = DP_ERROR;
		}
	}

	pthread_mutex_lock(&host_id_mutex);
	our_lease_status.acquire_last_result = result;
	our_lease_status.acquire_last_time = t;
	if (result == DP_OK)
		our_lease_status.acquire_good_time = t;
	our_lease_status.renewal_last_result = result;
	our_lease_status.renewal_last_time = t;
	if (result == DP_OK)
		our_lease_status.renewal_good_time = t;
	pthread_cond_broadcast(&host_id_cond);
	pthread_mutex_unlock(&host_id_mutex);

	if (result < 0) {
		log_error(NULL, "host_id %llu acquire failed %d",
			  (unsigned long long)host_id_in, result);
		goto out;
	}

	log_debug(NULL, "host_id %llu acquire %llu",
		  (unsigned long long)host_id_in, (unsigned long long)t);

	clock_gettime(CLOCK_REALTIME, &renew_time);

	while (1) {
		pthread_mutex_lock(&host_id_mutex);
		renew_time.tv_sec += to.host_id_renewal_seconds;
		rv = 0;
		while (!our_host_id_thread_stop && rv == 0) {
			rv = pthread_cond_timedwait(&host_id_cond,
						    &host_id_mutex,
						    &renew_time);
		}
		stop = our_host_id_thread_stop;
		pthread_mutex_unlock(&host_id_mutex);
		if (stop)
			break;

		clock_gettime(CLOCK_REALTIME, &renew_time);

		result = delta_lease_renew(&host_id_disk, host_id_in, &t);

		pthread_mutex_lock(&host_id_mutex);
		our_lease_status.renewal_last_result = result;
		our_lease_status.renewal_last_time = t;
		if (result == DP_OK)
			our_lease_status.renewal_good_time = t;
		pthread_mutex_unlock(&host_id_mutex);

		if (result < 0) {
			log_error(NULL, "host_id %llu renewal failed %d",
				  (unsigned long long)host_id_in, result);
			continue;
		}

		log_debug(NULL, "host_id %llu renewal %llu",
			  (unsigned long long)host_id_in, (unsigned long long)t);

		update_watchdog_file(t);
	}

	/* called below to get it done ASAP */
	/* unlink_watchdog_file(); */
 out:
	if (dl_result == DP_OK)
		delta_lease_release(&host_id_disk, host_id_in);
	return NULL;
}

/* 
 * options.our_host_id must be set prior to calling this, and the
 * caller should set our_host_id back to 0 if this function returns
 * an error; the delta_lease functions use options.our_host_id directly,
 * so we can't wait an set options.our_host_id after this function
 * returns success
 *
 * When this function returns, it needs to be safe to being processing lease
 * requests and allowing pid's to run, so we need to own our host_id, and the
 * watchdog needs to be active watching our host_id renewals.  start_host_id()
 * blocks the main processing thread, so a lease request can be processed
 * immediately when this returns, and it will check if options.our_host_id is > 0.
 */

int start_host_id(void)
{
	int rv, result;
	uint64_t *arg;

	memset(&host_id_disk, 0, sizeof(struct sync_disk));
	strncpy(host_id_disk.path, options.host_id_path, DISK_PATH_LEN);
	host_id_disk.offset = options.host_id_offset;

	rv = open_disks(&host_id_disk, 1);
	if (rv != 1) {
		log_error(NULL, "start_host_id open_disk failed %d %s",
			  rv, options.host_id_path);
		rv = -1;
		goto fail;
	}

	log_debug(NULL, "start_host_id %llu host_id_path %s offset %llu",
		  (unsigned long long)options.our_host_id,
		  options.host_id_path,
		  (unsigned long long)options.host_id_offset);

	arg = malloc(sizeof(uint64_t));
	if (!arg) {
		rv = -ENOMEM;
		goto fail_close;
	}
	*arg = options.our_host_id;

	memset(&our_lease_status, 0, sizeof(struct lease_status));

	rv = pthread_create(&our_host_id_thread, NULL, host_id_thread, arg);
	if (rv < 0) {
		log_error(NULL, "start_host_id create thread failed");
		goto fail_free;
	}

	pthread_mutex_lock(&host_id_mutex);
	while (!our_lease_status.acquire_last_result) {
		pthread_cond_wait(&host_id_cond, &host_id_mutex);
	}
	result = our_lease_status.acquire_last_result;
	pthread_mutex_unlock(&host_id_mutex);

	if (result != DP_OK) {
		/* the thread exits right away if acquire fails */
		pthread_join(our_host_id_thread, NULL);
		rv = result;
		goto fail_close;
	}

	return 0;

 fail_free:
	free(arg);
 fail_close:
	close_disks(&host_id_disk, 1);
 fail:
	return rv;
}

/* 
 * we call stop_host_id() when all pids are gone and we're in a safe state, so
 * it's safe to unlink the watchdog right away here.  We want to do the unlink
 * as soon as it's safe, so we can reduce the chance we get killed by the
 * watchdog (we could actually call this in main_loop just before the break).
 * Getting this unlink done quickly is more important than doing at the more
 * "logical" point commented above in host_id_thread.
 */

void stop_host_id(void)
{
	unlink_watchdog_file();

	pthread_mutex_lock(&host_id_mutex);
	our_host_id_thread_stop = 1;
	pthread_cond_broadcast(&host_id_cond);
	pthread_mutex_unlock(&host_id_mutex);

	pthread_join(our_host_id_thread, NULL);
	close_disks(&host_id_disk, 1);
}

