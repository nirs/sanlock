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

pthread_t wd_thread;
pthread_mutex_t wd_mutex = PTHREAD_MUTEX_INITIALIZER;
int wd_thread_running;
int wd_touch;
int wd_unlink;
int wd_fd;
char wd_path[PATH_MAX];
int wd_create_result;
int wd_touch_last_result;
time_t wd_create_time;
time_t wd_touch_last_time;
time_t wd_touch_good_time;

void *watchdog_thread(void *arg)
{
	int rv, fd, do_touch, do_unlink, do_create;
	time_t t;

	while (1) {
		do_create = 0;

		pthread_mutex_lock(&wd_mutex);
		do_touch = wd_touch;
		do_unlink = wd_unlink;
		pthread_mutex_unlock(&wd_mutex);

		if (do_unlink) {
			unlink(wd_path);
			log_debug(NULL, "unlinked watchdog file");
			break;
		}

		if (!do_touch)
			continue;

		if (!wd_fd) {
			fd = open(wd_path, O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK,
				  0666);
			if (fd < 0) {
				rv = fd;
			} else {
				rv = 0;
				wd_fd = fd;
			}
			do_create = 1;
		} else {
			rv = futimes(wd_fd, NULL);
		}
		t = time(NULL);

		pthread_mutex_lock(&wd_mutex);
		if (do_create) {
			wd_create_result = fd;
			wd_create_time = t;
		}
		wd_touch_last_result = rv;
		wd_touch_last_time = t;
		if (!rv)
			wd_touch_good_time = t;
		pthread_mutex_unlock(&wd_mutex);

		/* TODO: use a pthread_cond_timedwait() here so
		   unlink_watchdog can be quicker? */

		sleep(to.wd_touch_seconds);
	}
	return NULL;
}

void unlink_watchdog(void)
{
	void *ret;

	if (!options.opt_watchdog)
		return;

	pthread_mutex_lock(&wd_mutex);
	wd_unlink = 1;
	pthread_mutex_unlock(&wd_mutex);

	if (!wd_thread_running)
		return;

	pthread_join(wd_thread, &ret);
	wd_thread_running = 0;
}

int touch_watchdog(void)
{
	pthread_attr_t attr;
	time_t t, start;
	int rv;

	if (!options.opt_watchdog)
		return 0;

	if (wd_thread_running)
		return 0;

	wd_touch = 1;
	wd_fd = 0;
	wd_unlink = 0;
	wd_create_result = 0;
	wd_create_time = 0;
	wd_touch_last_result = 0;
	wd_touch_last_time = 0;

	snprintf(wd_path, PATH_MAX, "%s/%s", DAEMON_WATCHDOG_DIR, options.sm_id);

	pthread_attr_init(&attr);
	rv = pthread_create(&wd_thread, &attr, watchdog_thread, NULL);
	pthread_attr_destroy(&attr);
	if (rv < 0) {
		log_error(NULL, "create wd_thread failed %d", rv);
		return rv;
	}
	wd_thread_running = 1;

	start = time(NULL);

	while (1) {
		pthread_mutex_lock(&wd_mutex);
		rv = wd_create_result;
		t = wd_create_time;
		pthread_mutex_unlock(&wd_mutex);

		if (t)
			break;

		if (time(NULL) - start > to.wd_touch_fail_seconds) {
			rv = -1;
			break;
		}

		usleep(10000);
	}

	if (rv < 0) {
		log_error(NULL, "create watchdog file failed %d", rv);
		unlink_watchdog();
	} else {
		log_debug(NULL, "create watchdog file at %llu",
			  (unsigned long long)wd_create_time);
		rv = 0;
	}

	return rv;
}

void notouch_watchdog(void)
{
	time_t log_t = 0;

	pthread_mutex_lock(&wd_mutex);
	if (wd_touch)
		log_t = wd_touch_good_time;
	wd_touch = 0;
	pthread_mutex_unlock(&wd_mutex);

	if (log_t)
		log_error(NULL, "touch watchdog file stopped last %llu",
			  (unsigned long long)log_t);
}

int check_watchdog_thread(void)
{
	int touch;
	time_t t;

	if (!options.opt_watchdog)
		return 0;

	if (!wd_thread_running)
		return 0;

	pthread_mutex_lock(&wd_mutex);
	touch = wd_touch;
	t = wd_touch_good_time;
	pthread_mutex_unlock(&wd_mutex);

	if (!touch)
		return 0;

	if (time(NULL) - t > to.wd_touch_fail_seconds) {
		log_error(NULL, "touch watchdog file last %llu timeout %d",
			  (unsigned long long)t, to.wd_touch_fail_seconds);
		return -1;
	}
	return 0;
}
