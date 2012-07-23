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

#include "../wdmd/wdmd.h"

void update_watchdog_file(struct space *sp, uint64_t timestamp,
			  int id_renewal_fail_seconds)
{
	int rv;

	if (!com.use_watchdog)
		return;

	rv = wdmd_test_live(sp->wd_fd, timestamp, timestamp + id_renewal_fail_seconds);
	if (rv < 0)
		log_erros(sp, "wdmd_test_live %llu failed %d",
			  (unsigned long long)timestamp, rv);
}

int create_watchdog_file(struct space *sp, uint64_t timestamp,
			 int id_renewal_fail_seconds)
{
	char name[WDMD_NAME_SIZE];
	int test_interval, fire_timeout;
	uint64_t last_keepalive;
	int con, rv;

	if (!com.use_watchdog)
		return 0;

	con = wdmd_connect();
	if (con < 0) {
		log_erros(sp, "wdmd_connect failed %d", con);
		goto fail;
	}

	memset(name, 0, sizeof(name));

	snprintf(name, WDMD_NAME_SIZE - 1, "sanlock_%s:%llu",
		 sp->space_name, (unsigned long long)sp->host_id);

	rv = wdmd_register(con, name);
	if (rv < 0) {
		log_erros(sp, "wdmd_register failed %d", rv);
		goto fail_close;
	}

	/* the refcount tells wdmd that it should not cleanly exit */

	rv = wdmd_refcount_set(con);
	if (rv < 0) {
		log_erros(sp, "wdmd_refcount_set failed %d", rv);
		goto fail_close;
	}

	rv = wdmd_status(con, &test_interval, &fire_timeout, &last_keepalive);
	if (rv < 0) {
		log_erros(sp, "wdmd_status failed %d", rv);
		goto fail_clear;
	}

	if (fire_timeout != WATCHDOG_FIRE_TIMEOUT) {
		log_erros(sp, "wdmd invalid fire_timeout %d vs %d",
			  fire_timeout, WATCHDOG_FIRE_TIMEOUT);
		goto fail_clear;
	}

	rv = wdmd_test_live(con, timestamp, timestamp + id_renewal_fail_seconds);
	if (rv < 0) {
		log_erros(sp, "wdmd_test_live in create failed %d", rv);
		goto fail_clear;
	}

	sp->wd_fd = con;
	return 0;

 fail_clear:
	wdmd_refcount_clear(con);
 fail_close:
	close(con);
 fail:
	return -1;
}

void unlink_watchdog_file(struct space *sp)
{
	int rv;

	if (!com.use_watchdog)
		return;

	log_space(sp, "wdmd_test_live 0 0 to disable");

	rv = wdmd_test_live(sp->wd_fd, 0, 0);
	if (rv < 0) {
		log_erros(sp, "wdmd_test_live in unlink failed %d", rv);

		/* We really want this to succeed to avoid a reset, so retry
	   	   after a short delay in case the problem was transient... */

		usleep(500000);

		rv = wdmd_test_live(sp->wd_fd, 0, 0);
		if (rv < 0)
			log_erros(sp, "wdmd_test_live in unlink 2 failed %d", rv);
	}

	wdmd_refcount_clear(sp->wd_fd);
}

void close_watchdog_file(struct space *sp)
{
	if (!com.use_watchdog)
		return;

	close(sp->wd_fd);
}

