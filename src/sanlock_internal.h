/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __SANLOCK_INTERNAL_H__
#define __SANLOCK_INTERNAL_H__

#ifndef GNUC_UNUSED
#define GNUC_UNUSED __attribute__((__unused__))
#endif

#ifndef EXTERN
#define EXTERN extern
#else
#undef EXTERN
#define EXTERN
#endif

#include "sanlock.h"
#include "leader.h"
#include "list.h"

#define SM_MAGIC 0x04282010

/* max disks in a single lease */

#define MAX_DISKS 8

/* default max number of hosts supported */

#define DEFAULT_MAX_HOSTS 2000

#define SM_LOG_DUMP_SIZE (1024*1024)

/* this is just the path to the executable, not full command line */

#define COMMAND_MAX 4096

#define SANLK_RUN_DIR "/var/run/sanlock"
#define SANLK_LOG_DIR "/var/log"
#define SANLK_WDTEST_DIR "/var/run/sanlock/wdtest"
#define SANLK_SOCKET_NAME "sanlock_sock"
#define SANLK_LOGFILE_NAME "sanlock.log"
#define SANLK_LOCKFILE_NAME "sanlock.pid"

#define DAEMON_NAME "sanlock"


/* for paxos_lease sync_disk + offset:
   points to 1 leader_record + 1 request_record + MAX_HOSTS paxos_dblock's =
   256 blocks = 128KB, ref: lease_item_record */

struct sync_disk {
	/* mirror external sanlk_disk */
	char path[SANLK_PATH_LEN];
	uint64_t offset;
	uint32_t units;

	/* internal */
	uint32_t sector_size;
	int fd;
};

/* Once token and token->disks are initialized by the main loop, the only
   fields that are modified are disk fd's by open_disks() in the lease
   threads. */

struct token {
	/* mirror external sanlk_resource from acquire */
	char space_name[NAME_ID_SIZE];
	char resource_name[NAME_ID_SIZE];
	int num_disks;
	uint32_t acquire_data32;
	uint64_t acquire_data64;

	/* copied from the sp with space_name */
	uint64_t host_id;
	uint64_t host_generation;

	/* disks from acquire */
	struct sync_disk *disks;

	/* internal */
	int migrating;
	int token_id; /* used to refer to this token instance in log messages */
	int acquire_result;
	int migrate_result;
	int release_result;
	int setowner_result;
	uint64_t prev_lver; /* just used to pass a value between functions */
	struct leader_record leader; /* copy of last leader_record we wrote */
};

struct lease_status {
	int acquire_last_result;
	int renewal_last_result;
	int release_last_result;
	int max_renewal_interval;
	uint64_t acquire_last_time;
	uint64_t acquire_good_time;
	uint64_t renewal_last_time;
	uint64_t renewal_good_time;
	uint64_t release_last_time;
	uint64_t release_good_time;
	uint64_t max_renewal_time;
};

struct space {
	char space_name[NAME_ID_SIZE];
	uint64_t host_id;
	uint64_t host_generation;
	struct sync_disk host_id_disk;
	struct list_head list;
	int space_id; /* used to refer to this space instance in log messages */
	int killing_pids;
	int external_remove;
	int thread_stop;
	pthread_t thread;
	pthread_mutex_t mutex; /* protects lease_status, thread_stop  */
	pthread_cond_t cond;
	struct lease_status lease_status;
	int wd_fd;
	char wdtest_path[PATH_MAX];
};

struct sm_header {
	uint32_t magic;
	uint32_t version;
	uint32_t cmd;
	uint32_t length;
	uint32_t seq;
	uint32_t pad;
	uint32_t data;
	uint32_t data2;
};

/*
 * io_timeout_seconds - max time a single disk read or write can take to return
 * (if -1 then non-async i/o is used and time is unlimited)
 * (cf. safelease.c "max_op_ms")
 * (cf. light weight leases paper small delta)
 * (cf. delta_lease.c log message "d")
 *
 * host_id_renewal_seconds - attempt a renewal once in each interval of this length
 * (the sleeping time between each attempt will be this time minus the time spent
 * in renewal) 
 *
 * host_id_renewal_fail_seconds - daemon must renew lease once within this time
 * period to keep the lease.  daemon enters recovery mode (kills supervised pids)
 * if the lease is not renewed in this interval.
 * (cf. safelease.c "lease_ms")
 * (cf. light weight leases paper large delta)
 * (cf. delta_lease.c log message "D")
 *
 * host_id_timeout_seconds - one host considers another dead if the other's
 * host_id lease is this old (or more), and will take ownership of any resource
 * leases that the other host owned.
 *
 *
 * Example of watchdog behavior when host_id renewals fail, assuming
 * that sanlock cannot successfully kill the pids it is supervising that
 * depend on the given host_id.
 *
 * Using these default values
 * host_id_renewal_fail_seconds 30
 * host_id_timeout_seconds 90
 * wdmd fire_timeout 60
 *
 *   T
 *   0: sanlock renews host_id on disk
 *      sanlock calls wdmd_test_live(0, 30)
 *      wdmd test_client sees now 0 < expire 30 ok
 *      wdmd /dev/watchdog keepalive
 *
 *   5: sanlock renews host_id on disk
 *      sanlock calls wdmd_test_live(5, 35)
 *
 *  10: sanlock renews host_id on disk ok
 *      sanlock calls wdmd_test_live(10, 40)
 *      wdmd test_client sees now 10 < expire 35 or 40 ok
 *      wdmd /dev/watchdog keepalive
 *
 *  15: sanlock fails to renew host_id on disk
 *      sanlock does not call wdmd_test_live
 *
 *  20: sanlock fails to renew host_id on disk
 *      sanlock does not call wdmd_test_live
 *      wdmd test_client sees now 20 < expire 40 ok
 *      wdmd /dev/watchdog keepalive
 *
 *  25: sanlock fails to renew host_id on disk
 *      sanlock does not call wdmd_test_live
 *
 *  30: sanlock fails to renew host_id on disk
 *      sanlock does not call wdmd_test_live
 *      wdmd test_client sees now 30 < expire 40 ok
 *      wdmd /dev/watchdog keepalive
 *       
 *  35: sanlock fails to renew host_id on disk
 *      sanlock does not call wdmd_test_live
 *
 *  40: sanlock fails to renew host_id on disk
 *      sanlock does not call wdmd_test_live
 *      wdmd test_client sees now 40 >= expire 40 fail
 *      wdmd no keepalive
 *
 *      . /dev/watchdog will fire at last keepalive + fire_timeout =
 *        T30 + 60 = T90
 *      . host_id will expire at
 *        last disk renewal ok + host_id_renewal_fail_seconds + fire_timeout
 *        T10 + 30 + 60 = T100
 *      . the wdmd test at T30 could have been at T39, so wdmd would have
 *        seen the client unexpired/ok just before the expiry time at T40,
 *        which would lead to /dev/watchdog firing at 99 instead of 90
 *      . also last disk renewal ok + host_id_timeout_seconds
 *        T10 + 90 = T100
 *      . setup_watchdog checks that host_id_timeout_seconds =
 *        host_id_renewal_fail_seconds + fire_timeout
 *
 *  45: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *  50: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 50 > expire 40 fail -> no keepalive
 *  55: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *  60: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 60 > expire 40 fail -> no keepalive
 *  65: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *  70: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 70 > expire 40 fail -> no keepalive
 *  75: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *  80: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 80 > expire 40 fail -> no keepalive
 *  85: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *  90: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 90 > expire 40 fail -> no keepalive
 *      /dev/watchdog fires, machine reset
 * 100: another host takes over leases held by host_id
 *
 *
 * A more likely recovery scenario when a host_id cannot be renewed
 * (probably caused by loss of storage connection):
 *
 * The sanlock daemon fails six times to renew its host_id from
 * T15 to T40.  At T40, after failing for host_id_renewal_fail_seconds (30),
 * the sanlock daemon begins trying to kill all pids that were using
 * leases under this host_id.  As soon as all those pids exit, the sanlock
 * daemon will call wdmd_test_live(0, 0) to disable the wdmd testing for
 * this client/host_id.  If it's able to call wdmd_test_live(0, 0) before T90,
 * the wdmd test will no longer see this client's expiry time of 40,
 * so the wdmd tests will succeed, wdmd will immediately go back to
 * /dev/watchdog keepalive's, and the machine will not be reset.
 */

#define DEFAULT_IO_TIMEOUT_SECONDS 1
#define DEFAULT_HOST_ID_RENEWAL_SECONDS 5
#define DEFAULT_HOST_ID_RENEWAL_FAIL_SECONDS 30
#define DEFAULT_HOST_ID_RENEWAL_WARN_SECONDS 25
#define DEFAULT_HOST_ID_TIMEOUT_SECONDS 90

struct timeouts {
	int io_timeout_seconds;
	int host_id_timeout_seconds;
	int host_id_renewal_seconds;
	int host_id_renewal_fail_seconds;
	int host_id_renewal_warn_seconds;
};

/* values used after processing command, while running */

#define DEFAULT_USE_AIO 1
#define DEFAULT_USE_WATCHDOG 1
#define DEFAULT_HIGH_PRIORITY 1

struct options {
	int debug;
	int use_aio;
	int use_watchdog;
	int high_priority;
	uint32_t cluster_mode;
};

/* values used while processing command, not afterward */

struct command_line {
	int type;				/* COM_ */
	int action;				/* ACT_ */
	int pid;				/* -p */
	uint64_t local_host_id;			/* -i */
	uint64_t local_host_generation;		/* -g */
	uint64_t target_host_id;		/* -t */
	int num_hosts;				/* -n */
	int max_hosts;				/* -m */
	int res_count;
	char *dump_path;
	struct sanlk_lockspace lockspace;	/* -s LOCKSPACE */
	struct sanlk_resource *res_args[];	/* -r RESOURCE */
};

/* command line types and actions */

#define COM_DAEMON      1
#define COM_CLIENT      2
#define COM_DIRECT      3
#define COM_WDTEST      4

enum {
	ACT_STATUS = 1,
	ACT_LOG_DUMP,
	ACT_SHUTDOWN,
	ACT_ADD_LOCKSPACE,
	ACT_REM_LOCKSPACE,
	ACT_COMMAND, 
	ACT_ACQUIRE, 
	ACT_RELEASE,
	ACT_MIGRATE, 
	ACT_SETOWNER,
	ACT_ACQUIRE_ID,
	ACT_RELEASE_ID,
	ACT_RENEW_ID,
	ACT_INIT,
	ACT_DUMP,
};

EXTERN struct options options;
EXTERN struct timeouts to;
EXTERN struct command_line com;

#endif

