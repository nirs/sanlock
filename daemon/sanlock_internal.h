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

#define PAXOS_DISK_MAGIC 0x06152010
#define PAXOS_DISK_VERSION_MAJOR 0x00020000
#define PAXOS_DISK_VERSION_MINOR 0x00000001

#define DELTA_DISK_MAGIC 0x12212010
#define DELTA_DISK_VERSION_MAJOR 0x00010000
#define DELTA_DISK_VERSION_MINOR 0x00000001

#define SM_MAGIC 0x04282010

/* each pid can own this many leases */

#define MAX_LEASES SANLK_MAX_RESOURCES

/* max disks in a single lease */

#define MAX_DISKS 8

/* includes terminating null byte */

#define DISK_PATH_LEN SANLK_PATH_LEN

/* default max number of hosts supported */

#define DEFAULT_MAX_HOSTS 2000

/* does not include terminating null byte */

#define NAME_ID_SIZE SANLK_NAME_LEN

#define SM_LOG_DUMP_SIZE (1024*1024)

/* this is just the path to the executable, not full command line */

#define COMMAND_MAX 4096

#define SANLK_RUN_DIR "/var/run/sanlock"
#define SANLK_LOG_DIR "/var/log"
#define SANLK_SOCKET_NAME "sanlock.sock"
#define SANLK_LOGFILE_NAME "sanlock.log"
#define SANLK_LOCKFILE_NAME "sanlock.pid"
#define SANLK_WATCHDOG_NAME "sanlock.time"

#define DAEMON_NAME "sanlock"

#define SMERR_UNREGISTERED -501;

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
 * Example of how host_id_timeout_seconds is derived (primarily from 
 * host_id_renewal_fail_seconds).
 * . host_id_renewal_fail_seconds 30
 * . host_id_timeout_seconds 100
 *
 * - lease ages to 30 sec at which point daemon enters recovery mode
 *   (kills pids) and stops updating wd file
 * - 60 more seconds after we stop updating wd file, the wd fires
 *   (assuming standard 60 wd timeout, and assuming we don't unlink wd file first)
 * - this 90 seconds isn't quite right because of the intervals between
 *   checks (daemon checking lease age, and watchdog daemon running checks), so
 *   add 10 more seconds to deal with check intervals, e.g. the watchdog daemon
 *   checks the status every 5 or 10 seconds, so the lease may be 30-40 sec
 *   old when it stops petting the wd device
 */

#define DEFAULT_IO_TIMEOUT_SECONDS 1
#define DEFAULT_HOST_ID_RENEWAL_SECONDS 5
#define DEFAULT_HOST_ID_RENEWAL_FAIL_SECONDS 30
#define DEFAULT_HOST_ID_RENEWAL_WARN_SECONDS 25
#define DEFAULT_HOST_ID_TIMEOUT_SECONDS 100

struct sm_timeouts {
	int io_timeout_seconds;
	int host_id_timeout_seconds;
	int host_id_renewal_seconds;
	int host_id_renewal_fail_seconds;
	int host_id_renewal_warn_seconds;
};

/* values used after processing command, while running */

struct sm_options {
	int debug;
	int use_aio;
	int use_watchdog;
	uint32_t cluster_mode;
	uint64_t our_host_id;
	uint64_t host_id_offset;
	char host_id_path[DISK_PATH_LEN];
};

/* values used while processing command, not afterward */

struct command_line {
	int action;
	int pid;
	uint64_t host_id;
	int incoming;
	int num_hosts;
	int max_hosts;
	int res_count;
	struct sanlk_resource *res_args[];
};

EXTERN struct sm_options options;
EXTERN struct sm_timeouts to;
EXTERN struct command_line com;

#endif

