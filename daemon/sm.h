#ifndef __SM_H__
#define __SM_H__

#ifndef GNUC_UNUSED
#define GNUC_UNUSED __attribute__((__unused__))
#endif

#define PAXOS_DISK_MAGIC 0x06152010
#define PAXOS_DISK_VERSION_MAJOR 0x00020000
#define PAXOS_DISK_VERSION_MINOR 0x00000001

#define SM_MAGIC 0x04282010

/* max leases that sm will manage */

#define MAX_LEASES 8

/* max disks in a single lease */

#define MAX_DISKS 8

/* max leases on the command line */

#define MAX_LEASE_ARGS 50

/* includes terminating null byte */

#define DISK_PATH_LEN 1024

/* default num_hosts and host_id range */

#define DEFAULT_MAX_HOSTS 2000

/* does not include terminating null byte */

#define NAME_ID_SIZE 48

#define SM_LOG_DUMP_SIZE (1024*1024)

/* this is just the path to the executable, not full command line */

#define COMMAND_MAX 4096

#define SM_RUN_DIR "/var/run/sync_manager"
#define SM_LOG_DIR "/var/log/sync_manager"
#define DAEMON_WATCHDOG_DIR "/var/run/sync_manager/watchdog"
#define DAEMON_SOCKET_DIR "/var/run/sync_manager/sockets"
#define DAEMON_LOCKFILE_DIR "/var/run/sync_manager/daemon_lockfiles/"
#define RESOURCE_LOCKFILE_DIR "/var/run/sync_manager/resource_lockfiles/"

#define MAIN_SOCKET_NAME "main"

#define DAEMON_NAME "daemon"

#define DEFAULT_IO_TIMEOUT_SECONDS 60

#define SMERR_UNREGISTERED -501;
/*
 * host_timeout_seconds
 * disk paxos takes over lease if host_id hasn't been renewed for this long
 *
 * host_renewal_warn_seconds
 * sm emits a warning message if its host_id hasn't been renewed in this time
 *
 * host_renewal_fail_seconds
 * sm starts recovery if its host_id hasn't renewed in this time
 *
 * host_renewal_seconds
 * sm tries to renew its host_id this often
 *
 * script_shutdown_seconds
 * use killscript if this many seconds remain (or >) until lease can be taken
 *
 * sigterm_shutdown_seconds
 * use SIGTERM if this many seconds remain (or >) until lease can be taken
 *
 * stable_poll_ms
 * check pid and lease status this often when things appear to be stable
 *
 * unstable_poll_ms
 * check pid and lease status this often when things are changing
 */

struct sm_timeouts {
	int host_timeout_seconds;
	int host_renewal_warn_seconds;
	int host_renewal_fail_seconds;
	int host_renewal_seconds;
	int script_shutdown_seconds;
	int sigterm_shutdown_seconds;
	int stable_poll_ms;
	int unstable_poll_ms;
	int io_timeout_seconds;
};

#endif

