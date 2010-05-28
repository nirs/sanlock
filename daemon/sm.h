#ifndef __SM_H__
#define __SM_H__

#define SM_MAGIC 0x04282010

#define MAX_DISKS 128

/* includes terminating null byte */

#define DISK_PATH_LEN 1024

/* host id's 1-254 */

#define MAX_HOSTS 254

/* does not include terminating null byte */

#define NAME_ID_SIZE 32

#define SM_LOG_DUMP_SIZE (1024*1024)

#define COMMAND_MAX 1024

/*
 * lease_timeout_seconds
 * disk paxos takes over lease if it's not been renewed for this long
 *
 * lease_renewal_warn_seconds
 * sm emits a warning message if a lease hasn't renewed in this time
 *
 * lease_renewal_fail_seconds
 * sm starts recovery if one of its leases hasn't renewed in this time
 *
 * lease_renewal_seconds
 * sm tries to renew a lease this often
 *
 * wd_touch_seconds
 * sm touches a watchdog file this often
 *
 * wd_reboot_seconds
 * wd daemon reboots if it finds a wd file older than this (unused?)
 *
 * wd_touch_fail_seconds
 * sm starts recovery if the wd thread hasn't touched wd file in this time
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
	int lease_timeout_seconds;
	int lease_renewal_warn_seconds;
	int lease_renewal_fail_seconds;
	int lease_renewal_seconds;
	int wd_touch_seconds;
	int wd_reboot_seconds;
	int wd_touch_fail_seconds;
	int script_shutdown_seconds;
	int sigterm_shutdown_seconds;
	int stable_poll_ms;
	int unstable_poll_ms;
};

#endif

