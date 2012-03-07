/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __SANLOCK_INTERNAL_H__
#define __SANLOCK_INTERNAL_H__

#ifndef GNUC_UNUSED
#define GNUC_UNUSED __attribute__((__unused__))
#endif

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#ifndef EXTERN
#define EXTERN extern
#else
#undef EXTERN
#define EXTERN
#endif

#include "sanlock.h"
#include "sanlock_rv.h"
#include "sanlock_resource.h"
#include "leader.h"
#include "list.h"
#include "monotime.h"

#include <libaio.h>

/* default max number of hosts supported */

#define DEFAULT_MAX_HOSTS 2000

#define LOG_DUMP_SIZE (1024*1024)

/* this is just the path to the executable, not full command line */

#define COMMAND_MAX 4096

#define SANLK_LOG_DIR "/var/log"
#define SANLK_LOGFILE_NAME "sanlock.log"
#define SANLK_LOCKFILE_NAME "sanlock.pid"

#define DAEMON_NAME "sanlock"


/* for paxos_lease sync_disk + offset:
   points to 1 leader_record + 1 request_record + MAX_HOSTS paxos_dblock's =
   256 blocks = 128KB, ref: lease_item_record */

/* must mirror external sanlk_disk */

struct sync_disk {
	char path[SANLK_PATH_LEN];
	uint64_t offset;
	uint32_t sector_size;	/* sanlk_disk pad1 */
	int fd;			/* sanlk_disk pad2 */
};

/*
 * There are two different wrappers around a sanlk_resource:
 * 'struct token' keeps track of resources per-client, client.tokens[]
 * 'struct resource' keeps track of resources globally, resources list
 */

#define T_RESTRICT_SIGKILL	0x00000001 /* inherited from client->restrict */
#define T_LS_DEAD		0x00000002 /* don't bother trying to release if ls is dead */

struct token {
	/* values copied from acquire res arg */
	uint64_t acquire_lver;
	uint64_t acquire_data64;
	uint32_t acquire_data32;
	uint32_t acquire_flags;

	/* copied from the sp with r.lockspace_name */
	uint64_t host_id;
	uint64_t host_generation;

	/* internal */
	struct list_head list; /* resource->tokens */
	struct resource *resource;
	int pid;
	uint32_t flags;
	uint32_t token_id; /* used to refer to this token instance in log messages */
	int shared_count;
	char shared_bitmap[HOSTID_BITMAP_SIZE]; /* bit set for host_id with SH */

	struct sync_disk *disks; /* shorthand, points to r.disks[0] */
	struct sanlk_resource r;
};

#define R_SHARED     		0x00000001
#define R_THREAD_EXAMINE    	0x00000002
#define R_THREAD_RELEASE	0x00000004
#define R_RESTRICT_SIGKILL	0x00000008 /* inherited from token */

struct resource {
	struct list_head list;
	struct list_head tokens;     /* only one token when ex, multiple sh */
	uint64_t host_id;
	uint64_t host_generation;
	int pid;                     /* copied from token when ex */
	uint32_t flags;
	uint32_t release_token_id;   /* copy to temp token (tt) for log messages */
	struct leader_record leader; /* copy of last leader_record we wrote */
	struct sanlk_resource r;
};

struct lease_status {
	int corrupt_result;
	int acquire_last_result;
	int renewal_last_result;
	uint64_t acquire_last_attempt;
	uint64_t acquire_last_success;
	uint64_t renewal_last_attempt;
	uint64_t renewal_last_success;

	uint32_t renewal_read_count;
	uint32_t renewal_read_check;
	char *renewal_read_buf;
};

struct host_status {
	uint64_t first_check; /* local monotime */
	uint64_t last_check; /* local monotime */
	uint64_t last_live; /* local monotime */
	uint64_t last_req; /* local monotime */
	uint64_t owner_id;
	uint64_t owner_generation;
	uint64_t timestamp; /* remote monotime */
	uint64_t set_bit_time;
};

struct space {
	struct list_head list;
	char space_name[NAME_ID_SIZE];
	uint32_t space_id; /* used to refer to this space instance in log messages */
	uint64_t host_id;
	uint64_t host_generation;
	struct sync_disk host_id_disk;
	int align_size;
	int space_dead;
	int killing_pids;
	int external_remove;
	int thread_stop;
	int wd_fd;
	pthread_t thread;
	pthread_mutex_t mutex; /* protects lease_status, thread_stop  */
	struct lease_status lease_status;
	struct host_status host_status[DEFAULT_MAX_HOSTS];
};

/*
 * Example of watchdog behavior when host_id renewals fail, assuming
 * that sanlock cannot successfully kill the pids it is supervising that
 * depend on the given host_id.
 *
 * 
 * Using these values in the example
 * watchdog_fire_timeout        = 60 (constant)
 * io_timeout_seconds           =  2 (defined by us)
 * id_renewal_seconds           = 10 (defined by us)
 * id_renewal_fail_seconds      = 30 (defined by us)
 * host_dead_seconds            = 90 (derived below)
 *
 * (FIXME: 2/10/30 is not a combination we'd actually create,
 * but the example still works)
 *
 *   T  time in seconds
 *
 *   0: sanlock renews host_id on disk
 *      sanlock calls wdmd_test_live(0, 30)
 *      wdmd test_client sees now 0 < expire 30 ok
 *      wdmd /dev/watchdog keepalive
 *
 *  10: sanlock renews host_id on disk ok
 *      sanlock calls wdmd_test_live(10, 40)
 *      wdmd test_client sees now 10 < expire 30 or 40 ok
 *      wdmd /dev/watchdog keepalive
 *
 *  20: sanlock fails to renew host_id on disk
 *      sanlock does not call wdmd_test_live
 *      wdmd test_client sees now 20 < expire 40 ok
 *      wdmd /dev/watchdog keepalive
 *
 *  30: sanlock fails to renew host_id on disk
 *      sanlock does not call wdmd_test_live
 *      wdmd test_client sees now 30 < expire 40 ok
 *      wdmd /dev/watchdog keepalive
 *
 *  40: sanlock fails to renew host_id on disk
 *      sanlock does not call wdmd_test_live
 *      wdmd test_client sees now 40 >= expire 40 fail
 *      wdmd no keepalive
 *
 *      . /dev/watchdog will fire at last keepalive + watchdog_fire_timeout =
 *        T30 + 60 = T90
 *      . host_id will expire at
 *        last disk renewal ok + id_renewal_fail_seconds + watchdog_fire_timeout
 *        T10 + 30 + 60 = T100
 *        (aka last disk renewal ok + host_dead_seconds)
 *      . the wdmd test at T30 could have been at T39, so wdmd would have
 *        seen the client unexpired/ok just before the expiry time at T40,
 *        which would lead to /dev/watchdog firing at 99 instead of 90
 *
 *  50: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 50 > expire 40 fail -> no keepalive
 *  60: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 60 > expire 40 fail -> no keepalive
 *  70: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 70 > expire 40 fail -> no keepalive
 *  80: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 80 > expire 40 fail -> no keepalive
 *  90: sanlock fails to renew host_id on disk -> does not call wdmd_test_live
 *      wdmd test_client sees now 90 > expire 40 fail -> no keepalive
 *      /dev/watchdog fires, machine reset
 * 100: another host takes over leases held by host_id
 *
 *
 * A more likely recovery scenario when a host_id cannot be renewed
 * (probably caused by loss of storage connection):
 *
 * The sanlock daemon fails to renew its host_id from T20 to T40.
 * At T40, after failing to renew within id_renewal_fail_seconds (30),
 * the sanlock daemon begins trying to kill all pids that were using
 * leases under this host_id.  As soon as all those pids exit, the sanlock
 * daemon will call wdmd_test_live(0, 0) to disable the wdmd testing for
 * this client/host_id.  If it's able to call wdmd_test_live(0, 0) before T90,
 * the wdmd test will no longer see this client's expiry time of 40,
 * so the wdmd tests will succeed, wdmd will immediately go back to
 * /dev/watchdog keepalive's, and the machine will not be reset.
 *
 */
 
/*
 * "delta" refers to timed based leases described in Chockler/Malkhi that
 * we use for host_id ownership.
 *
 * "paxos" refers to disk paxos based leases described in Lamport that
 * we use for resource (vm) ownership.
 *
 * "free" refers to a lease (either type) that is not owned by anyone
 *
 * "held" refers to a lease (either type) that was owned by a host that
 * failed, so it was not released/freed.
 . (if a renewal fails we always attempt another renewal immediately)
 *
 * "max" refers to the maximum time that a successful acquire/renew can
 * take, assuming that every io operation takes the max allowable time
 * (io_timeout_seconds)
 *
 * "min" refers to the minimum time that a successful acquire/renew can
 * take, assuming that every io operation completes immediately, in
 * effectively zero time
 *
 *
 * io_timeout_seconds: defined by us
 *
 * id_renewal_seconds: defined by us
 *
 * id_renewal_fail_seconds: defined by us
 *
 * watchdog_fire_timeout: /dev/watchdog will fire without being petted this long
 * = 60 constant
 *
 * host_dead_seconds: the length of time from the last successful host_id
 * renewal until that host is killed by its watchdog.
 * = id_renewal_fail_seconds + watchdog_fire_timeout
 *
 * delta_large_delay: from the algorithm
 * = id_renewal_seconds + (6 * io_timeout_seconds)
 *
 * delta_short_delay: from the algorithm
 * = 2 * io_timeout_seconds
 *
 * delta_acquire_held_max: max time it can take to successfully
 * acquire a non-free delta lease
 * = io_timeout_seconds (read) +
 *   max(delta_large_delay, host_dead_seconds) +
 *   io_timeout_seconds (read) +
 *   io_timeout_seconds (write) +
 *   delta_short_delay +
 *   io_timeout_seconds (read)
 *
 * delta_acquire_held_min: min time it can take to successfully
 * acquire a non-free delta lease
 * = max(delta_large_delay, host_dead_seconds)
 *
 * delta_acquire_free_max: max time it can take to successfully
 * acquire a free delta lease.
 * = io_timeout_seconds (read) +
 *   io_timeout_seconds (write) +
 *   delta_short_delay +
 *   io_timeout_seconds (read)
 *
 * delta_acquire_free_min: min time it can take to successfully
 * acquire a free delta lease.
 * = delta_short_delay
 *
 * delta_renew_max: max time it can take to successfully
 * renew a delta lease.
 * = io_timeout_seconds (read) +
 *   io_timeout_seconds (write)
 *
 * delta_renew_min: min time it can take to successfully
 * renew a delta lease.
 * = 0
 *
 * paxos_acquire_held_max: max time it can take to successfully
 * acquire a non-free paxos lease, uncontended.
 * = io_timeout_seconds (read leader) +
 *   host_dead_seconds +
 *   io_timeout_seconds (read leader) +
 *   io_timeout_seconds (write dblock) +
 *   io_timeout_seconds (read dblocks) +
 *   io_timeout_seconds (write dblock) +
 *   io_timeout_seconds (read dblocks) +
 *   io_timeout_seconds (write leader)
 *
 * paxos_acquire_held_min: min time it can take to successfully
 * acquire a non-free paxos lease, uncontended.
 * = host_dead_seconds
 *
 * paxos_acquire_free_max: max time it can take to successfully
 * acquire a free paxos lease, uncontended.
 * = io_timeout_seconds (read leader) +
 *   io_timeout_seconds (write dblock) +
 *   io_timeout_seconds (read dblocks) +
 *   io_timeout_seconds (write dblock) +
 *   io_timeout_seconds (read dblocks) +
 *   io_timeout_seconds (write leader)
 *
 * paxos_acquire_free_min: min time it can take to successfully
 * acquire a free paxos lease, uncontended.
 * = 0
 *
 *
 * How to configure the combination of related timeouts defined by us:
 * io_timeout_seconds
 * id_renewal_seconds
 * id_renewal_fail_seconds
 *
 * Here's one approach that seems to produce sensible sets of numbers:
 *
 * io_timeout_seconds = N
 * . max time one io can take
 *
 * delta_renew_max = 2N
 * . max time one renewal can take
 *
 * id_renewal_seconds = delta_renew_max (2N)
 * . delay this long after renewal success before next renew attempt begins
 * . this will be the difference between two successive renewal timestamps
 *   when io times are effectively 0
 * . there's no particular reason for it to be 2N exactly
 * . if a successful renewal takes the max possible time (delta_renew_max),
 *   then the next renewal attempt will begin right away
 * . (if a renewal fails we always attempt another renewal immediately)
 *
 * id_renewal_fail_seconds = 4 * delta_renew_max (8N)
 * . time from last successful renewal until recovery begins
 * . allows for three consecutive max len renewal failures, i.e.
 *   id_renewal_seconds + (3 * delta_renew_max)
 *
 * id_renewal_warn_seconds = 3 * delta_renew_max (6N)
 * . time from last successful renewal until warning about renewal length
 * . allows for two consecutive max len renewal failues
 *
 * T		time in seconds
 * 0		renewal ok
 * 2N		renewal attempt begin
 * 4N		renewal attempt fail1 (each io takes max time)
 * 4N		renewal attempt begin
 * 6N		renewal attempt fail2 (each io takes max time)
 * 6N		renewal attempt begin
 * 8N		renewal attempt fail3 (each io takes max time)
 * 8N		recovery begins (pids killed)
 *
 * If ios don't take the max len (delta_renew_max), this just
 * gives us more attempts to renew before recovery begins.
 *
 * io_timeout_seconds        N    5  10  20
 * id_renewal_seconds       2N   10  20  40
 * id_renewal_fail_seconds  8N   40  80 160
 *
 *  5 sec io timeout: fast storage io perf
 * 10 sec io timeout: normal storage io perf
 * 20 sec io timeout: slow storage io perf
 *
 * [We could break down these computations further by adding a variable
 * F = number of full len renewal failures allowed before recovery
 * begins.  Above F is fixed at 3, but we may want to vary it to be
 * 2 or 4.]
 *
 *                             fast norm slow
 * watchdog_fire_timeout         60   60   60
 *
 * io_timeout_seconds             5   10   20
 * id_renewal_seconds            10   20   40
 * id_renewal_fail_seconds       40   80  160
 * id_renewal_warn_seconds       30   60  120
 *
 * host_dead_seconds            100  140  220
 * delta_large_delay             40   80  160
 * delta_short_delay             10   20   40
 * delta_acquire_held_max       130  200  340
 * delta_acquire_held_min       100  140  220
 * delta_acquire_free_max        25   50  100
 * delta_acquire_free_min        10   20   40
 * delta_renew_max               10   20   40
 * delta_renew_min                0    0    0
 * paxos_acquire_held_max       135  210  360
 * paxos_acquire_held_min       100  140  220
 * paxos_acquire_free_max        30   60  120
 * paxos_acquire_free_min         0    0    0
 */

/*
 * Why does delta_acquire use max(delta_large_delay, host_dead_seconds) instead
 * of just delta_large_delay as specified in the algorithm?
 *
 * 1. the time based lease algorithm uses delta_large_delay to determine that a
 * host is failed, but we want to be more certain the host is dead based on its
 * watchdog firing, and we know the watchdog has fired after host_dead_seconds.
 *
 * 2. if a delta lease can be acquired and released (freed) before
 * host_dead_seconds, that could allow the paxos leases of a failed host to be
 * acquired by someone else before host_dead_seconds (and before the failed
 * host is really dead), because acquiring a held paxos lease depends on the
 * delta lease of the failed owner not changing for host_dead_seconds.
 * We cannot allow a host to acquire another failed host's paxos lease before
 * host_dead_seconds.
 *
 * 3. ios can't be reliably canceled and never really time out; an io is only
 * really dead when the machine is dead/reset or storage access is cut off.
 * The delta lease algorithm expects real io timeouts.
 *
 * So, the delay is really meant to represent the time until we are certain a
 * host is safely gone and will no longer write, and for sanlock that means
 * until the watchdog has reset it.
 */

#define HOSTID_AIO_CB_SIZE 4
#define WORKER_AIO_CB_SIZE 2
#define DIRECT_AIO_CB_SIZE 1
#define RESOURCE_AIO_CB_SIZE 2
#define LIB_AIO_CB_SIZE 1

struct aicb {
	int used;
	char *buf;
	struct iocb iocb;
};

struct task {
	char name[NAME_ID_SIZE+1];   /* for log messages */

	int io_timeout_seconds;      /* configured */
	int id_renewal_seconds;      /* configured */
	int id_renewal_fail_seconds; /* configured */
	int id_renewal_warn_seconds; /* configured */
	int host_dead_seconds;       /* calculated */
	int request_finish_seconds;  /* calculated */
	int kill_count_term;         /* constant */
	int kill_count_max;          /* constant */

	unsigned int io_count;       /* stats */
	unsigned int to_count;       /* stats */

	int use_aio;
	int cb_size;
	char *iobuf;
	io_context_t aio_ctx;
	struct aicb *read_iobuf_timeout_aicb;
	struct aicb *callbacks;
};

EXTERN struct task main_task;

struct client {
	int used;
	int fd;  /* unset is -1 */
	int pid; /* unset is -1 */
	int cmd_active;
	int cmd_last;
	int pid_dead;
	int suspend;
	int need_free;
	int kill_count;
	uint32_t restrict;
	uint64_t kill_last;
	char owner_name[SANLK_NAME_LEN+1];
	pthread_mutex_t mutex;
	void *workfn;
	void *deadfn;
	struct token *tokens[SANLK_MAX_RESOURCES];
};

/*
 * client array is only touched by main_loop, there is no lock for it.
 * individual cl structs are accessed by worker threads using cl->mutex
 */

EXTERN struct client *client;

#define WATCHDOG_FIRE_TIMEOUT 60
#define DEFAULT_USE_AIO 1
#define DEFAULT_IO_TIMEOUT 10
#define DEFAULT_USE_WATCHDOG 1
#define DEFAULT_HIGH_PRIORITY 1
#define DEFAULT_SOCKET_UID 0
#define DEFAULT_SOCKET_GID 0
#define DEFAULT_SOCKET_MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)
#define DEFAULT_MIN_WORKER_THREADS 2
#define DEFAULT_MAX_WORKER_THREADS 8
#define DEFAULT_SH_RETRIES 8

struct command_line {
	int type;				/* COM_ */
	int action;				/* ACT_ */
	int debug;
	int debug_renew;
	int quiet_fail;
	int use_watchdog;
	int high_priority;
	int max_worker_threads;
	int aio_arg;
	int io_timeout_arg;
	int uid;				/* -U */
	int gid;				/* -G */
	int pid;				/* -p */
	char sort_arg;
	uint64_t local_host_id;			/* -i */
	uint64_t local_host_generation;		/* -g */
	int num_hosts;				/* -n */
	int max_hosts;				/* -m */
	int res_count;
	int sh_retries;
	uint32_t force_mode;
	char our_host_name[SANLK_NAME_LEN+1];
	char *dump_path;
	struct sanlk_lockspace lockspace;	/* -s LOCKSPACE */
	struct sanlk_resource *res_args[SANLK_MAX_RESOURCES]; /* -r RESOURCE */
};

EXTERN struct command_line com;

/* command line types and actions */

#define COM_DAEMON      1
#define COM_CLIENT      2
#define COM_DIRECT      3

enum {
	ACT_STATUS = 1,
	ACT_HOST_STATUS,
	ACT_LOG_DUMP,
	ACT_SHUTDOWN,
	ACT_ADD_LOCKSPACE,
	ACT_INQ_LOCKSPACE,
	ACT_REM_LOCKSPACE,
	ACT_COMMAND, 
	ACT_ACQUIRE, 
	ACT_RELEASE,
	ACT_INQUIRE, 
	ACT_REQUEST,
	ACT_ACQUIRE_ID,
	ACT_RELEASE_ID,
	ACT_RENEW_ID,
	ACT_READ_ID,
	ACT_LIVE_ID,
	ACT_DIRECT_INIT,
	ACT_DUMP,
	ACT_READ_LEADER,
	ACT_CLIENT_INIT,
	ACT_CLIENT_ALIGN,
	ACT_EXAMINE,
};

EXTERN int external_shutdown;
EXTERN char our_host_name_global[SANLK_NAME_LEN+1];

EXTERN struct list_head spaces;
EXTERN struct list_head spaces_rem;
EXTERN struct list_head spaces_add;
EXTERN pthread_mutex_t spaces_mutex;

#endif

