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

#define T_RESTRICT_SIGKILL	 0x00000001 /* inherited from client->restricted */
#define T_RESTRICT_SIGTERM	 0x00000002 /* inherited from client->restricted */
#define T_RETRACT_PAXOS		 0x00000004
#define T_WRITE_DBLOCK_MBLOCK_SH 0x00000008 /* make paxos layer include mb SHARED with dblock */

struct token {
	/* values copied from acquire res arg */
	uint64_t acquire_lver;
	uint64_t acquire_data64;
	uint32_t acquire_data32;
	uint32_t acquire_flags;

	/* copied from the sp with r.lockspace_name */
	uint64_t host_id;
	uint64_t host_generation;
	uint32_t io_timeout;

	/* internal */
	struct list_head list; /* resource->tokens */
	struct resource *resource;
	int pid;
	uint32_t flags;  /* be careful to avoid using this from different threads */
	uint32_t token_id; /* used to refer to this token instance in log messages */
	int space_dead; /* copied from sp->space_dead, set by main thread */
	int shared_count; /* set during ballot by paxos_lease_acquire */
	char shared_bitmap[HOSTID_BITMAP_SIZE]; /* bit set for host_id with SH */

	struct sync_disk *disks; /* shorthand, points to r.disks[0] */
	struct sanlk_resource r;
};

#define R_SHARED     		0x00000001
#define R_THREAD_EXAMINE    	0x00000002
#define R_THREAD_RELEASE	0x00000004
#define R_RESTRICT_SIGKILL	0x00000008 /* inherited from token */
#define R_RESTRICT_SIGTERM	0x00000010 /* inherited from token */
#define R_LVB_WRITE_RELEASE	0x00000020
#define R_UNDO_SHARED		0x00000040
#define R_ERASE_ALL		0x00000080

struct resource {
	struct list_head list;
	struct list_head tokens;     /* only one token when ex, multiple sh */
	uint64_t host_id;
	uint64_t host_generation;
	uint32_t io_timeout;
	int pid;                     /* copied from token when ex */
	uint32_t flags;
	uint32_t release_token_id;   /* copy to temp token (tt) for log messages */
	uint64_t thread_release_retry;
	char *lvb;
	char killpath[SANLK_HELPER_PATH_LEN]; /* copied from client */
	char killargs[SANLK_HELPER_ARGS_LEN]; /* copied from client */
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
	uint16_t io_timeout;
};

struct space {
	struct list_head list;
	char space_name[NAME_ID_SIZE];
	uint32_t space_id; /* used to refer to this space instance in log messages */
	uint64_t host_id;
	uint64_t host_generation;
	struct sync_disk host_id_disk;
	uint32_t io_timeout;
	int align_size;
	int renew_fail;
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

/* Update lockspace_info() to copy any fields from struct space
   to space_info */

struct space_info {
	uint32_t space_id;
	uint32_t io_timeout;
	uint64_t host_id;
	uint64_t host_generation;
	int killing_pids;
};

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

/* TODO: change used, suspend, need_free, pid_dead to flags */

#define CL_KILLPATH_PID 0x00000001 /* include pid as killpath arg */
#define CL_RUNPATH_SENT 0x00000002 /* a RUNPATH msg has been sent to helper */

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
	uint32_t flags;
	uint32_t restricted;
	uint64_t kill_last;
	char owner_name[SANLK_NAME_LEN+1];
	char killpath[SANLK_HELPER_PATH_LEN];
	char killargs[SANLK_HELPER_ARGS_LEN];
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
#define DEFAULT_GRACE_SEC 40
#define DEFAULT_USE_WATCHDOG 1
#define DEFAULT_HIGH_PRIORITY 1
#define DEFAULT_MLOCK_LEVEL 1 /* 1=CURRENT, 2=CURRENT|FUTURE */
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
	int high_priority;		/* -h */
	int get_hosts;			/* -h */
	int mlock_level;
	int max_worker_threads;
	int aio_arg;
	int io_timeout_arg;
	char *uname;			/* -U */
	int uid;				/* -U */
	char *gname;			/* -G */
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
	ACT_CONVERT, 
	ACT_REQUEST,
	ACT_ACQUIRE_ID,
	ACT_RELEASE_ID,
	ACT_RENEW_ID,
	ACT_DIRECT_INIT,
	ACT_DUMP,
	ACT_NEXT_FREE,
	ACT_READ_LEADER,
	ACT_CLIENT_INIT,
	ACT_CLIENT_READ,
	ACT_CLIENT_ALIGN,
	ACT_EXAMINE,
	ACT_GETS,
};

EXTERN int external_shutdown;
EXTERN char our_host_name_global[SANLK_NAME_LEN+1];

EXTERN int kill_count_max;
EXTERN int kill_grace_seconds;
EXTERN int helper_ci;
EXTERN int helper_pid;
EXTERN int helper_kill_fd;
EXTERN int helper_status_fd;
EXTERN uint64_t helper_last_status;
EXTERN uint32_t helper_full_count;

EXTERN struct list_head spaces;
EXTERN struct list_head spaces_rem;
EXTERN struct list_head spaces_add;
EXTERN pthread_mutex_t spaces_mutex;

#endif

