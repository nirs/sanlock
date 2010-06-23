#ifndef __SM_MSG_H__
#define __SM_MSG_H__

enum {
	SM_CMD_STATUS = 1,
	SM_CMD_LOG_DUMP,
	SM_CMD_SHUTDOWN,

	SM_CMD_NUM_HOSTS,
	SM_CMD_ACQUIRE,
	SM_CMD_RELEASE,
	SM_CMD_GET_TIMEOUTS,
	SM_CMD_SET_TIMEOUTS,
	SM_CMD_SUPERVISE,
};

struct sm_header {
	uint32_t magic;
	uint32_t version;
	uint32_t cmd;
	uint32_t length;
	uint32_t info_len;
	uint32_t seq;
	uint32_t data;
	uint32_t unused;
	char sm_id[NAME_ID_SIZE];
};

struct sm_info {
	char command[COMMAND_MAX];
	char killscript[COMMAND_MAX];
	uint64_t our_host_id;

	int supervise_pid;
	int supervise_pid_exit_status;
	int starting_lease_threads;
	int stopping_lease_threads;
	int killing_supervise_pid;
	int external_shutdown;

	/* TODO: include wd info */

	uint64_t current_time;
	uint64_t oldest_renewal_time;

	uint32_t lease_info_len;
	uint32_t lease_info_count;
};

struct sm_lease_info {
	char resource_name[NAME_ID_SIZE];
	int token_id;
	int stop_thread;
	int thread_running;

	/* TODO: copy out the latest leader record ? */

	int acquire_last_result;
	int renewal_last_result;
	int release_last_result;
	uint64_t acquire_last_time;
	uint64_t acquire_good_time;
	uint64_t renewal_last_time;
	uint64_t renewal_good_time;
	uint64_t release_last_time;
	uint64_t release_good_time;

	uint32_t disk_info_len;
	uint32_t disk_info_count;
};

struct sm_disk_info {
	uint64_t offset;
	char path[DISK_PATH_LEN];
};

#endif
