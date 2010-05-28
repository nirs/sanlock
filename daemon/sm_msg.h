#ifndef __SM_MSG_H__
#define __SM_MSG_H__

enum {
	SM_CMD_STATUS = 1,
	SM_CMD_LOG_DUMP,
	SM_CMD_SHUTDOWN,

	SM_CMD_NUM_HOSTS,
	SM_CMD_ADD_LEASE,
	SM_CMD_DEL_LEASE,
	SM_CMD_GET_TIMEOUTS,
	SM_CMD_SET_TIMEOUTS,
	SM_CMD_SUPERVISE_PID,
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
	char resource_id[NAME_ID_SIZE];
};

struct sm_info {
	char command[COMMAND_MAX];
	char killscript[COMMAND_MAX];
	uint64_t our_host_id;
	uint64_t num_hosts;

	int supervise_pid;
	int supervise_pid_exit_status;
	int starting_lease_thread;
	int stopping_lease_threads;
	int killing_supervise_pid;
	int external_shutdown;

	/* TODO: include wd info */

	uint64_t current_time;
	uint64_t oldest_renewal_time;
	int oldest_renewal_num;

	uint32_t lease_info_len;
	uint32_t lease_info_count;
};

struct sm_lease_info {
	char token_name[NAME_ID_SIZE];
	uint32_t token_type;
	int num;
	int stop_thread;
	int thread_running;

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
