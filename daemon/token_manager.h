#ifndef	__TOKEN_MANAGER_H__
#define __TOKEN_MANAGER_H__

#define OP_ACQUIRE 1
#define OP_RENEWAL 2
#define OP_RELEASE 3

struct lease_status {
	int acquire_last_result;
	int renewal_last_result;
	int release_last_result;
	uint64_t acquire_last_time;
	uint64_t acquire_good_time;
	uint64_t renewal_last_time;
	uint64_t renewal_good_time;
	uint64_t release_last_time;
	uint64_t release_good_time;

	int stop_thread;
	int thread_running;

	int token_id;
	char resource_name[NAME_ID_SIZE + 1];
};

extern struct token *tokens[MAX_LEASES];

uint64_t get_oldest_renewal_time(void);
int wait_acquire_result(int token_id, int *result);
int get_lease_status(int token_id, struct lease_status *status);
int check_leases_renewed(void);
int create_token(int num_disks, struct token **token_out);
int add_lease_thread(struct token *token, int *token_id_ret);

int stop_lease(char *resource_name);
int stop_token(int token_id);
void cleanup_stopped_lease(void);

void stop_all_leases(void);
void cleanup_all_leases(void);
#endif

