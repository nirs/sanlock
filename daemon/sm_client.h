#ifndef __SM_CLIENT_H__
#define __SM_CLIENT_H__

/*
 * process creates registered connection and acquires/releases leases on
 * that connection for itself
 */

int sm_register(void);
int sm_acquire_self(int sock, int token_count, struct token *tokens_args[]);
int sm_release_self(int sock, int token_count, struct token *tokens_args[]);
int sm_migrate_self(int sock, uint64_t target_host_id);

/*
 * process asks daemon to acquire/release leases for another separately
 * registered pid
 */

int sm_acquire_pid(int pid, int token_count, struct token *tokens_args[]);
int sm_release_pid(int pid, int token_count, struct token *tokens_args[]);
int sm_migrate_pid(int pid, uint64_t target_host_id);

/*
 * daemon admin/managment
 */

int sm_shutdown(void);
int sm_status(void);
int sm_log_dump(void);
int sm_set_host_id(uint32_t our_host_id);

#endif
