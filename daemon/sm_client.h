#ifndef __SM_CLIENT_H__
#define __SM_CLIENT_H__

int sm_register(void);
int sm_acquire(int sock, int token_count, struct token *tokens_args[]);
int sm_release(int pid, int token_count, struct token *tokens_args[]);
int sm_shutdown(void);
int sm_status(void);
int sm_log_dump(void);
int sm_set_host_id(uint32_t our_host_id);

#endif
