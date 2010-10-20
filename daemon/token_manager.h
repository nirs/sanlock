#ifndef	__TOKEN_MANAGER_H__
#define __TOKEN_MANAGER_H__

int create_token(int num_disks, struct token **token_out);
void free_token(struct token *token);
void release_token_wait(struct token *token);
void release_token_async(struct token *token);
void *acquire_thread(void *arg);
int add_resource(struct token *token, int pid);
void del_resource(struct token *token);
int setup_token_manager(void);
void close_token_manager(void);

#endif

