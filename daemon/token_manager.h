#ifndef	__TOKEN_MANAGER_H__
#define __TOKEN_MANAGER_H__

int create_token(int num_disks, struct token **token_out);
void release_token_wait(struct token *token);
void release_token_async(struct token *token);
void *acquire_thread(void *arg);

#endif

