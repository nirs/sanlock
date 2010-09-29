#ifndef	__TOKEN_MANAGER_H__
#define __TOKEN_MANAGER_H__

#define OP_ACQUIRE 1
#define OP_RENEWAL 2
#define OP_RELEASE 3

int create_token(int num_disks, struct token **token_out);
void *lease_thread(void *arg);
int release_lease(struct token *token);

#endif

