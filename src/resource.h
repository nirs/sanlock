/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef	__RESOURCE_H__
#define __RESOURCE_H__

void send_state_resources(int fd);

int lockspace_is_used(struct sanlk_lockspace *ls);

void check_mode_block(struct token *token, int q, char *dblock);

int acquire_token(struct task *task, struct token *token, uint32_t cmd_flags,
		  char *killpath, char *killargs);
int release_token(struct task *task, struct token *token);
void release_token_async(struct token *token);

int request_token(struct task *task, struct token *token, uint32_t force_mode,
		  uint64_t *owner_id, int next_lver);

int set_resource_examine(char *space_name, char *res_name);

int res_set_lvb(struct sanlk_resource *res, char *lvb, int lvblen);
int res_get_lvb(struct sanlk_resource *res, char **lvb_out, int *lvblen);

int read_resource_owners(struct task *task, struct token *token,
                         struct sanlk_resource *res,
                         char **send_buf, int *send_len, int *count);

int setup_token_manager(void);
void close_token_manager(void);

#endif

