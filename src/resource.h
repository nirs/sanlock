/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef	__TOKEN_MANAGER_H__
#define __TOKEN_MANAGER_H__

int acquire_token(struct task *task, struct token *token,
		  uint64_t acquire_lver, int new_num_hosts);

int release_token(struct task *task, struct token *token);

void release_token_async(struct token *token);

int request_token(struct task *task, struct token *token, uint32_t force_mode,
		  uint64_t *owner_id);

int add_resource(struct token *token, int pid, uint32_t cl_restrict);
void del_resource(struct token *token);

int set_resource_examine(char *space_name, char *res_name);

int setup_token_manager(void);
void close_token_manager(void);

#endif

