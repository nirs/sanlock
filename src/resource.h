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

void check_mode_block(struct token *token, int q, char *dblock);

int acquire_token(struct task *task, struct token *token);
int release_token(struct task *task, struct token *token);
void release_token_async(struct token *token);

int request_token(struct task *task, struct token *token, uint32_t force_mode,
		  uint64_t *owner_id);

int set_resource_examine(char *space_name, char *res_name);

int setup_token_manager(void);
void close_token_manager(void);

#endif

