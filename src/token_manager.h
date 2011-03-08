/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef	__TOKEN_MANAGER_H__
#define __TOKEN_MANAGER_H__

int acquire_token(struct token *token, uint64_t reacquire_lver,
		  int new_num_hosts);
int release_token(struct token *token);
int setowner_token(struct token *token);

int check_incoming_state(struct token *token, char *opt_str,
			 int *migrate_result_out);
int set_next_owner_other(struct token *token, uint64_t target_host_id);
int set_next_owner_self(struct token *token);

int create_token(int num_disks, struct token **token_out);
void free_token(struct token *token);
void release_token_async(struct token *token);

int add_resource(struct token *token, int pid);
void del_resource(struct token *token);
void save_resource(struct token *token);
void purge_saved_resources(int pid);
void save_resource_leader(struct token *token);

int setup_token_manager(void);
void close_token_manager(void);

#endif

