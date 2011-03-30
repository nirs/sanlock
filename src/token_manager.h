/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef	__TOKEN_MANAGER_H__
#define __TOKEN_MANAGER_H__

int acquire_token(struct token *token, uint64_t acquire_lver, int new_num_hosts);
int release_token(struct token *token);

void release_token_async(struct token *token);

int add_resource(struct token *token, int pid);
void del_resource(struct token *token);

int setup_token_manager(void);
void close_token_manager(void);

#endif

