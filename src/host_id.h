/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __HOST_ID_H__
#define __HOST_ID__H__

int print_space_state(struct space *sp, char *str);
int _get_space_info(char *space_name, struct space *sp_out);
int get_space_info(char *space_name, struct space *sp_out);
void block_watchdog_updates(char *space_name);
int host_id_disk_info(char *name, struct sync_disk *disk);
int host_info_set_bit(char *space_name, uint64_t host_id);
int host_info_clear_bit(char *space_name, uint64_t host_id);
int test_id_bit(int host_id, char *bitmap);
int check_our_lease(struct task *task, struct space *sp, int *check_all, char *check_buf);
void check_other_leases(struct task *task, struct space *sp, char *buf);
int add_lockspace(struct sanlk_lockspace *ls);
int rem_lockspace(struct sanlk_lockspace *ls);
void free_lockspaces(int wait);
void setup_spaces(void);

#endif
