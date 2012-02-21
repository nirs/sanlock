/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __HOST_ID_H__
#define __HOST_ID__H__

struct space *find_lockspace(char *name);
int _lockspace_info(char *space_name, struct space *sp_out);
int lockspace_info(char *space_name, struct space *sp_out);
int lockspace_disk(char *space_name, struct sync_disk *disk);
int host_info(char *space_name, uint64_t host_id, struct host_status *hs_out);
int host_status_set_bit(char *space_name, uint64_t host_id);
int test_id_bit(int host_id, char *bitmap);
void set_id_bit(int host_id, char *bitmap, char *c);
int check_our_lease(struct task *task, struct space *sp, int *check_all, char *check_buf);
void check_other_leases(struct task *task, struct space *sp, char *buf);
int add_lockspace(struct sanlk_lockspace *ls);
int inq_lockspace(struct sanlk_lockspace *ls);
int rem_lockspace(struct sanlk_lockspace *ls);
void free_lockspaces(int wait);

#endif
