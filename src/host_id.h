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
int host_id_disk_info(char *name, struct sync_disk *disk);
int host_id_check(struct task *task, struct space *sp);
int add_space(struct space *sp);
int rem_space(char *name, struct sync_disk *disk, uint64_t host_id);
void clear_spaces(int wait);
int space_exists(char *name, struct sync_disk *disk, uint64_t host_id);
void setup_spaces(void);

#endif
