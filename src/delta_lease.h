/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __DELTA_LEASE_H__
#define __DELTA_LEASE_H__

int delta_lease_leader_read(struct task *task,
			    struct sync_disk *disk,
			    char *space_name,
			    uint64_t host_id,
			    struct leader_record *leader_ret,
			    const char *caller);

int delta_lease_acquire(struct task *task,
                        struct space *sp,
                        struct sync_disk *disk,
                        char *space_name,
                        char *our_host_name,
                        uint64_t host_id,
                        struct leader_record *leader_ret);

int delta_lease_renew(struct task *task,
                      struct space *sp,
                      struct sync_disk *disk,
                      char *space_name,
                      char *bitmap,
                      int prev_result,
		      int *read_result,
                      struct leader_record *leader_last,
                      struct leader_record *leader_ret);

int delta_lease_release(struct task *task,
                        struct space *sp,
                        struct sync_disk *disk,
                        char *space_name GNUC_UNUSED,
                        struct leader_record *leader_last,
                        struct leader_record *leader_ret);

int delta_lease_init(struct task *task,
		     struct sync_disk *disk,
		     char *space_name,
		     int max_hosts);

#endif
