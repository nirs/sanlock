/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __PAXOS_LEASE_H__
#define __PAXOS_LEASE_H__

#define PAXOS_ACQUIRE_FORCE		0x00000001
#define PAXOS_ACQUIRE_QUIET_FAIL	0x00000002

uint32_t leader_checksum(struct leader_record *lr);

int majority_disks(struct token *token, int num);

int paxos_lease_leader_read(struct task *task,
			    struct token *token,
			    struct leader_record *leader_ret,
			    const char *caller);

int paxos_lease_acquire(struct task *task,
			struct token *token,
			uint32_t flags,
		        struct leader_record *leader_ret,
		        uint64_t acquire_lver,
		        int new_num_hosts);

int paxos_lease_release(struct task *task,
			struct token *token,
			struct leader_record *leader_last,
			struct leader_record *leader_ret);

int paxos_lease_init(struct task *task,
		     struct token *token,
		     int num_hosts, int max_hosts);

#endif
