/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __LOCKSPACE_H__
#define __LOCKSPACE__H__

/* See resource.h for lock ordering between spaces_mutex and resource_mutex. */

/* no locks */
struct space *find_lockspace(const char *name);

/* no locks */
int _lockspace_info(const char *space_name, struct space_info *spi);

/* locks spaces_mutex */
int lockspace_info(const char *space_name, struct space_info *spi);

/* locks spaces_mutex */
int lockspace_disk(char *space_name, struct sync_disk *disk, int *sector_size);

/* locks spaces_mutex */
int host_info(char *space_name, uint64_t host_id, struct host_status *hs_out);

/* locks spaces_mutex, locks sp */
int host_status_set_bit(char *space_name, uint64_t host_id);

/* no locks */
int test_id_bit(int host_id, char *bitmap);

/* no locks */
void set_id_bit(int host_id, char *bitmap, char *c);

/* locks sp */
int check_our_lease(struct space *sp, int *check_all, char *check_buf);

/* locks resource_mutex (add_host_event), locks resource_mutex (set_resource_examine) */
void check_other_leases(struct space *sp, char *buf);

/* locks spaces_mutex */
int add_lockspace_start(struct sanlk_lockspace *ls, uint32_t io_timeout, struct space **sp_out);

/* locks sp, locks spaces_mutex */
int add_lockspace_wait(struct space *sp);

/* locks spaces_mutex */
int inq_lockspace(struct sanlk_lockspace *ls);

/* locks spaces_mutex */
int rem_lockspace_start(struct sanlk_lockspace *ls, unsigned int *space_id);

/* locks spaces_mutex */
int rem_lockspace_wait(struct sanlk_lockspace *ls, unsigned int space_id);

/* locks spaces_mutex, locks sp */
void free_lockspaces(int wait);

/* locks spaces_mutex */
int get_lockspaces(char *buf, int *len, int *count, int maxlen);

/* locks spaces_mutex */
int get_hosts(struct sanlk_lockspace *ls, char *buf, int *len, int *count, int maxlen);

/* locks spaces_mutex, locks sp */
int lockspace_set_event(struct sanlk_lockspace *ls, struct sanlk_host_event *he, uint32_t flags);

/* locks spaces_mutex, locks sp */
int lockspace_reg_event(struct sanlk_lockspace *ls, int fd, uint32_t flags);

/* locks spaces_mutex, locks sp */
int lockspace_end_event(struct sanlk_lockspace *ls);

/* locks spaces_mutex, locks sp */
int send_event_callbacks(uint32_t space_id, uint64_t from_host_id, uint64_t from_generation, struct sanlk_host_event *he);

/* locks spaces_mutex, locks sp */
int lockspace_set_config(struct sanlk_lockspace *ls, uint32_t flags, uint32_t cmd);

#endif
