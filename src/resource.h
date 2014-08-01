/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef	__RESOURCE_H__
#define __RESOURCE_H__

/*
 * We mostly avoid holding resource_mutex and spaces_mutex at once.  When they
 * are held at once, the order is spaces_mutex, then resource_mutex.
 */

/* locks resource_mutex */
void send_state_resources(int fd);

/* locks resource_mutex */
int lockspace_is_used(struct sanlk_lockspace *ls);

/* locks resource_mutex */
int resource_orphan_count(char *space_name);

/* no locks */
void check_mode_block(struct token *token, uint64_t next_lver, int q, char *dblock);

/* locks resource_mutex */
int convert_token(struct task *task, struct sanlk_resource *res, struct token *cl_token);

/* locks resource_mutex */
int acquire_token(struct task *task, struct token *token, uint32_t cmd_flags,
		  char *killpath, char *killargs);


/* locks resource_mutex */
int release_token(struct task *task, struct token *token,
		  struct sanlk_resource *resrename);

/* locks resource_mutex */
void release_token_async(struct token *token);

/* no locks */
int request_token(struct task *task, struct token *token, uint32_t force_mode,
		  uint64_t *owner_id, int next_lver);

/* locks resource_mutex */
int set_resource_examine(char *space_name, char *res_name);

/* locks resource_mutex */
int res_set_lvb(struct sanlk_resource *res, char *lvb, int lvblen);

/* locks resource_mutex */
int res_get_lvb(struct sanlk_resource *res, char **lvb_out, int *lvblen);

/* no locks */
int read_resource_owners(struct task *task, struct token *token,
                         struct sanlk_resource *res,
                         char **send_buf, int *send_len, int *count);

/* locks resource_mutex */
void free_resources(void);

/* locks resource_mutex */
int release_orphan(struct sanlk_resource *res);

/* locks resource_mutex */
void purge_resource_orphans(char *space_name);

/* locks resource_mutex */
void add_host_event(uint32_t space_id, struct sanlk_host_event *he,
		    uint64_t from_host_id, uint64_t from_generation);

int setup_token_manager(void);
void close_token_manager(void);

#endif

