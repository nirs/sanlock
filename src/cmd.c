/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <syslog.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <uuid/uuid.h>

#include "sanlock_internal.h"
#include "sanlock_sock.h"
#include "diskio.h"
#include "log.h"
#include "paxos_lease.h"
#include "delta_lease.h"
#include "lockspace.h"
#include "resource.h"
#include "direct.h"
#include "task.h"
#include "cmd.h"

/* from main.c */
void client_resume(int ci);
void client_free(int ci);
void client_recv_all(int ci, struct sm_header *h_recv, int pos);
void client_pid_dead(int ci);
void send_result(int fd, struct sm_header *h_recv, int result);

static uint32_t token_id_counter = 1;

static void release_cl_tokens(struct task *task, struct client *cl)
{
	struct token *token;
	int j;

	for (j = 0; j < SANLK_MAX_RESOURCES; j++) {
		token = cl->tokens[j];
		if (!token)
			continue;
		release_token(task, token);
		free(token);
	}
}

static void release_new_tokens(struct task *task, struct token *new_tokens[],
			       int alloc_count, int acquire_count)
{
	int i;

	for (i = 0; i < acquire_count; i++)
		release_token(task, new_tokens[i]);

	for (i = 0; i < alloc_count; i++)
		free(new_tokens[i]);
}

/* called with both spaces_mutex and cl->mutex held */

static int check_new_tokens_space(struct client *cl,
				  struct token *new_tokens[],
				  int new_tokens_count)
{
	struct space space;
	struct token *token;
	int i, rv, empty_slots = 0;

	for (i = 0; i < SANLK_MAX_RESOURCES; i++) {
		if (!cl->tokens[i])
			empty_slots++;
	}

	if (empty_slots < new_tokens_count) {
		/* shouldn't ever happen */
		return -ENOENT;
	}

	/* space may have failed while new tokens were being acquired */

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];

		rv = _lockspace_info(token->r.lockspace_name, &space);

		if (!rv && !space.killing_pids && space.host_id == token->host_id)
			continue;

		return -ENOSPC;
	}

	return 0;
}

static void cmd_acquire(struct task *task, struct cmd_args *ca)
{
	struct client *cl;
	struct token *token = NULL;
	struct token *new_tokens[SANLK_MAX_RESOURCES];
	struct sanlk_resource res;
	struct sanlk_options opt;
	struct space space;
	char *opt_str;
	int token_len, disks_len;
	int fd, rv, i, j, empty_slots, lvl;
	int alloc_count = 0, acquire_count = 0;
	int pos = 0, pid_dead = 0;
	int new_tokens_count;
	int recv_done = 0;
	int result = 0;
	int cl_ci = ca->ci_target;
	int cl_fd = ca->cl_fd;
	int cl_pid = ca->cl_pid;

	cl = &client[cl_ci];
	fd = client[ca->ci_in].fd;

	new_tokens_count = ca->header.data;

	log_debug("cmd_acquire %d,%d,%d ci_in %d fd %d count %d",
		  cl_ci, cl_fd, cl_pid, ca->ci_in, fd, new_tokens_count);

	if (new_tokens_count > SANLK_MAX_RESOURCES) {
		log_error("cmd_acquire %d,%d,%d new %d max %d",
			  cl_ci, cl_fd, cl_pid, new_tokens_count, SANLK_MAX_RESOURCES);
		result = -E2BIG;
		goto done;
	}

	pthread_mutex_lock(&cl->mutex);
	if (cl->pid_dead) {
		result = -ESTALE;
		pthread_mutex_unlock(&cl->mutex);
		goto done;
	}

	empty_slots = 0;
	for (i = 0; i < SANLK_MAX_RESOURCES; i++) {
		if (!cl->tokens[i])
			empty_slots++;
	}
	pthread_mutex_unlock(&cl->mutex);

	if (empty_slots < new_tokens_count) {
		log_error("cmd_acquire %d,%d,%d new %d slots %d",
			  cl_ci, cl_fd, cl_pid, new_tokens_count, empty_slots);
		result = -ENOENT;
		goto done;
	}

	/*
	 * read resource input and allocate tokens for each
	 */

	for (i = 0; i < new_tokens_count; i++) {

		/*
		 * receive sanlk_resource, create token for it
		 */

		rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
		if (rv > 0)
			pos += rv;
		if (rv != sizeof(struct sanlk_resource)) {
			log_error("cmd_acquire %d,%d,%d recv res %d %d",
				  cl_ci, cl_fd, cl_pid, rv, errno);
			result = -ENOTCONN;
			goto done;
		}

		if (!res.num_disks || res.num_disks > SANLK_MAX_DISKS) {
			result = -ERANGE;
			goto done;
		}

		disks_len = res.num_disks * sizeof(struct sync_disk);
		token_len = sizeof(struct token) + disks_len;

		token = malloc(token_len);
		if (!token) {
			result = -ENOMEM;
			goto done;
		}
		memset(token, 0, token_len);
		token->disks = (struct sync_disk *)&token->r.disks[0]; /* shorthand */
		token->r.num_disks = res.num_disks;
		memcpy(token->r.lockspace_name, res.lockspace_name, SANLK_NAME_LEN);
		memcpy(token->r.name, res.name, SANLK_NAME_LEN);
		if (res.flags & SANLK_RES_SHARED)
			token->r.flags |= SANLK_RES_SHARED;

		token->acquire_lver = res.lver;
		token->acquire_data64 = res.data64;
		token->acquire_data32 = res.data32;
		token->acquire_flags = res.flags;

		/*
		 * receive sanlk_disk's / sync_disk's
		 *
		 * WARNING: as a shortcut, this requires that sync_disk and
		 * sanlk_disk match; this is the reason for the pad fields
		 * in sanlk_disk (TODO: let these differ?)
		 */

		rv = recv(fd, token->disks, disks_len, MSG_WAITALL);
		if (rv > 0)
			pos += rv;
		if (rv != disks_len) {
			log_error("cmd_acquire %d,%d,%d recv disks %d %d",
				  cl_ci, cl_fd, cl_pid, rv, errno);
			free(token);
			result = -ENOTCONN;
			goto done;
		}

		/* zero out pad1 and pad2, see WARNING above */
		for (j = 0; j < token->r.num_disks; j++) {
			token->disks[j].sector_size = 0;
			token->disks[j].fd = -1;
		}

		token->token_id = token_id_counter++;
		new_tokens[i] = token;
		alloc_count++;
	}

	rv = recv(fd, &opt, sizeof(struct sanlk_options), MSG_WAITALL);
	if (rv > 0)
		pos += rv;
	if (rv != sizeof(struct sanlk_options)) {
		log_error("cmd_acquire %d,%d,%d recv opt %d %d",
			  cl_ci, cl_fd, cl_pid, rv, errno);
		result = -ENOTCONN;
		goto done;
	}

	strncpy(cl->owner_name, opt.owner_name, SANLK_NAME_LEN);

	if (opt.len) {
		opt_str = malloc(opt.len);
		if (!opt_str) {
			result = -ENOMEM;
			goto done;
		}

		rv = recv(fd, opt_str, opt.len, MSG_WAITALL);
		if (rv > 0)
			pos += rv;
		if (rv != opt.len) {
			log_error("cmd_acquire %d,%d,%d recv str %d %d",
			  	  cl_ci, cl_fd, cl_pid, rv, errno);
			free(opt_str);
			result = -ENOTCONN;
			goto done;
		}
	}

	/* TODO: warn if header.length != sizeof(header) + pos ? */
	recv_done = 1;

	/*
	 * all command input has been received, start doing the acquire
	 */

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];
		rv = lockspace_info(token->r.lockspace_name, &space);
		if (rv < 0 || space.killing_pids) {
			log_errot(token, "cmd_acquire %d,%d,%d invalid lockspace "
				  "found %d failed %d name %.48s",
				  cl_ci, cl_fd, cl_pid, rv, space.killing_pids,
				  token->r.lockspace_name);
			result = -ENOSPC;
			goto done;
		}
		token->host_id = space.host_id;
		token->host_generation = space.host_generation;
		token->pid = cl_pid;
		if (cl->restrict & SANLK_RESTRICT_SIGKILL)
			token->flags |= T_RESTRICT_SIGKILL;

		/* save a record of what this token_id is for later debugging */
		log_level(space.space_id, token->token_id, NULL, LOG_WARNING,
			  "resource %.48s:%.48s:%.256s:%llu%s for %d,%d,%d",
			  token->r.lockspace_name,
			  token->r.name,
			  token->r.disks[0].path,
			  (unsigned long long)token->r.disks[0].offset,
			  (token->acquire_flags & SANLK_RES_SHARED) ? ":SH" : "",
			  cl_ci, cl_fd, cl_pid);
	}

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];

		rv = acquire_token(task, token);
		if (rv < 0) {
			switch (rv) {
			case -EEXIST:
			case -EAGAIN:
			case -EBUSY:
				lvl = LOG_DEBUG;
				break;
			case SANLK_ACQUIRE_IDLIVE:
				lvl = com.quiet_fail ? LOG_DEBUG : LOG_ERR;
				break;
			default:
				lvl = LOG_ERR;
			}
			log_level(0, token->token_id, NULL, lvl,
				  "cmd_acquire %d,%d,%d acquire_token %d",
				  cl_ci, cl_fd, cl_pid, rv);
			result = rv;
			goto done;
		}
		acquire_count++;
	}

	/*
	 * Success acquiring the leases:
	 * lock mutex,
	 * 1. if pid is live, move new_tokens to cl->tokens, clear cmd_active, unlock mutex
	 * 2. if pid is dead, clear cmd_active, unlock mutex, release new_tokens, release cl->tokens, client_free
	 *
	 * Failure acquiring the leases:
	 * lock mutex,
	 * 3. if pid is live, clear cmd_active, unlock mutex, release new_tokens
	 * 4. if pid is dead, clear cmd_active, unlock mutex, release new_tokens, release cl->tokens, client_free
	 *
	 * client_pid_dead() won't touch cl->tokens while cmd_active is set.
	 * As soon as we clear cmd_active and unlock the mutex, client_pid_dead
	 * will attempt to clear cl->tokens itself.  If we find client_pid_dead
	 * has already happened when we look at pid_dead, then we know that it
	 * won't be called again, and it's our responsibility to clear cl->tokens
	 * and call client_free.
	 */

	/*
	 * We hold both space_mutex and cl->mutex at once to create the crucial
	 * linkage between the client pid and the lockspace.  Once we release
	 * these two mutexes, if the lockspace fails, this pid will be killed.
	 * Prior to inserting the new_tokens into the client, if the lockspace
	 * fails, kill_pids/client_using_pid would not find this pid (assuming
	 * it doesn't already hold other tokens using the lockspace).  If
	 * the lockspace failed while we were acquring the tokens, kill_pids
	 * has already run and not found us, so we must revert what we've done
	 * in acquire.
	 *
	 * Warning:
	 * We could deadlock if we hold cl->mutex and take spaces_mutex,
	 * because all_pids_dead() and kill_pids() hold spaces_mutex and take
	 * cl->mutex.  So, lock spaces_mutex first, then cl->mutex to avoid the
	 * deadlock.
	 *
	 * Other approaches:
	 * A solution may be to record in each sp all the pids/cis using it
	 * prior to starting the acquire.  Then we would not need to do this
	 * check here to see if the lockspace has been killed (if it was, the
	 * pid for this ci would have been killed in kill_pids), and
	 * all_pids_dead() and kill_pids() would not need to go through each cl
	 * and each cl->token to check if it's using the sp (it would know by
	 * just looking at sp->pids[] and killing each).
	 */

 done:
	pthread_mutex_lock(&spaces_mutex);
	pthread_mutex_lock(&cl->mutex);
	log_debug("cmd_acquire %d,%d,%d result %d pid_dead %d",
		  cl_ci, cl_fd, cl_pid, result, cl->pid_dead);

	pid_dead = cl->pid_dead;
	cl->cmd_active = 0;

	if (!result && !pid_dead) {
		if (check_new_tokens_space(cl, new_tokens, new_tokens_count)) {
			/* case 1 becomes case 3 */
			log_error("cmd_acquire %d,%d,%d invalid lockspace",
				  cl_ci, cl_fd, cl_pid);
			result = -ENOSPC;
		}
	}

	/* 1. Success acquiring leases, and pid is live */

	if (!result && !pid_dead) {
		for (i = 0; i < new_tokens_count; i++) {
			for (j = 0; j < SANLK_MAX_RESOURCES; j++) {
				if (!cl->tokens[j]) {
					cl->tokens[j] = new_tokens[i];
					break;
				}
			}
		}
		/* goto reply after mutex unlock */
	}
	pthread_mutex_unlock(&cl->mutex);
	pthread_mutex_unlock(&spaces_mutex);


	/* 1. Success acquiring leases, and pid is live */

	if (!result && !pid_dead) {
		/* work done before mutex unlock */
		goto reply;
	}

	/* 2. Success acquiring leases, and pid is dead */

	if (!result && pid_dead) {
		release_new_tokens(task, new_tokens, alloc_count, acquire_count);
		release_cl_tokens(task, cl);
		client_free(cl_ci);
		result = -ENOTTY;
		goto reply;
	}

	/* 3. Failure acquiring leases, and pid is live */

	if (result && !pid_dead) {
		release_new_tokens(task, new_tokens, alloc_count, acquire_count);
		goto reply;
	}

	/* 4. Failure acquiring leases, and pid is dead */

	if (result && pid_dead) {
		release_new_tokens(task, new_tokens, alloc_count, acquire_count);
		release_cl_tokens(task, cl);
		client_free(cl_ci);
		goto reply;
	}

 reply:
	if (!recv_done)
		client_recv_all(ca->ci_in, &ca->header, pos);
	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_release(struct task *task, struct cmd_args *ca)
{
	struct client *cl;
	struct token *token;
	struct token *rem_tokens[SANLK_MAX_RESOURCES];
	struct sanlk_resource res;
	int fd, rv, i, j, found, pid_dead;
	int rem_tokens_count = 0;
	int result = 0;
	int cl_ci = ca->ci_target;
	int cl_fd = ca->cl_fd;
	int cl_pid = ca->cl_pid;

	cl = &client[cl_ci];
	fd = client[ca->ci_in].fd;

	log_debug("cmd_release %d,%d,%d ci_in %d fd %d count %d flags %x",
		  cl_ci, cl_fd, cl_pid, ca->ci_in, fd,
		  ca->header.data, ca->header.cmd_flags);

	/* caller wants to release all resources */

	if (ca->header.cmd_flags & SANLK_REL_ALL) {
		pthread_mutex_lock(&cl->mutex);
		for (j = 0; j < SANLK_MAX_RESOURCES; j++) {
			token = cl->tokens[j];
			if (!token)
				continue;
			rem_tokens[rem_tokens_count++] = token;
			cl->tokens[j] = NULL;
		}
		pthread_mutex_unlock(&cl->mutex);
		goto do_remove;
	}

	/* caller is specifying specific resources to release */

	for (i = 0; i < ca->header.data; i++) {
		rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
		if (rv != sizeof(struct sanlk_resource)) {
			log_error("cmd_release %d,%d,%d recv res %d %d",
				  cl_ci, cl_fd, cl_pid, rv, errno);
			result = -ENOTCONN;
			break;
		}

		found = 0;

		pthread_mutex_lock(&cl->mutex);
		for (j = 0; j < SANLK_MAX_RESOURCES; j++) {
			token = cl->tokens[j];
			if (!token)
				continue;

			if (memcmp(token->r.lockspace_name, res.lockspace_name, NAME_ID_SIZE))
				continue;
			if (memcmp(token->r.name, res.name, NAME_ID_SIZE))
				continue;

			rem_tokens[rem_tokens_count++] = token;
			cl->tokens[j] = NULL;
			found = 1;
			break;
		}
		pthread_mutex_unlock(&cl->mutex);

		if (!found) {
			log_error("cmd_release %d,%d,%d no resource %.48s",
				  cl_ci, cl_fd, cl_pid, res.name);
			result = -1;
		}
	}

 do_remove:

	for (i = 0; i < rem_tokens_count; i++) {
		token = rem_tokens[i];
		rv = release_token(task, token);
		if (rv < 0)
			result = rv;
		free(token);
	}


	pthread_mutex_lock(&cl->mutex);
	log_debug("cmd_release %d,%d,%d result %d pid_dead %d count %d",
		  cl_ci, cl_fd, cl_pid, result, cl->pid_dead,
		  rem_tokens_count);

	pid_dead = cl->pid_dead;
	cl->cmd_active = 0;
	pthread_mutex_unlock(&cl->mutex);

	if (pid_dead) {
		/* release any tokens not already released above */
		release_cl_tokens(task, cl);
		client_free(cl_ci);
	}

	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_inquire(struct task *task, struct cmd_args *ca)
{
	struct sm_header h;
	struct token *token;
	struct client *cl;
	char *state = NULL, *str;
	int state_maxlen = 0, state_strlen = 0;
	int res_count = 0, cat_count = 0;
	int fd, i, rv, pid_dead;
	int result = 0;
	int cl_ci = ca->ci_target;
	int cl_fd = ca->cl_fd;
	int cl_pid = ca->cl_pid;

	cl = &client[cl_ci];
	fd = client[ca->ci_in].fd;

	log_debug("cmd_inquire %d,%d,%d ci_in %d fd %d",
		  cl_ci, cl_fd, cl_pid, ca->ci_in, fd);

	pthread_mutex_lock(&cl->mutex);

	if (cl->pid_dead) {
		result = -ESTALE;
		goto done;
	}

	for (i = 0; i < SANLK_MAX_RESOURCES; i++) {
		if (cl->tokens[i])
			res_count++;
	}

	if (!res_count) {
		result = 0;
		goto done;
	}

	state_maxlen = res_count * (SANLK_MAX_RES_STR + 1);

	state = malloc(state_maxlen);
	if (!state) {
		result = -ENOMEM;
		goto done;
	}
	memset(state, 0, state_maxlen);

	/* should match sanlock_args_to_state() */

	for (i = 0; i < SANLK_MAX_RESOURCES; i++) {
		token = cl->tokens[i];
		if (!token)
			continue;

		/* check number of tokens hasn't changed since first count */

		if (cat_count >= res_count) {
			log_error("cmd_inquire %d,%d,%d count changed %d %d",
				  cl_ci, cl_fd, cl_pid, res_count, cat_count);
			result = -ENOENT;
			goto done;
		}

		str = NULL;

		rv = sanlock_res_to_str(&token->r, &str);
		if (rv < 0 || !str) {
			log_errot(token, "cmd_inquire %d,%d,%d res_to_str %d",
				  cl_ci, cl_fd, cl_pid, rv);
			result = -ELIBACC;
			goto done;
		}

		if (strlen(str) > SANLK_MAX_RES_STR - 1) {
			log_errot(token, "cmd_inquire %d,%d,%d strlen %zu",
				  cl_ci, cl_fd, cl_pid, strlen(str));
			free(str);
			result = -ELIBBAD;
			goto done;
		}

		/* space is str separator, so it's invalid within each str */

		if (strstr(str, " ")) {
			log_errot(token, "cmd_inquire %d,%d,%d str space",
				  cl_ci, cl_fd, cl_pid);
			free(str);
			result = -ELIBSCN;
			goto done;
		}

		if (cat_count)
			strcat(state, " ");
		strcat(state, str);
		cat_count++;
		free(str);
	}

	state[state_maxlen - 1] = '\0';
	state_strlen = strlen(state);
	result = 0;
 done:
	pid_dead = cl->pid_dead;
	cl->cmd_active = 0;
	pthread_mutex_unlock(&cl->mutex);

	log_debug("cmd_inquire %d,%d,%d result %d pid_dead %d res_count %d cat_count %d strlen %d",
		  cl_ci, cl_fd, cl_pid, result, pid_dead, res_count, cat_count, state_strlen);

	if (pid_dead) {
		release_cl_tokens(task, cl);
		client_free(cl_ci);
	}

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.data = result;
	h.data2 = res_count;

	if (state) {
		h.length = sizeof(h) + state_strlen + 1;
		send(fd, &h, sizeof(h), MSG_NOSIGNAL);
		send(fd, state, state_strlen + 1, MSG_NOSIGNAL);
		free(state);
	} else {
		h.length = sizeof(h);
		send(fd, &h, sizeof(h), MSG_NOSIGNAL);
	}

	client_resume(ca->ci_in);
}

static void cmd_request(struct task *task, struct cmd_args *ca)
{
	struct token *token;
	struct sanlk_resource res;
	uint64_t owner_id;
	uint32_t force_mode;
	int token_len, disks_len;
	int j, fd, rv, error, result;

	fd = client[ca->ci_in].fd;

	force_mode = ca->header.data;

	/* receiving and setting up token copied from cmd_acquire */

	rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_resource)) {
		log_error("cmd_request %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	if (!res.num_disks || res.num_disks > SANLK_MAX_DISKS) {
		result = -ERANGE;
		goto reply;
	}

	disks_len = res.num_disks * sizeof(struct sync_disk);
	token_len = sizeof(struct token) + disks_len;

	token = malloc(token_len);
	if (!token) {
		result = -ENOMEM;
		goto reply;
	}

	memset(token, 0, token_len);
	token->disks = (struct sync_disk *)&token->r.disks[0]; /* shorthand */
	token->r.num_disks = res.num_disks;
	memcpy(token->r.lockspace_name, res.lockspace_name, SANLK_NAME_LEN);
	memcpy(token->r.name, res.name, SANLK_NAME_LEN);

	token->acquire_lver = res.lver;
	token->acquire_data64 = res.data64;
	token->acquire_data32 = res.data32;
	token->acquire_flags = res.flags;

	/*
	 * receive sanlk_disk's / sync_disk's
	 *
	 * WARNING: as a shortcut, this requires that sync_disk and
	 * sanlk_disk match; this is the reason for the pad fields
	 * in sanlk_disk (TODO: let these differ?)
	 */

	rv = recv(fd, token->disks, disks_len, MSG_WAITALL);
	if (rv != disks_len) {
		result = -ENOTCONN;
		goto reply_free;
	}

	/* zero out pad1 and pad2, see WARNING above */
	for (j = 0; j < token->r.num_disks; j++) {
		token->disks[j].sector_size = 0;
		token->disks[j].fd = -1;
	}

	log_debug("cmd_request %d,%d force_mode %u %.48s:%.48s:%.256s:%llu",
		  ca->ci_in, fd, force_mode,
		  token->r.lockspace_name,
		  token->r.name,
		  token->disks[0].path,
		  (unsigned long long)token->r.disks[0].offset);

	error = request_token(task, token, force_mode, &owner_id);
	if (error < 0) {
		result = error;
		goto reply_free;
	}

	result = 0;

	if (!token->acquire_lver && !force_mode)
		goto reply_free;

	if (owner_id)
		host_status_set_bit(token->r.lockspace_name, owner_id);
 reply_free:
	free(token);
 reply:
	log_debug("cmd_request %d,%d done %d", ca->ci_in, fd, result);

	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_examine(struct task *task GNUC_UNUSED, struct cmd_args *ca)
{
	union {
		struct sanlk_resource r;
		struct sanlk_lockspace s;
	} buf;
	struct sanlk_resource *res = NULL;
	struct sanlk_lockspace *ls = NULL;
	char *space_name = NULL;
	char *res_name = NULL;
	int fd, rv, result, count = 0, datalen;

	fd = client[ca->ci_in].fd;

	if (ca->header.cmd == SM_CMD_EXAMINE_RESOURCE) {
		datalen = sizeof(struct sanlk_resource);
		res = &buf.r;
	} else {
		datalen = sizeof(struct sanlk_lockspace);
		ls = &buf.s;
	}

	rv = recv(fd, &buf, datalen, MSG_WAITALL);
	if (rv != datalen) {
		log_error("cmd_examine %d,%d recv %d %d",
			  ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	if (res) {
		space_name = res->lockspace_name;
		res_name = res->name;
	} else {
		space_name = ls->name;
	}

	log_debug("cmd_examine %d,%d %.48s %.48s",
		  ca->ci_in, fd, space_name, res_name ? res_name : "");

	count = set_resource_examine(space_name, res_name);
	result = 0;
 reply:
	log_debug("cmd_examine %d,%d done %d", ca->ci_in, fd, count);

	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_add_lockspace(struct cmd_args *ca)
{
	struct sanlk_lockspace lockspace;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_add_lockspace %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_debug("cmd_add_lockspace %d,%d %.48s:%llu:%s:%llu",
		  ca->ci_in, fd, lockspace.name,
		  (unsigned long long)lockspace.host_id,
		  lockspace.host_id_disk.path,
		  (unsigned long long)lockspace.host_id_disk.offset);

	result = add_lockspace(&lockspace);
 reply:
	log_debug("cmd_add_lockspace %d,%d done %d", ca->ci_in, fd, result);

	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_inq_lockspace(struct cmd_args *ca)
{
	struct sanlk_lockspace lockspace;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_inq_lockspace %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_debug("cmd_inq_lockspace %d,%d %.48s:%llu:%s:%llu",
		  ca->ci_in, fd, lockspace.name,
		  (unsigned long long)lockspace.host_id,
		  lockspace.host_id_disk.path,
		  (unsigned long long)lockspace.host_id_disk.offset);

	result = inq_lockspace(&lockspace);
 reply:
	log_debug("cmd_inq_lockspace %d,%d done %d", ca->ci_in, fd, result);

	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

/*
 * TODO: rem_lockspace works like a renewal failure would, and abandons
 * resource leases (tokens) without releasing them.  Unlike the renewal
 * failure case, rem_lockspace most likely releases the host_id.
 *
 * What might be nice is an option where rem_lockspace would try to
 * release resource leases before releasing the lockspace host_id.
 * (We don't really want to be releasing tokens after we've released
 * our host_id for the token's lockspace.)
 *
 * - kill all pids (by looking at struct resource pid?)
 * - wait for all pids to exit
 * o have us or other thread release their tokens/resources
 * o wait for tokens/resources to be released, although the release
 *   may fail or time out, we don't want to wait too long
 * - set sp->external_remove
 * - main_loop sets sp->thread_stop (should find no pids)
 * - main_loop unlinks watchdog
 * - lockspace_thread releases host_id
 *
 * The aim is that we kill pids and wait for resources to be released
 * before main_loop gets involved and before the lockspace_thread is
 * told to stop.
 *
 * An alternative messy is to add another condition to the current
 * main_loop checks:
 *
 * if (sp->killing_pids && all_pids_dead(sp) && all_tokens_released(sp)) {
 * 	sp->thread_stop = 1;
 * 	unlink_watchdog_file(sp);
 * 	list_move(spaces_rem);
 * }
 *
 * all_tokens_released would just return 1 in case we're not doing
 * the releases
 *
 * release_token_async would need to learn to put the resources onto
 * dispose list in this case
 *
 * consider using the resources/dispose_resources list for all_pids_dead
 * and kill_pids?  instead of the clients[].tokens[] loops?  actually,
 * could we remove tokens and cl->tokens altogether and just use the
 * resources list?
 */

static void cmd_rem_lockspace(struct cmd_args *ca)
{
	struct sanlk_lockspace lockspace;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_rem_lockspace %d,%d recv %d %d",
			  ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_debug("cmd_rem_lockspace %d,%d %.48s",
		  ca->ci_in, fd, lockspace.name);

	result = rem_lockspace(&lockspace);
 reply:
	log_debug("cmd_rem_lockspace %d,%d done %d", ca->ci_in, fd, result);

	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_align(struct task *task GNUC_UNUSED, struct cmd_args *ca)
{
	struct sanlk_disk disk;
	struct sync_disk sd;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &disk, sizeof(struct sanlk_disk), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_disk)) {
		log_error("cmd_align %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_debug("cmd_align %d,%d", ca->ci_in, fd);

	if (!disk.path[0]) {
		result = -ENODEV;
		goto reply;
	}

	memset(&sd, 0, sizeof(struct sync_disk));
	memcpy(&sd, &disk, sizeof(struct sanlk_disk));
	sd.fd = -1;

	rv = open_disk(&sd);
	if (rv < 0) {
		result = -ENODEV;
		goto reply;
	}

	result = direct_align(&sd);

	close_disks(&sd, 1);
 reply:
	log_debug("cmd_align %d,%d done %d", ca->ci_in, fd, result);

	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_init_lockspace(struct task *task, struct cmd_args *ca)
{
	struct sanlk_lockspace lockspace;
	struct sync_disk sd;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_init_lockspace %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_debug("cmd_init_lockspace %d,%d %.48s:%llu:%s:%llu",
		  ca->ci_in, fd, lockspace.name,
		  (unsigned long long)lockspace.host_id,
		  lockspace.host_id_disk.path,
		  (unsigned long long)lockspace.host_id_disk.offset);

	if (!lockspace.host_id_disk.path[0]) {
		result = -ENODEV;
		goto reply;
	}

	memset(&sd, 0, sizeof(struct sync_disk));
	memcpy(&sd, &lockspace.host_id_disk, sizeof(struct sanlk_disk));
	sd.fd = -1;

	rv = open_disk(&sd);
	if (rv < 0) {
		result = -ENODEV;
		goto reply;
	}

	result = delta_lease_init(task, &sd, lockspace.name, ca->header.data);

	close_disks(&sd, 1);
 reply:
	log_debug("cmd_init_lockspace %d,%d done %d", ca->ci_in, fd, result);

	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_init_resource(struct task *task, struct cmd_args *ca)
{
	struct token *token = NULL;
	struct sanlk_resource res;
	int token_len, disks_len;
	int j, fd, rv, result;

	fd = client[ca->ci_in].fd;

	/* receiving and setting up token copied from cmd_acquire */

	rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_resource)) {
		log_error("cmd_init_resource %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	if (!res.num_disks || res.num_disks > SANLK_MAX_DISKS) {
		result = -ERANGE;
		goto reply;
	}

	disks_len = res.num_disks * sizeof(struct sync_disk);
	token_len = sizeof(struct token) + disks_len;

	token = malloc(token_len);
	if (!token) {
		result = -ENOMEM;
		goto reply;
	}
	memset(token, 0, token_len);
	token->disks = (struct sync_disk *)&token->r.disks[0]; /* shorthand */
	token->r.num_disks = res.num_disks;
	memcpy(token->r.lockspace_name, res.lockspace_name, SANLK_NAME_LEN);
	memcpy(token->r.name, res.name, SANLK_NAME_LEN);

	/*
	 * receive sanlk_disk's / sync_disk's
	 *
	 * WARNING: as a shortcut, this requires that sync_disk and
	 * sanlk_disk match; this is the reason for the pad fields
	 * in sanlk_disk (TODO: let these differ?)
	 */

	rv = recv(fd, token->disks, disks_len, MSG_WAITALL);
	if (rv != disks_len) {
		result = -ENOTCONN;
		goto reply;
	}

	/* zero out pad1 and pad2, see WARNING above */
	for (j = 0; j < token->r.num_disks; j++) {
		token->disks[j].sector_size = 0;
		token->disks[j].fd = -1;
	}

	log_debug("cmd_init_resource %d,%d %.48s:%.48s:%.256s:%llu",
		  ca->ci_in, fd,
		  token->r.lockspace_name,
		  token->r.name,
		  token->disks[0].path,
		  (unsigned long long)token->r.disks[0].offset);

	rv = open_disks(token->disks, token->r.num_disks);
	if (rv < 0) {
		result = rv;
		goto reply;
	}

	result = paxos_lease_init(task, token, ca->header.data, ca->header.data2);

	close_disks(token->disks, token->r.num_disks);
 reply:
	if (token)
		free(token);
	log_debug("cmd_init_resource %d,%d done %d", ca->ci_in, fd, result);

	send_result(fd, &ca->header, result);
	client_resume(ca->ci_in);
}

void call_cmd_thread(struct task *task, struct cmd_args *ca)
{
	switch (ca->header.cmd) {
	case SM_CMD_ACQUIRE:
		cmd_acquire(task, ca);
		break;
	case SM_CMD_RELEASE:
		cmd_release(task, ca);
		break;
	case SM_CMD_INQUIRE:
		cmd_inquire(task, ca);
		break;
	case SM_CMD_REQUEST:
		cmd_request(task, ca);
		break;
	case SM_CMD_ADD_LOCKSPACE:
		strcpy(client[ca->ci_in].owner_name, "add_lockspace");
		cmd_add_lockspace(ca);
		break;
	case SM_CMD_INQ_LOCKSPACE:
		strcpy(client[ca->ci_in].owner_name, "inq_lockspace");
		cmd_inq_lockspace(ca);
		break;
	case SM_CMD_REM_LOCKSPACE:
		strcpy(client[ca->ci_in].owner_name, "rem_lockspace");
		cmd_rem_lockspace(ca);
		break;
	case SM_CMD_ALIGN:
		cmd_align(task, ca);
		break;
	case SM_CMD_INIT_LOCKSPACE:
		cmd_init_lockspace(task, ca);
		break;
	case SM_CMD_INIT_RESOURCE:
		cmd_init_resource(task, ca);
		break;
	case SM_CMD_EXAMINE_LOCKSPACE:
	case SM_CMD_EXAMINE_RESOURCE:
		cmd_examine(task, ca);
		break;
	};
}

/*
 * sanlock client status
 *
 * 1. send_state_daemon
 *
 * 2. for each cl in clients
 *     send_state_client() [sanlk_state + str_len]
 *
 * 3. for each sp in spaces, spaces_add, spaces_rem
 *     send_state_lockspace() [sanlk_state + str_len + sanlk_lockspace]
 *
 * 4. for each r in resources, dispose_resources
 *     send_state_resource() [sanlk_state + str_len + sanlk_resource + sanlk_disk * num_disks]
 *
 * sanlock client host_status <lockspace_name>
 *
 * 1. for each hs in sp->host_status
 * 	send_state_host()
 */

static int print_state_daemon(char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "our_host_name=%s "
		 "use_aio=%d "
		 "io_timeout=%d "
		 "id_renewal=%d "
		 "id_renewal_fail=%d "
		 "id_renewal_warn=%d "
		 "monotime=%llu",
		 our_host_name_global,
		 main_task.use_aio,
		 main_task.io_timeout_seconds,
		 main_task.id_renewal_seconds,
		 main_task.id_renewal_fail_seconds,
		 main_task.id_renewal_warn_seconds,
		 (unsigned long long)monotime());

	return strlen(str) + 1;
}

static int print_state_client(struct client *cl, int ci, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "ci=%d "
		 "fd=%d "
		 "pid=%d "
		 "restrict=%x "
		 "cmd_active=%d "
		 "cmd_last=%d "
		 "pid_dead=%d "
		 "kill_count=%d "
		 "kill_last=%llu "
		 "suspend=%d "
		 "need_free=%d",
		 ci,
		 cl->fd,
		 cl->pid,
		 cl->restrict,
		 cl->cmd_active,
		 cl->cmd_last,
		 cl->pid_dead,
		 cl->kill_count,
		 (unsigned long long)cl->kill_last,
		 cl->suspend,
		 cl->need_free);

	return strlen(str) + 1;
}

static int print_state_lockspace(struct space *sp, char *str, const char *list_name)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "list=%s "
		 "space_id=%u "
		 "host_generation=%llu "
		 "space_dead=%d "
		 "killing_pids=%d "
		 "corrupt_result=%d "
		 "acquire_last_result=%d "
		 "renewal_last_result=%d "
		 "acquire_last_attempt=%llu "
		 "acquire_last_success=%llu "
		 "renewal_last_attempt=%llu "
		 "renewal_last_success=%llu",
		 list_name,
		 sp->space_id,
		 (unsigned long long)sp->host_generation,
		 sp->space_dead,
		 sp->killing_pids,
		 sp->lease_status.corrupt_result,
		 sp->lease_status.acquire_last_result,
		 sp->lease_status.renewal_last_result,
		 (unsigned long long)sp->lease_status.acquire_last_attempt,
		 (unsigned long long)sp->lease_status.acquire_last_success,
		 (unsigned long long)sp->lease_status.renewal_last_attempt,
		 (unsigned long long)sp->lease_status.renewal_last_success);

	return strlen(str) + 1;
}

static int print_state_resource(struct resource *r, char *str, const char *list_name,
				uint32_t token_id)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "list=%s "
		 "flags=%x "
		 "lver=%llu "
		 "token_id=%u",
		 list_name,
		 r->flags,
		 (unsigned long long)r->leader.lver,
		 token_id);

	return strlen(str) + 1;
}

static int print_state_host(struct host_status *hs, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "last_check=%llu "
		 "last_live=%llu "
		 "last_req=%llu "
		 "owner_id=%llu "
		 "owner_generation=%llu "
		 "timestamp=%llu",
		 (unsigned long long)hs->last_check,
		 (unsigned long long)hs->last_live,
		 (unsigned long long)hs->last_req,
		 (unsigned long long)hs->owner_id,
		 (unsigned long long)hs->owner_generation,
		 (unsigned long long)hs->timestamp);

	return strlen(str) + 1;
}

static void send_state_daemon(int fd)
{
	struct sanlk_state st;
	char str[SANLK_STATE_MAXSTR];
	int str_len;

	memset(&st, 0, sizeof(st));
	strncpy(st.name, our_host_name_global, NAME_ID_SIZE);

	st.type = SANLK_STATE_DAEMON;

	str_len = print_state_daemon(str);

	st.str_len = str_len;

	send(fd, &st, sizeof(st), MSG_NOSIGNAL);
	if (str_len)
		send(fd, str, str_len, MSG_NOSIGNAL);
}

static void send_state_client(int fd, struct client *cl, int ci)
{
	struct sanlk_state st;
	char str[SANLK_STATE_MAXSTR];
	int str_len;

	memset(&st, 0, sizeof(st));

	st.type = SANLK_STATE_CLIENT;
	st.data32 = cl->pid;
	strncpy(st.name, cl->owner_name, NAME_ID_SIZE);

	str_len = print_state_client(cl, ci, str);

	st.str_len = str_len;

	send(fd, &st, sizeof(st), MSG_NOSIGNAL);
	if (str_len)
		send(fd, str, str_len, MSG_NOSIGNAL);
}

static void send_state_lockspace(int fd, struct space *sp, const char *list_name)
{
	struct sanlk_state st;
	struct sanlk_lockspace lockspace;
	char str[SANLK_STATE_MAXSTR];
	int str_len;

	memset(&st, 0, sizeof(st));

	st.type = SANLK_STATE_LOCKSPACE;
	st.data64 = sp->host_id;
	strncpy(st.name, sp->space_name, NAME_ID_SIZE);

	str_len = print_state_lockspace(sp, str, list_name);

	st.str_len = str_len;

	send(fd, &st, sizeof(st), MSG_NOSIGNAL);
	if (str_len)
		send(fd, str, str_len, MSG_NOSIGNAL);

	memset(&lockspace, 0, sizeof(struct sanlk_lockspace));
	strncpy(lockspace.name, sp->space_name, NAME_ID_SIZE);
	lockspace.host_id = sp->host_id;
	memcpy(&lockspace.host_id_disk, &sp->host_id_disk, sizeof(struct sanlk_disk));

	send(fd, &lockspace, sizeof(lockspace), MSG_NOSIGNAL);
}

void send_state_resource(int fd, struct resource *r, const char *list_name,
			 int pid, uint32_t token_id);

void send_state_resource(int fd, struct resource *r, const char *list_name,
			 int pid, uint32_t token_id)
{
	struct sanlk_state st;
	char str[SANLK_STATE_MAXSTR];
	int str_len;
	int i;

	memset(&st, 0, sizeof(st));

	st.type = SANLK_STATE_RESOURCE;
	st.data32 = pid;
	st.data64 = r->leader.lver;
	strncpy(st.name, r->r.name, NAME_ID_SIZE);

	str_len = print_state_resource(r, str, list_name, token_id);

	st.str_len = str_len;

	send(fd, &st, sizeof(st), MSG_NOSIGNAL);
	if (str_len)
		send(fd, str, str_len, MSG_NOSIGNAL);

	send(fd, &r->r, sizeof(struct sanlk_resource), MSG_NOSIGNAL);

	for (i = 0; i < r->r.num_disks; i++) {
		send(fd, &r->r.disks[i], sizeof(struct sanlk_disk), MSG_NOSIGNAL);
	}
}

static void send_state_host(int fd, struct host_status *hs, int host_id)
{
	struct sanlk_state st;
	char str[SANLK_STATE_MAXSTR];
	int str_len;

	memset(&st, 0, sizeof(st));

	st.type = SANLK_STATE_HOST;
	st.data32 = host_id;
	st.data64 = hs->timestamp;

	str_len = print_state_host(hs, str);

	st.str_len = str_len;

	send(fd, &st, sizeof(st), MSG_NOSIGNAL);
	if (str_len)
		send(fd, str, str_len, MSG_NOSIGNAL);
}

static void cmd_status(int fd, struct sm_header *h_recv, int client_maxi)
{
	struct sm_header h;
	struct client *cl;
	struct space *sp;
	int ci;

	memset(&h, 0, sizeof(h));
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = 0;

	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	send_state_daemon(fd);

	if (h_recv->data == SANLK_STATE_DAEMON)
		return;

	for (ci = 0; ci <= client_maxi; ci++) {
		cl = &client[ci];
		if (!cl->used)
			continue;
		send_state_client(fd, cl, ci);
	}

	if (h_recv->data == SANLK_STATE_CLIENT)
		return;

	pthread_mutex_lock(&spaces_mutex);
	list_for_each_entry(sp, &spaces, list)
		send_state_lockspace(fd, sp, "spaces");
	list_for_each_entry(sp, &spaces_rem, list)
		send_state_lockspace(fd, sp, "spaces_rem");
	list_for_each_entry(sp, &spaces_rem, list)
		send_state_lockspace(fd, sp, "spaces_add");
	pthread_mutex_unlock(&spaces_mutex);

	if (h_recv->data == SANLK_STATE_LOCKSPACE)
		return;

	/* resource.c will iterate through private lists and call
	   back here for each r */

	send_state_resources(fd);
}

static void cmd_host_status(int fd, struct sm_header *h_recv)
{
	struct sm_header h;
	struct sanlk_lockspace lockspace;
	struct space *sp;
	struct host_status *hs, *status = NULL;
	int status_len;
	int i, rv;

	memset(&h, 0, sizeof(h));
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = 0;

	status_len = sizeof(struct host_status) * DEFAULT_MAX_HOSTS;

	status = malloc(status_len);
	if (!status) {
		h.data = -ENOMEM;
		goto fail;
	}

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		h.data = -ENOTCONN;
		goto fail;
	}

	pthread_mutex_lock(&spaces_mutex);
	sp = find_lockspace(lockspace.name);
	if (sp)
		memcpy(status, &sp->host_status, status_len);
	pthread_mutex_unlock(&spaces_mutex);

	if (!sp) {
		h.data = -ENOSPC;
		goto fail;
	}

	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	for (i = 0; i < DEFAULT_MAX_HOSTS; i++) {
		hs = &status[i];
		if (!hs->last_live && !hs->owner_id)
			continue;
		send_state_host(fd, hs, i+1);
	}

	if (status)
		free(status);
	return;
 fail:
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	if (status)
		free(status);
}

static char send_log_dump[LOG_DUMP_SIZE];

static void cmd_log_dump(int fd, struct sm_header *h_recv)
{
	int len;

	copy_log_dump(send_log_dump, &len);

	h_recv->data = len;

	send(fd, h_recv, sizeof(struct sm_header), MSG_NOSIGNAL);
	send(fd, send_log_dump, len, MSG_NOSIGNAL);
}

static void cmd_restrict(int ci, int fd, struct sm_header *h_recv)
{
	log_debug("cmd_restrict ci %d fd %d pid %d flags %x",
		  ci, fd, client[ci].pid, h_recv->cmd_flags);

	client[ci].restrict = h_recv->cmd_flags;

	send_result(fd, h_recv, 0);
}

static int get_peer_pid(int fd, int *pid)
{
	struct ucred cred;
	unsigned int len = sizeof(cred);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
		return -1;

	*pid = cred.pid;
	return 0;
}

void call_cmd_daemon(int ci, struct sm_header *h_recv, int client_maxi)
{
	int rv, pid, auto_close = 1;
	int fd = client[ci].fd;

	switch (h_recv->cmd) {
	case SM_CMD_REGISTER:
		rv = get_peer_pid(fd, &pid);
		if (rv < 0) {
			log_error("cmd_register ci %d fd %d get pid failed", ci, fd);
			break;
		}
		log_debug("cmd_register ci %d fd %d pid %d", ci, fd, pid);
		snprintf(client[ci].owner_name, SANLK_NAME_LEN, "%d", pid);
		client[ci].pid = pid;
		client[ci].deadfn = client_pid_dead;
		auto_close = 0;
		break;
	case SM_CMD_RESTRICT:
		cmd_restrict(ci, fd, h_recv);
		auto_close = 0;
		break;
	case SM_CMD_SHUTDOWN:
		strcpy(client[ci].owner_name, "shutdown");
		if (h_recv->data) {
			/* force */
			external_shutdown = 2;
		} else {
			pthread_mutex_lock(&spaces_mutex);
			if (list_empty(&spaces) &&
			    list_empty(&spaces_rem) &&
			    list_empty(&spaces_add))
				external_shutdown = 1;
			else
				log_debug("ignore shutdown, lockspace exists");
			pthread_mutex_unlock(&spaces_mutex);
		}
		break;
	case SM_CMD_STATUS:
		strcpy(client[ci].owner_name, "status");
		cmd_status(fd, h_recv, client_maxi);
		break;
	case SM_CMD_HOST_STATUS:
		strcpy(client[ci].owner_name, "host_status");
		cmd_host_status(fd, h_recv);
		break;
	case SM_CMD_LOG_DUMP:
		strcpy(client[ci].owner_name, "log_dump");
		cmd_log_dump(fd, h_recv);
		break;
	};

	if (auto_close)
		close(fd);
}

