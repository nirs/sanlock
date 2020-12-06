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
#include "sanlock_admin.h"
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
#include "rindex.h"

/* from main.c */
void client_resume(int ci);
void client_free(int ci);
void client_recv_all(int ci, struct sm_header *h_recv, int pos);
void client_pid_dead(int ci);
void send_result(int ci, int fd, struct sm_header *h_recv, int result);

static uint32_t token_id_counter = 1;

static void release_cl_tokens(struct task *task, struct client *cl)
{
	struct token *token;
	int j;

	for (j = 0; j < cl->tokens_slots; j++) {
		token = cl->tokens[j];
		if (!token)
			continue;
		release_token(task, token, NULL);
		free(token);
	}
}

static void release_new_tokens(struct task *task, struct token *new_tokens[],
			       int alloc_count, int acquire_count)
{
	int i;

	for (i = 0; i < acquire_count; i++)
		release_token(task, new_tokens[i], NULL);

	for (i = 0; i < alloc_count; i++)
		free(new_tokens[i]);
}

/* called with both spaces_mutex and cl->mutex held */

static int check_new_tokens_space(struct client *cl,
				  struct token *new_tokens[],
				  int new_tokens_count)
{
	struct space_info spi;
	struct token *token;
	int i, rv, empty_slots = 0;

	for (i = 0; i < cl->tokens_slots; i++) {
		if (!cl->tokens[i])
			empty_slots++;
	}

	if (empty_slots < new_tokens_count) {
		/* shouldn't ever happen */
		log_error("check_new_tokens_space slots %d empty %d new_tokens %d",
			  cl->tokens_slots, empty_slots, new_tokens_count);
		return -ENOENT;
	}

	/* space may have failed while new tokens were being acquired */

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];

		rv = _lockspace_info(token->r.lockspace_name, &spi);

		if (!rv && !spi.killing_pids && spi.host_id == token->host_id)
			continue;

		return -ENOSPC;
	}

	return 0;
}

static const char *acquire_error_str(int error)
{
	switch (error) {
	case SANLK_ACQUIRE_IDLIVE:
	case SANLK_ACQUIRE_OWNED:
	case SANLK_ACQUIRE_OTHER:
	case SANLK_ACQUIRE_OWNED_RETRY:
		return "lease owned by other host";

	case SANLK_ACQUIRE_SHRETRY:
		return "shared lease contention";

	case SANLK_DBLOCK_READ:
	case SANLK_DBLOCK_WRITE:
	case SANLK_LEADER_READ:
	case SANLK_LEADER_WRITE:
		return "lease io error";

	case SANLK_LEADER_DIFF:
	case SANLK_LEADER_VERSION:
	case SANLK_LEADER_SECTORSIZE:
	case SANLK_LEADER_LOCKSPACE:
	case SANLK_LEADER_RESOURCE:
	case SANLK_LEADER_NUMHOSTS:
	case SANLK_LEADER_CHECKSUM:
		return "lease data invalid";

	case SANLK_LEADER_MAGIC:
		return "lease not found";

	default:
		return "";
	};
}

static void cmd_acquire(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct client *cl;
	struct token *token = NULL;
	struct token *new_tokens[SANLK_MAX_RESOURCES];
	struct token **grow_tokens;
	struct sanlk_resource res;
	struct sanlk_options opt;
	struct space_info spi;
	char killpath[SANLK_HELPER_PATH_LEN];
	char killargs[SANLK_HELPER_ARGS_LEN];
	char *opt_str;
	int token_len, disks_len;
	int fd, rv, i, j, empty_slots, lvl;
	int alloc_count = 0, acquire_count = 0;
	int pos = 0, pid_dead = 0;
	int new_tokens_count;
	int recv_done = 0;
	int result = 0;
	int grow_size;
	int cl_ci = ca->ci_target;
	int cl_fd = ca->cl_fd;
	int cl_pid = ca->cl_pid;

	cl = &client[cl_ci];
	fd = client[ca->ci_in].fd;

	new_tokens_count = ca->header.data;

	log_cmd(cmd, "cmd_acquire %d,%d,%d ci_in %d fd %d count %d flags %x",
		  cl_ci, cl_fd, cl_pid, ca->ci_in, fd, new_tokens_count, ca->header.cmd_flags);

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
	for (i = 0; i < cl->tokens_slots; i++) {
		if (!cl->tokens[i])
			empty_slots++;
	}

	if (empty_slots < new_tokens_count) {
		log_debug("cmd_acquire grow tokens slots %d empty %d new %d",
			  cl->tokens_slots, empty_slots, new_tokens_count);

		grow_size = (cl->tokens_slots + (SANLK_MAX_RESOURCES * 2)) * sizeof(struct token *);
		grow_tokens = malloc(grow_size);
		if (!grow_tokens) {
			log_error("cmd_acquire ENOMEM grow tokens slots %d empty %d new %d grow_size %d",
				  cl->tokens_slots, empty_slots, new_tokens_count, grow_size);
			result = -ENOMEM;
			pthread_mutex_unlock(&cl->mutex);
			goto done;
		} else {
			memset(grow_tokens, 0, grow_size);
			memcpy(grow_tokens, cl->tokens, cl->tokens_slots * sizeof(struct token *));
			free(cl->tokens);
			cl->tokens = grow_tokens;
			cl->tokens_slots += (SANLK_MAX_RESOURCES * 2);
			empty_slots += (SANLK_MAX_RESOURCES * 2);
		}
	}

	memcpy(killpath, cl->killpath, SANLK_HELPER_PATH_LEN);
	memcpy(killargs, cl->killargs, SANLK_HELPER_ARGS_LEN);
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
		rv = lockspace_info(token->r.lockspace_name, &spi);
		if (rv < 0 || spi.killing_pids) {
			log_errot(token, "cmd_acquire %d,%d,%d invalid lockspace "
				  "found %d failed %d name %.48s",
				  cl_ci, cl_fd, cl_pid, rv, spi.killing_pids,
				  token->r.lockspace_name);
			result = -ENOSPC;
			goto done;
		}
		token->host_id = spi.host_id;
		token->host_generation = spi.host_generation;
		token->space_id = spi.space_id;
		token->pid = cl_pid;
		token->io_timeout = spi.io_timeout;
		token->sector_size = spi.sector_size; /* starting hint, may be changed */
		token->align_size = spi.align_size; /* starting hint, may be changed */
		if (cl->restricted & SANLK_RESTRICT_SIGKILL)
			token->flags |= T_RESTRICT_SIGKILL;
		if (cl->restricted & SANLK_RESTRICT_SIGTERM)
			token->flags |= T_RESTRICT_SIGTERM;

	}

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];

		rv = acquire_token(task, token, ca->header.cmd_flags, killpath, killargs);
		if (rv < 0) {
			switch (rv) {
			case -EEXIST:
			case -EAGAIN:
			case -EBUSY:
				lvl = LOG_DEBUG;
				break;
			case SANLK_ACQUIRE_IDLIVE:
			case SANLK_ACQUIRE_OWNED:
			case SANLK_ACQUIRE_OTHER:
			case SANLK_ACQUIRE_OWNED_RETRY:
				lvl = com.quiet_fail ? LOG_DEBUG : LOG_ERR;
				break;
			default:
				lvl = LOG_ERR;
			}

			if (token->res_id)
				log_level(token->space_id, token->res_id, NULL, lvl,
					  "cmd_acquire %d,%d,%d acquire_token %d %s",
					  cl_ci, cl_fd, cl_pid, rv, acquire_error_str(rv));
			else
				log_level(token->space_id, 0, NULL, lvl,
					  "cmd_acquire %d,%d,%d acquire_token %s %d %s",
					  cl_ci, cl_fd, cl_pid,
					  token->r.name, rv, acquire_error_str(rv));
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
	log_cmd(cmd, "cmd_acquire %d,%d,%d result %d pid_dead %d",
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
			for (j = 0; j < cl->tokens_slots; j++) {
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
	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_release(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct client *cl;
	struct token *token;
	struct token *rem_tokens[SANLK_MAX_RESOURCES];
	struct sanlk_resource res;
	struct sanlk_resource new;
	struct sanlk_resource *resrename = NULL;
	int fd, rv, i, j, found, pid_dead;
	int rem_tokens_count = 0;
	int result = 0;
	int cl_ci = ca->ci_target;
	int cl_fd = ca->cl_fd;
	int cl_pid = ca->cl_pid;

	cl = &client[cl_ci];
	fd = client[ca->ci_in].fd;

	log_cmd(cmd, "cmd_release %d,%d,%d ci_in %d fd %d count %d flags %x",
		  cl_ci, cl_fd, cl_pid, ca->ci_in, fd,
		  ca->header.data, ca->header.cmd_flags);

	/* caller wants to release all resources */

	if (ca->header.cmd_flags & SANLK_REL_ALL) {
		pthread_mutex_lock(&cl->mutex);
		for (j = 0; j < cl->tokens_slots; j++) {
			token = cl->tokens[j];
			if (!token)
				continue;
			rem_tokens[rem_tokens_count++] = token;
			cl->tokens[j] = NULL;
		}
		pthread_mutex_unlock(&cl->mutex);
		goto do_remove;
	}

	if (ca->header.cmd_flags & SANLK_REL_ORPHAN) {
		rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
		if (rv != sizeof(struct sanlk_resource)) {
			log_error("cmd_release %d,%d,%d recv res %d %d",
				  cl_ci, cl_fd, cl_pid, rv, errno);
			result = -ENOTCONN;
			goto do_remove;
		}

		result = release_orphan(&res);
		goto out;
	}

	if (ca->header.cmd_flags & SANLK_REL_RENAME) {
		rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
		if (rv != sizeof(struct sanlk_resource)) {
			log_error("cmd_release %d,%d,%d recv res %d %d",
				  cl_ci, cl_fd, cl_pid, rv, errno);
			result = -ENOTCONN;
			goto do_remove;
		}

		/* second res struct has new name for first res */
		rv = recv(fd, &new, sizeof(struct sanlk_resource), MSG_WAITALL);
		if (rv != sizeof(struct sanlk_resource)) {
			log_error("cmd_release %d,%d,%d recv new %d %d",
				  cl_ci, cl_fd, cl_pid, rv, errno);
			result = -ENOTCONN;
			goto do_remove;
		}

		found = 0;

		pthread_mutex_lock(&cl->mutex);
		for (j = 0; j < cl->tokens_slots; j++) {
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

		resrename = &new;
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
		for (j = 0; j < cl->tokens_slots; j++) {
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
		rv = release_token(task, token, resrename);
		if (rv < 0)
			result = rv;
		free(token);
	}

 out:
	pthread_mutex_lock(&cl->mutex);
	log_cmd(cmd, "cmd_release %d,%d,%d result %d pid_dead %d count %d",
		  cl_ci, cl_fd, cl_pid, result, cl->pid_dead,
		  rem_tokens_count);

	pid_dead = cl->pid_dead;
	cl->cmd_active = 0;

	if (!pid_dead && cl->kill_count) {
		/*
		 * If no tokens are left, clear all cl killing state.  The
		 * cl no longer needs to be killed, and the pid may continue
		 * running, even if a failed lockspace it was using is
		 * released.  When the lockspace is re-added, the tokens
		 * may be re-acquired for this same cl/pid.
		 */

		found = 0;

		for (j = 0; j < cl->tokens_slots; j++) {
			if (!cl->tokens[j])
				continue;
			found = 1;
			break;
		}

		if (!found) {
			cl->kill_count = 0;
			cl->kill_last = 0;
			cl->flags &= ~CL_RUNPATH_SENT;

			log_cmd(cmd, "cmd_release %d,%d,%d clear kill state",
				  cl_ci, cl_fd, cl_pid);
		}
	}
	pthread_mutex_unlock(&cl->mutex);

	if (pid_dead) {
		/* release any tokens not already released above */
		release_cl_tokens(task, cl);
		client_free(cl_ci);
	}

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_inquire(struct task *task, struct cmd_args *ca, uint32_t cmd)
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

	log_cmd(cmd, "cmd_inquire %d,%d,%d ci_in %d fd %d",
		  cl_ci, cl_fd, cl_pid, ca->ci_in, fd);

	pthread_mutex_lock(&cl->mutex);

	if (cl->pid_dead) {
		result = -ESTALE;
		goto done;
	}

	for (i = 0; i < cl->tokens_slots; i++) {
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

	for (i = 0; i < cl->tokens_slots; i++) {
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

	log_cmd(cmd, "cmd_inquire %d,%d,%d result %d pid_dead %d res_count %d cat_count %d strlen %d",
		  cl_ci, cl_fd, cl_pid, result, pid_dead, res_count, cat_count, state_strlen);

	if (pid_dead) {
		release_cl_tokens(task, cl);
		client_free(cl_ci);
	}

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.version = SM_PROTO;
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

/*
 * The behavior may be a little iffy in the case where a pid is killed (due to
 * lockspace failure) while it is doing convert.  If the pid responds by
 * exiting, then this cmd_convert will see pid_dead and release all tokens at
 * the end.  If the pid wants to respond by explicitly releasing its leases,
 * then this convert should fail and return for the same reason the lockspace
 * failed.  Once the convert returns, the pid can respond to the killpath by
 * releasing all the leases.
 *
 * This sets cmd_active, along with acquire/release/inquire, which means
 * that it is serialized along with all cmds that set cmd_active, and
 * cl->tokens will not change while the cmd is active.  This also means
 * it has to handle pid_dead at the end in case the pid exited while the
 * cmd was active and cl->tokens need to be released.
 * (killpath also sets cmd_active so that tokens are not acquired
 * while it's being set.)
 */

static void cmd_convert(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct sanlk_resource res;
	struct token *token;
	struct client *cl;
	int cl_ci = ca->ci_target;
	int cl_fd = ca->cl_fd;
	int cl_pid = ca->cl_pid;
	int pid_dead = 0;
	int result = 0;
	int found = 0;
	int fd, i, rv;

	cl = &client[cl_ci];
	fd = client[ca->ci_in].fd;

	log_cmd(cmd, "cmd_convert %d,%d,%d ci_in %d fd %d",
		  cl_ci, cl_fd, cl_pid, ca->ci_in, fd);

	rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_resource)) {
		result = -ENOTCONN;
		goto reply;
	}

	pthread_mutex_lock(&cl->mutex);
	for (i = 0; i < cl->tokens_slots; i++) {
		token = cl->tokens[i];
		if (!token)
			continue;
		if (memcmp(token->r.lockspace_name, res.lockspace_name, NAME_ID_SIZE))
			continue;
		if (memcmp(token->r.name, res.name, NAME_ID_SIZE))
			continue;
		found = 1;
		break;
	}
	pthread_mutex_unlock(&cl->mutex);

	if (!found) {
		result = -ENOENT;
		goto cmd_done;
	}

	rv = convert_token(task, &res, token, ca->header.cmd_flags);
	if (rv < 0)
		result = rv;

 cmd_done:
	pthread_mutex_lock(&cl->mutex);
	pid_dead = cl->pid_dead;
	cl->cmd_active = 0;
	pthread_mutex_unlock(&cl->mutex);

 reply:
	log_cmd(cmd, "cmd_convert %d,%d,%d result %d pid_dead %d",
		  cl_ci, cl_fd, cl_pid, result, pid_dead);

	if (pid_dead) {
		release_cl_tokens(task, cl);
		client_free(cl_ci);
	}

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_request(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct token *token;
	struct sanlk_resource res;
	struct space_info spi;
	uint64_t owner_id = 0;
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

	log_cmd(cmd, "cmd_request %d,%d force_mode %u %.48s:%.48s:%.256s:%llu",
		  ca->ci_in, fd, force_mode,
		  token->r.lockspace_name,
		  token->r.name,
		  token->disks[0].path,
		  (unsigned long long)token->r.disks[0].offset);

	rv = lockspace_info(token->r.lockspace_name, &spi);
	if (rv < 0 || spi.killing_pids) {
		result = -ENOSPC;
		goto reply_free;
	}

	token->io_timeout = spi.io_timeout;
	token->sector_size = spi.sector_size;
	token->align_size = spi.align_size;

	error = request_token(task, token, force_mode, &owner_id,
			      (ca->header.cmd_flags & SANLK_REQUEST_NEXT_LVER));
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
	log_cmd(cmd, "cmd_request %d,%d done %d", ca->ci_in, fd, result);

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_examine(struct task *task GNUC_UNUSED, struct cmd_args *ca, uint32_t cmd)
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

	log_cmd(cmd, "cmd_examine %d,%d %.48s %.48s",
		  ca->ci_in, fd, space_name, res_name ? res_name : "");

	count = set_resource_examine(space_name, res_name);
	result = 0;
 reply:
	log_cmd(cmd, "cmd_examine %d,%d done %d", ca->ci_in, fd, count);

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_set_lvb(struct task *task GNUC_UNUSED, struct cmd_args *ca, uint32_t cmd)
{
	struct sanlk_resource res;
	char *lvb = NULL;
	int lvblen, rv, fd, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_resource)) {
		log_error("cmd_set_lvb %d,%d recv %d %d", ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	lvblen = ca->header.length - sizeof(struct sm_header) - sizeof(struct sanlk_resource);

	/* 4096 is the max sector size we handle, it is compared
	   against the actual 512/4K sector size in res_set_lvb. */

	if (lvblen > 4096) {
		log_error("cmd_set_lvb %d,%d lvblen %d too big", ca->ci_in, fd, lvblen);
		result = -E2BIG;
		goto reply;
	}

	lvb = malloc(lvblen);
	if (!lvb) {
		result = -ENOMEM;
		goto reply;
	}

	rv = recv(fd, lvb, lvblen, MSG_WAITALL);
	if (rv != lvblen) {
		log_error("cmd_set_lvb %d,%d recv lvblen %d lvb %d %d",
			  ca->ci_in, fd, lvblen, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	result = res_set_lvb(&res, lvb, lvblen);

	log_cmd(cmd, "cmd_set_lvb ci %d fd %d result %d res %s:%s",
		  ca->ci_in, fd, result, res.lockspace_name, res.name);
 reply:
	if (lvb)
		free(lvb);

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_get_lvb(struct task *task GNUC_UNUSED, struct cmd_args *ca, uint32_t cmd)
{
	struct sm_header h;
	struct sanlk_resource res;
	char *lvb = NULL;
	int lvblen = 0, rv, fd, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_resource)) {
		log_error("cmd_get_lvb %d,%d recv %d %d", ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	/* if 0 then we use the sector size as lvb len */
	lvblen = ca->header.data2;

	result = res_get_lvb(&res, &lvb, &lvblen);

	log_cmd(cmd, "cmd_get_lvb ci %d fd %d result %d res %s:%s",
		  ca->ci_in, fd, result, res.lockspace_name, res.name);
 reply:
	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.data = result;
	h.data2 = 0;
	h.length = sizeof(h) + lvblen;

	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	if (lvb) {
		send(fd, lvb, lvblen, MSG_NOSIGNAL);
		free(lvb);
	}

	client_resume(ca->ci_in);
}

static int shutdown_reply_ci = -1;
static int shutdown_reply_fd = -1;

static int daemon_shutdown_start(int ci, int fd, int force)
{
	int rv;

	if (force) {
		shutdown_reply_ci = ci;
		shutdown_reply_fd = fd;
		external_shutdown = 2;
		return 0;
	}

	pthread_mutex_lock(&spaces_mutex);
	if (list_empty(&spaces) &&
	    list_empty(&spaces_rem) &&
	    list_empty(&spaces_add)) {
		shutdown_reply_ci = ci;
		shutdown_reply_fd = fd;
		external_shutdown = 1;
		rv = 0;
	} else {
		rv = -EBUSY;
	}
	pthread_mutex_unlock(&spaces_mutex);

	return rv;
}

static void cmd_shutdown_wait(struct task *task GNUC_UNUSED, struct cmd_args *ca, uint32_t cmd)
{
	int fd, result;

	fd = client[ca->ci_in].fd;

	result = daemon_shutdown_start(ca->ci_in, fd, ca->header.data);

	/*
	 * daemon_shutdown_reply will send the result at the
	 * end of main_loop.
	 */
	if (!result)
		return;

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

void daemon_shutdown_reply(void)
{
	struct sm_header h;

	/* shutdown wait was not used */
	if (shutdown_reply_fd == -1)
		return;

	memset(&h, 0, sizeof(h));
	h.magic = SM_MAGIC;
	h.version = SM_PROTO;
	h.length = sizeof(h);

	send(shutdown_reply_fd, &h, sizeof(h), MSG_NOSIGNAL);
	close(shutdown_reply_fd);

	client_resume(shutdown_reply_ci);
}

static void cmd_add_lockspace(struct cmd_args *ca, uint32_t cmd)
{
	struct sanlk_lockspace lockspace;
	struct space *sp;
	uint32_t io_timeout;
	int async = ca->header.cmd_flags & SANLK_ADD_ASYNC;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_add_lockspace %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_cmd(cmd, "cmd_add_lockspace %d,%d %.48s:%llu:%s:%llu flags %x timeout %u",
		  ca->ci_in, fd, lockspace.name,
		  (unsigned long long)lockspace.host_id,
		  lockspace.host_id_disk.path,
		  (unsigned long long)lockspace.host_id_disk.offset,
		  ca->header.cmd_flags, ca->header.data);

	io_timeout = ca->header.data;
	if (!io_timeout)
		io_timeout = DEFAULT_IO_TIMEOUT;

	rv = add_lockspace_start(&lockspace, io_timeout, &sp);
	if (rv < 0) {
		result = rv;
		goto reply;
	}

	if (async) {
		result = rv;
		log_cmd(cmd, "cmd_add_lockspace %d,%d async done %d", ca->ci_in, fd, result);
		send_result(ca->ci_in, fd, &ca->header, result);
		client_resume(ca->ci_in);
		add_lockspace_wait(sp);
		return;
	}

	result = add_lockspace_wait(sp);
 reply:
	log_cmd(cmd, "cmd_add_lockspace %d,%d done %d", ca->ci_in, fd, result);
	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_inq_lockspace(struct cmd_args *ca, uint32_t cmd)
{
	struct sanlk_lockspace lockspace;
	int waitrs = ca->header.cmd_flags & SANLK_INQ_WAIT;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_inq_lockspace %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_cmd(cmd, "cmd_inq_lockspace %d,%d %.48s:%llu:%s:%llu flags %x",
		  ca->ci_in, fd, lockspace.name,
		  (unsigned long long)lockspace.host_id,
		  lockspace.host_id_disk.path,
		  (unsigned long long)lockspace.host_id_disk.offset,
		  ca->header.cmd_flags);

	while (1) {
		result = inq_lockspace(&lockspace);
		if ((result != -EINPROGRESS) || !(waitrs)) {
			break;
		}
		sleep(1);
	}

 reply:
	log_cmd(cmd, "cmd_inq_lockspace %d,%d done %d", ca->ci_in, fd, result);

	send_result(ca->ci_in, fd, &ca->header, result);
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
 * 	deactivate_watchdog(sp);
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

static void cmd_rem_lockspace(struct cmd_args *ca, uint32_t cmd)
{
	struct sanlk_lockspace lockspace;
	int async = ca->header.cmd_flags & SANLK_REM_ASYNC;
	int fd, rv, result;
	unsigned int space_id;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_rem_lockspace %d,%d recv %d %d",
			  ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_cmd(cmd, "cmd_rem_lockspace %d,%d %.48s flags %x",
		  ca->ci_in, fd, lockspace.name, ca->header.cmd_flags);

	if (ca->header.cmd_flags & SANLK_REM_UNUSED) {
		if (lockspace_is_used(&lockspace)) {
			result = -EBUSY;
			goto reply;
		}
	}

	rv = rem_lockspace_start(&lockspace, &space_id);
	if (rv < 0) {
		result = rv;
		goto reply;
	}

	if (async) {
		result = rv;
		log_cmd(cmd, "cmd_rem_lockspace %d,%d async done %d", ca->ci_in, fd, result);
		send_result(ca->ci_in, fd, &ca->header, result);
		client_resume(ca->ci_in);
		rem_lockspace_wait(&lockspace, space_id);
		return;
	}

	result = rem_lockspace_wait(&lockspace, space_id);
 reply:
	log_cmd(cmd, "cmd_rem_lockspace %d,%d done %d", ca->ci_in, fd, result);
	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_align(struct task *task GNUC_UNUSED, struct cmd_args *ca, uint32_t cmd)
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

	log_cmd(cmd, "cmd_align %d,%d", ca->ci_in, fd);

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
	log_cmd(cmd, "cmd_align %d,%d done %d", ca->ci_in, fd, result);

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_read_lockspace(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct sm_header h;
	struct sanlk_lockspace lockspace;
	struct sync_disk sd;
	uint64_t host_id;
	int sector_size = 0;
	int align_size = 0;
	int io_timeout = 0;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_read_lockspace %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	if (!lockspace.host_id)
		host_id = 1;
	else
		host_id = lockspace.host_id;

	log_cmd(cmd, "cmd_read_lockspace %d,%d %llu %s:%llu",
		  ca->ci_in, fd,
		  (unsigned long long)host_id,
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

	sector_size = sanlk_lsf_sector_flag_to_size(lockspace.flags);
	align_size = sanlk_lsf_align_flag_to_size(lockspace.flags);

	if (!sector_size) {
		/* reads the first leader record to get sector size */
		result = delta_read_lockspace_sizes(task, &sd, DEFAULT_IO_TIMEOUT, &sector_size, &align_size);
		if (result < 0)
			goto out_close;
		if ((sector_size != 512) && (sector_size != 4096)) {
			result = -EINVAL;
			goto out_close;
		}
	}

	/* sets ls->name and io_timeout */
	result = delta_read_lockspace(task, &sd, sector_size, align_size, host_id, &lockspace,
				      DEFAULT_IO_TIMEOUT, &io_timeout);
	if (result == SANLK_OK)
		result = 0;

 out_close:
	close_disks(&sd, 1);
 reply:
	log_cmd(cmd, "cmd_read_lockspace %d,%d done %d", ca->ci_in, fd, result);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.data = result;
	h.data2 = io_timeout;
	h.length = sizeof(h) + sizeof(lockspace);
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);
	send(fd, &lockspace, sizeof(lockspace), MSG_NOSIGNAL);
	client_resume(ca->ci_in);
}

static void cmd_read_resource(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct sm_header h;
	struct sanlk_resource res;
	struct token *token = NULL;
	int token_len, disks_len;
	int j, fd, rv, result;

	fd = client[ca->ci_in].fd;

	/* receiving and setting up token copied from cmd_acquire */

	rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_resource)) {
		log_error("cmd_read_resource %d,%d recv %d %d",
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

	log_cmd(cmd, "cmd_read_resource %d,%d %.256s:%llu",
		  ca->ci_in, fd,
		  token->disks[0].path,
		  (unsigned long long)token->r.disks[0].offset);

	rv = open_disks(token->disks, token->r.num_disks);
	if (rv < 0) {
		result = rv;
		goto reply;
	}

	token->io_timeout = DEFAULT_IO_TIMEOUT;

	/*
	 * These may be zero, in which case paxos_read_resource reads a 4K sector
	 * and gets the values from the leader record.
	 */
	token->sector_size = sanlk_res_sector_flag_to_size(res.flags);
	token->align_size = sanlk_res_align_flag_to_size(res.flags);

	/* sets res.lockspace_name, res.name, res.lver, res.flags */
	result = paxos_read_resource(task, token, &res);
	if (result == SANLK_OK)
		result = 0;

	close_disks(token->disks, token->r.num_disks);
 reply:
	if (token)
		free(token);
	log_cmd(cmd, "cmd_read_resource %d,%d done %d", ca->ci_in, fd, result);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.data = result;
	h.data2 = 0;
	h.length = sizeof(h) + sizeof(res);
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);
	send(fd, &res, sizeof(res), MSG_NOSIGNAL);
	client_resume(ca->ci_in);
}

static void cmd_read_resource_owners(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct sm_header h;
	struct sanlk_resource res;
	struct token *token = NULL;
	char *send_buf;
	int token_len, disks_len, send_len = 0;
	int j, fd, rv, result, count = 0;

	fd = client[ca->ci_in].fd;

	/* receiving and setting up token copied from cmd_acquire */

	rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_resource)) {
		log_error("cmd_read_resource_owners %d,%d recv %d %d",
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

	log_cmd(cmd, "cmd_read_resource_owners %d,%d %.256s:%llu",
		  ca->ci_in, fd,
		  token->disks[0].path,
		  (unsigned long long)token->r.disks[0].offset);

	rv = open_disks(token->disks, token->r.num_disks);
	if (rv < 0) {
		result = rv;
		goto reply;
	}

	token->io_timeout = DEFAULT_IO_TIMEOUT;

	/*
	 * These may be zero, in which case paxos_read_resource reads a 4K sector
	 * and gets the values from the leader record.
	 */
	token->sector_size = sanlk_res_sector_flag_to_size(res.flags);
	token->align_size = sanlk_res_align_flag_to_size(res.flags);

	send_buf = NULL;
	send_len = 0;

	result = read_resource_owners(task, token, &res, &send_buf, &send_len, &count);
	if (result == SANLK_OK)
		result = 0;

	close_disks(token->disks, token->r.num_disks);
 reply:
	if (token)
		free(token);
	log_cmd(cmd, "cmd_read_resource_owners %d,%d count %d done %d", ca->ci_in, fd, count, result);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.data = result;
	h.data2 = count;
	h.length = sizeof(h) + sizeof(res) + send_len;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);
	send(fd, &res, sizeof(res), MSG_NOSIGNAL);
	if (send_len && send_buf) {
		send(fd, send_buf, send_len, MSG_NOSIGNAL);
		free(send_buf);
	}

	client_resume(ca->ci_in);
}

static void cmd_write_lockspace(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct sanlk_lockspace lockspace;
	struct sync_disk sd;
	int fd, rv, result;
	int io_timeout = DEFAULT_IO_TIMEOUT;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_write_lockspace %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_cmd(cmd, "cmd_write_lockspace %d,%d %.48s:%llu:%s:%llu 0x%x",
		  ca->ci_in, fd, lockspace.name,
		  (unsigned long long)lockspace.host_id,
		  lockspace.host_id_disk.path,
		  (unsigned long long)lockspace.host_id_disk.offset,
		  lockspace.flags);

	if (!lockspace.host_id_disk.path[0]) {
		result = -ENODEV;
		goto reply;
	}

	/* No longer used, max_hosts is derived from sector/align sizes. */
	/* max_hosts = ca->header.data; */

	memset(&sd, 0, sizeof(struct sync_disk));
	memcpy(&sd, &lockspace.host_id_disk, sizeof(struct sanlk_disk));
	sd.fd = -1;

	rv = open_disk(&sd);
	if (rv < 0) {
		result = -ENODEV;
		goto reply;
	}

	if (ca->header.data2)
		io_timeout = ca->header.data2;

	result = delta_lease_init(task, &lockspace, io_timeout, &sd);

	close_disks(&sd, 1);
 reply:
	log_cmd(cmd, "cmd_write_lockspace %d,%d done %d", ca->ci_in, fd, result);

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_write_resource(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct token *token = NULL;
	struct sanlk_resource res;
	int token_len, disks_len;
	int num_hosts;
	int write_clear = 0;
	int j, fd, rv, result;

	fd = client[ca->ci_in].fd;

	/* receiving and setting up token copied from cmd_acquire */

	rv = recv(fd, &res, sizeof(struct sanlk_resource), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_resource)) {
		log_error("cmd_write_resource %d,%d recv %d %d",
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
	token->r.flags = res.flags;

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

	log_cmd(cmd, "cmd_write_resource %d,%d %.48s:%.48s:%.256s:%llu 0x%x",
		  ca->ci_in, fd,
		  token->r.lockspace_name,
		  token->r.name,
		  token->disks[0].path,
		  (unsigned long long)token->r.disks[0].offset,
		  res.flags);

	num_hosts = ca->header.data;

	/* No longer used, max_hosts is derived from sector/align sizes. */
	/* max_hosts = ca->header.data2; */

	if (ca->header.cmd_flags & SANLK_WRITE_CLEAR)
		write_clear = 1;

	rv = open_disks(token->disks, token->r.num_disks);
	if (rv < 0) {
		result = rv;
		goto reply;
	}

	token->io_timeout = DEFAULT_IO_TIMEOUT;

	result = paxos_lease_init(task, token, num_hosts, write_clear);

	close_disks(token->disks, token->r.num_disks);
 reply:
	if (token)
		free(token);

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

/* N.B. the api doesn't support one client setting killpath for another
   pid/client */

static void cmd_killpath(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct client *cl;
	int cl_ci = ca->ci_target;
	int cl_fd = ca->cl_fd;
	int cl_pid = ca->cl_pid;
	int rv, result, pid_dead;

	cl = &client[cl_ci];

	log_cmd(cmd, "cmd_killpath %d,%d,%d flags %x",
		  cl_ci, cl_fd, cl_pid, ca->header.cmd_flags);

	rv = recv(cl_fd, cl->killpath, SANLK_HELPER_PATH_LEN, MSG_WAITALL);
	if (rv != SANLK_HELPER_PATH_LEN) {
		log_error("cmd_killpath %d,%d,%d recv path %d %d",
			  cl_ci, cl_fd, cl_pid, rv, errno);
		memset(cl->killpath, 0, SANLK_HELPER_PATH_LEN);
		memset(cl->killargs, 0, SANLK_HELPER_ARGS_LEN);
		result = -ENOTCONN;
		goto done;
	}

	rv = recv(cl_fd, cl->killargs, SANLK_HELPER_ARGS_LEN, MSG_WAITALL);
	if (rv != SANLK_HELPER_ARGS_LEN) {
		log_error("cmd_killpath %d,%d,%d recv args %d %d",
			  cl_ci, cl_fd, cl_pid, rv, errno);
		memset(cl->killpath, 0, SANLK_HELPER_PATH_LEN);
		memset(cl->killargs, 0, SANLK_HELPER_ARGS_LEN);
		result = -ENOTCONN;
		goto done;
	}

	cl->killpath[SANLK_HELPER_PATH_LEN - 1] = '\0';
	cl->killargs[SANLK_HELPER_ARGS_LEN - 1] = '\0';

	if (ca->header.cmd_flags & SANLK_KILLPATH_PID)
		cl->flags |= CL_KILLPATH_PID;

	result = 0;
 done:
	pthread_mutex_lock(&cl->mutex);
	pid_dead = cl->pid_dead;
	cl->cmd_active = 0;
	pthread_mutex_unlock(&cl->mutex);

	if (pid_dead) {
		/* release tokens in case a client sets/changes its killpath
		   after it has acquired leases */
		release_cl_tokens(task, cl);
		client_free(cl_ci);
		return;
	}

	send_result(ca->ci_in, cl_fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_set_event(struct task *task GNUC_UNUSED, struct cmd_args *ca, uint32_t cmd)
{
	struct sanlk_lockspace lockspace;
	struct sanlk_host_event he;
	int rv, fd, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
	        result = -ENOTCONN;
	        goto reply;
	}

	rv = recv(fd, &he, sizeof(struct sanlk_host_event), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_host_event)) {
	        result = -ENOTCONN;
	        goto reply;
	}

	log_cmd(cmd, "cmd_set_event %.48s", lockspace.name);

	result = lockspace_set_event(&lockspace, &he, ca->header.cmd_flags);

	log_cmd(cmd, "cmd_set_event result %d", result);
reply:
	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_format_rindex(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct sanlk_rindex ri;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &ri, sizeof(struct sanlk_rindex), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_rindex)) {
		log_error("cmd_format_rindex %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_cmd(cmd, "cmd_format_rindex %d,%d %.48s %s:%llu",
		  ca->ci_in, fd, ri.lockspace_name,
		  ri.disk.path,
		  (unsigned long long)ri.disk.offset);

	result = rindex_format(task, &ri);
 reply:
	log_cmd(cmd, "cmd_format_rindex %d,%d done %d", ca->ci_in, fd, result);

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void cmd_rebuild_rindex(struct task *task, struct cmd_args *ca, uint32_t cmd)
{
	struct sanlk_rindex ri;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &ri, sizeof(struct sanlk_rindex), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_rindex)) {
		log_error("cmd_rebuild_rindex %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_cmd(cmd, "cmd_rebuild_rindex %d,%d %.48s %s:%llu",
		  ca->ci_in, fd, ri.lockspace_name,
		  ri.disk.path,
		  (unsigned long long)ri.disk.offset);

	result = rindex_rebuild(task, &ri, ca->header.cmd_flags);
 reply:
	log_cmd(cmd, "cmd_rebuild_rindex %d,%d done %d", ca->ci_in, fd, result);

	send_result(ca->ci_in, fd, &ca->header, result);
	client_resume(ca->ci_in);
}

static void rindex_op(struct task *task, struct cmd_args *ca, const char *ri_cmd_str, int op, uint32_t cmd)
{
	struct sanlk_rindex ri;
	struct sanlk_rentry re;
	struct sanlk_rentry re_ret;
	struct sm_header h;
	int fd, rv, result;

	memset(&re_ret, 0, sizeof(re_ret));

	fd = client[ca->ci_in].fd;

	rv = recv(fd, &ri, sizeof(struct sanlk_rindex), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_rindex)) {
		log_error("%s %d,%d recv %d %d", ri_cmd_str, ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	rv = recv(fd, &re, sizeof(struct sanlk_rentry), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_rentry)) {
		log_error("%s %d,%d recv %d %d", ri_cmd_str, ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	log_cmd(cmd, "%s %d,%d %.48s %s:%llu", ri_cmd_str,
		  ca->ci_in, fd, ri.lockspace_name,
		  ri.disk.path,
		  (unsigned long long)ri.disk.offset);

	if (op == RX_OP_LOOKUP)
		result = rindex_lookup(task, &ri, &re, &re_ret, ca->header.cmd_flags);
	else if (op == RX_OP_UPDATE)
		result = rindex_update(task, &ri, &re, &re_ret, ca->header.cmd_flags);
	else if (op == RX_OP_CREATE)
		result = rindex_create(task, &ri, &re, &re_ret, ca->header.data, ca->header.data2);
	else if (op == RX_OP_DELETE)
		result = rindex_delete(task, &ri, &re, &re_ret);
	else
		result = -EINVAL;

 reply:
	log_cmd(cmd, "%s %d,%d done %d", ri_cmd_str, ca->ci_in, fd, result);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.data = result;
	h.data2 = 0;
	h.length = sizeof(h) + sizeof(re_ret);
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);
	send(fd, &re_ret, sizeof(re), MSG_NOSIGNAL);

	client_resume(ca->ci_in);
}

void call_cmd_thread(struct task *task, struct cmd_args *ca)
{
	uint32_t cmd = ca->header.cmd;

	switch (cmd) {
	case SM_CMD_ACQUIRE:
		cmd_acquire(task, ca, cmd);
		break;
	case SM_CMD_RELEASE:
		cmd_release(task, ca, cmd);
		break;
	case SM_CMD_INQUIRE:
		cmd_inquire(task, ca, cmd);
		break;
	case SM_CMD_CONVERT:
		cmd_convert(task, ca, cmd);
		break;
	case SM_CMD_REQUEST:
		cmd_request(task, ca, cmd);
		break;
	case SM_CMD_ADD_LOCKSPACE:
		strcpy(client[ca->ci_in].owner_name, "add_lockspace");
		cmd_add_lockspace(ca, cmd);
		break;
	case SM_CMD_INQ_LOCKSPACE:
		strcpy(client[ca->ci_in].owner_name, "inq_lockspace");
		cmd_inq_lockspace(ca, cmd);
		break;
	case SM_CMD_REM_LOCKSPACE:
		strcpy(client[ca->ci_in].owner_name, "rem_lockspace");
		cmd_rem_lockspace(ca, cmd);
		break;
	case SM_CMD_ALIGN:
		cmd_align(task, ca, cmd);
		break;
	case SM_CMD_WRITE_LOCKSPACE:
		cmd_write_lockspace(task, ca, cmd);
		break;
	case SM_CMD_WRITE_RESOURCE:
		cmd_write_resource(task, ca, cmd);
		break;
	case SM_CMD_READ_LOCKSPACE:
		cmd_read_lockspace(task, ca, cmd);
		break;
	case SM_CMD_READ_RESOURCE:
		cmd_read_resource(task, ca, cmd);
		break;
	case SM_CMD_READ_RESOURCE_OWNERS:
		cmd_read_resource_owners(task, ca, cmd);
		break;
	case SM_CMD_EXAMINE_LOCKSPACE:
	case SM_CMD_EXAMINE_RESOURCE:
		cmd_examine(task, ca, cmd);
		break;
	case SM_CMD_KILLPATH:
		cmd_killpath(task, ca, cmd);
		break;
	case SM_CMD_SET_LVB:
		cmd_set_lvb(task, ca, cmd);
		break;
	case SM_CMD_GET_LVB:
		cmd_get_lvb(task, ca, cmd);
		break;
	case SM_CMD_SHUTDOWN_WAIT:
		cmd_shutdown_wait(task, ca, cmd);
		break;
	case SM_CMD_SET_EVENT:
		cmd_set_event(task, ca, cmd);
		break;
	case SM_CMD_FORMAT_RINDEX:
		cmd_format_rindex(task, ca, cmd);
		break;
	case SM_CMD_REBUILD_RINDEX:
		cmd_rebuild_rindex(task, ca, cmd);
		break;
	case SM_CMD_UPDATE_RINDEX:
		rindex_op(task, ca, "cmd_update_rindex", RX_OP_UPDATE, cmd);
		break;
	case SM_CMD_LOOKUP_RINDEX:
		rindex_op(task, ca, "cmd_lookup_rindex", RX_OP_LOOKUP, cmd);
		break;
	case SM_CMD_CREATE_RESOURCE:
		rindex_op(task, ca, "cmd_create_resource", RX_OP_CREATE, cmd);
		break;
	case SM_CMD_DELETE_RESOURCE:
		rindex_op(task, ca, "cmd_delete_resource", RX_OP_DELETE, cmd);
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
		 "use_watchdog=%d "
		 "high_priority=%d "
		 "mlock_level=%d "
		 "quiet_fail=%d "
		 "debug_renew=%d "
		 "debug_clients=%d "
		 "debug_cmds=0x%llx "
		 "renewal_history_size=%d "
		 "gid=%d "
		 "uid=%d "
		 "sh_retries=%d "
		 "max_sectors_kb_ignore=%d "
		 "max_sectors_kb_align=%d "
		 "max_sectors_kb_num=%d "
		 "max_worker_threads=%d "
		 "write_init_io_timeout=%u "
		 "use_aio=%d "
		 "kill_grace_seconds=%d "
		 "helper_pid=%d "
		 "helper_kill_fd=%d "
		 "helper_full_count=%u "
		 "helper_last_status=%llu "
		 "monotime=%llu "
		 "version_str=%s "
		 "version_num=%u.%u.%u "
		 "version_hex=%08x "
		 "smproto_hex=%08x",
		 our_host_name_global,
		 com.use_watchdog,
		 com.high_priority,
		 com.mlock_level,
		 com.quiet_fail,
		 com.debug_renew,
		 com.debug_clients,
		 (unsigned long long)com.debug_cmds,
		 com.renewal_history_size,
		 com.gid,
		 com.uid,
		 com.sh_retries,
		 com.max_sectors_kb_ignore,
		 com.max_sectors_kb_align,
		 com.max_sectors_kb_num,
		 com.max_worker_threads,
		 com.write_init_io_timeout,
		 main_task.use_aio,
		 kill_grace_seconds,
		 helper_pid,
		 helper_kill_fd,
		 helper_full_count,
		 (unsigned long long)helper_last_status,
		 (unsigned long long)monotime(),
		 VERSION,
		 sanlock_version_major,
		 sanlock_version_minor,
		 sanlock_version_patch,
		 sanlock_version_combined,
		 SM_PROTO);

	return strlen(str) + 1;
}

static int print_state_client(struct client *cl, int ci, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "ci=%d "
		 "fd=%d "
		 "pid=%d "
		 "flags=%x "
		 "restricted=%x "
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
		 cl->flags,
		 cl->restricted,
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
		 "io_timeout=%d "
		 "sector_size=%d "
		 "align_size=%d "
		 "host_generation=%llu "
		 "renew_fail=%d "
		 "space_dead=%d "
		 "killing_pids=%d "
		 "used_retries=%u "
		 "external_used=%d "
		 "used_by_orphans=%d "
		 "renewal_read_extend_sec=%u "
		 "corrupt_result=%d "
		 "acquire_last_result=%d "
		 "renewal_last_result=%d "
		 "acquire_last_attempt=%llu "
		 "acquire_last_success=%llu "
		 "renewal_last_attempt=%llu "
		 "renewal_last_success=%llu",
		 list_name,
		 sp->space_id,
		 sp->io_timeout,
		 sp->sector_size,
		 sp->align_size,
		 (unsigned long long)sp->host_generation,
		 sp->renew_fail,
		 sp->space_dead,
		 sp->killing_pids,
		 sp->used_retries,
		 (sp->flags & SP_EXTERNAL_USED) ? 1 : 0,
		 (sp->flags & SP_USED_BY_ORPHANS) ? 1 : 0,
		 sp->renewal_read_extend_sec,
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
		 "sector_size=%d "
		 "align_size=%d "
		 "lver=%llu "
		 "reused=%u "
		 "res_id=%u "
		 "token_id=%u",
		 list_name,
		 r->flags,
		 r->sector_size,
		 r->align_size,
		 (unsigned long long)r->leader.lver,
		 r->reused,
		 r->res_id,
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
		 "timestamp=%llu "
		 "io_timeout=%u "
		 "owner_name=%.48s",
		 (unsigned long long)hs->last_check,
		 (unsigned long long)hs->last_live,
		 (unsigned long long)hs->last_req,
		 (unsigned long long)hs->owner_id,
		 (unsigned long long)hs->owner_generation,
		 (unsigned long long)hs->timestamp,
		 hs->io_timeout,
		 hs->owner_name);

	return strlen(str) + 1;
}

static int print_state_renewal(struct renewal_history *hi, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "timestamp=%llu "
		 "read_ms=%d "
		 "write_ms=%d "
		 "next_timeouts=%d "
		 "next_errors=%d",
		 (unsigned long long)hi->timestamp,
		 hi->read_ms,
		 hi->write_ms,
		 hi->next_timeouts,
		 hi->next_errors);

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

static void send_state_renewal(int fd, struct renewal_history *hi)
{
	struct sanlk_state st;
	char str[SANLK_STATE_MAXSTR];
	int str_len;

	memset(&st, 0, sizeof(st));

	st.type = SANLK_STATE_RENEWAL;
	st.data64 = hi->timestamp;

	str_len = print_state_renewal(hi, str);

	st.str_len = str_len;

	send(fd, &st, sizeof(st), MSG_NOSIGNAL);
	if (str_len)
		send(fd, str, str_len, MSG_NOSIGNAL);
}

static void cmd_status(int ci, int fd, struct sm_header *h_recv, int client_maxi, uint32_t cmd)
{
	struct sm_header h;
	struct client *cl;
	struct space *sp;
	int ci_iter;

	log_cmd(cmd, "cmd_status %d,%d", ci, fd);

	memset(&h, 0, sizeof(h));
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.length = sizeof(h);
	h.data = 0;

	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	send_state_daemon(fd);

	if (h_recv->data == SANLK_STATE_DAEMON)
		return;

	for (ci_iter = 0; ci_iter <= client_maxi; ci_iter++) {
		cl = &client[ci_iter];
		if (!cl->used)
			continue;
		send_state_client(fd, cl, ci_iter);
	}

	if (h_recv->data == SANLK_STATE_CLIENT)
		return;

	/* N.B. the reporting function looks for the
	   strings "add" and "rem", so if changed,
	   the strings should be changed in both places. */

	pthread_mutex_lock(&spaces_mutex);
	list_for_each_entry(sp, &spaces, list)
		send_state_lockspace(fd, sp, "spaces");
	list_for_each_entry(sp, &spaces_add, list)
		send_state_lockspace(fd, sp, "add");
	list_for_each_entry(sp, &spaces_rem, list)
		send_state_lockspace(fd, sp, "rem");
	pthread_mutex_unlock(&spaces_mutex);

	if (h_recv->data == SANLK_STATE_LOCKSPACE)
		return;

	/* resource.c will iterate through private lists and call
	   back here for each r */

	send_state_resources(fd);
}

static void cmd_host_status(int ci, int fd, struct sm_header *h_recv, uint32_t cmd)
{
	struct sm_header h;
	struct sanlk_lockspace lockspace;
	struct space *sp;
	struct host_status *hs, *status = NULL;
	int status_len;
	int i, rv;

	log_cmd(cmd, "cmd_host_status %d,%d", ci, fd);

	memset(&h, 0, sizeof(h));
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.version = SM_PROTO;
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

static void cmd_renewal(int fd, struct sm_header *h_recv)
{
	struct sm_header h;
	struct sanlk_lockspace lockspace;
	struct space *sp;
	uint32_t io_timeout = 0;
	struct renewal_history *history = NULL;
	struct renewal_history *hi;
	int history_size, history_prev, history_next;
	int i, rv, len;

	memset(&h, 0, sizeof(h));
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.length = sizeof(h);
	h.data = 0;

	if (!com.renewal_history_size)
		goto fail;

	len = sizeof(struct renewal_history) * com.renewal_history_size;

	history = malloc(len);
	if (!history) {
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
	if (sp) {
		history_size = sp->renewal_history_size;
		history_prev = sp->renewal_history_prev;
		history_next = sp->renewal_history_next;
		io_timeout = sp->io_timeout;

		if (history_size != com.renewal_history_size) {
			log_error("mismatch history size");
			history_size = 0;
			history_prev = 0;
			history_next = 0;
		} else {
			memcpy(history, sp->renewal_history, len);
		}
	}
	pthread_mutex_unlock(&spaces_mutex);

	if (!sp) {
		h.data = -ENOSPC;
		goto fail;
	}

	if (!history_size || (!history_prev && !history_next))
		goto fail;

	h.data2 = io_timeout;

	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	/* If next slot is non-zero, then we've wrapped and
	   should begin sending history from next to end
	   before sending from 0 to prev. */

	if (history[history_next].timestamp) {
		for (i = history_next; i < history_size; i++) {
			hi = &history[i];
			send_state_renewal(fd, hi);
		}
	
	}
	for (i = 0; i < history_next; i++) {
		hi = &history[i];
		send_state_renewal(fd, hi);
	}

	if (history)
		free(history);
	return;
 fail:
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	if (history)
		free(history);
}

static char send_data_buf[LOG_DUMP_SIZE];

static void cmd_log_dump(int fd, struct sm_header *h_recv)
{
	int len;

	copy_log_dump(send_data_buf, &len);

	h_recv->version = SM_PROTO;
	h_recv->data = len;

	send(fd, h_recv, sizeof(struct sm_header), MSG_NOSIGNAL);
	send(fd, send_data_buf, len, MSG_NOSIGNAL);
}

static void cmd_get_lockspaces(int ci, int fd, struct sm_header *h_recv, uint32_t cmd)
{
	int count, len, rv;

	log_cmd(cmd, "cmd_get_lockspaces %d,%d", ci, fd);

	rv = get_lockspaces(send_data_buf, &len, &count, LOG_DUMP_SIZE);

	h_recv->version = SM_PROTO;
	h_recv->length = sizeof(struct sm_header) + len;
	h_recv->data = rv;
	h_recv->data2 = count;

	send(fd, h_recv, sizeof(struct sm_header), MSG_NOSIGNAL);
	send(fd, send_data_buf, len, MSG_NOSIGNAL);
}

static void cmd_get_hosts(int ci, int fd, struct sm_header *h_recv, uint32_t cmd)
{
	struct sm_header h;
	struct sanlk_lockspace lockspace;
	int count = 0, len = 0, rv;

	log_cmd(cmd, "cmd_get_hosts %d,%d", ci, fd);

	memset(&h, 0, sizeof(h));
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.length = sizeof(h);
	h.data = 0;

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		h.data = -ENOTCONN;
		goto out;
	}

	rv = get_hosts(&lockspace, send_data_buf, &len, &count, LOG_DUMP_SIZE);

	h.length = sizeof(struct sm_header) + len;
	h.data = rv;
	h.data2 = count;
out:
	send(fd, &h, sizeof(struct sm_header), MSG_NOSIGNAL);
	if (len)
		send(fd, send_data_buf, len, MSG_NOSIGNAL);
}

static void cmd_restrict(int ci, int fd, struct sm_header *h_recv, uint32_t cmd)
{
	log_cmd(cmd, "cmd_restrict ci %d fd %d pid %d flags %x",
		  ci, fd, client[ci].pid, h_recv->cmd_flags);

	client[ci].restricted = h_recv->cmd_flags;

	h_recv->version = SM_PROTO;
	send_result(ci, fd, h_recv, 0);
}

static void cmd_version(int ci GNUC_UNUSED, int fd, struct sm_header *h_recv)
{
	h_recv->magic = SM_MAGIC;
	h_recv->version = SM_PROTO;
	h_recv->cmd = SM_CMD_VERSION;
	h_recv->cmd_flags = 0;
	h_recv->length = sizeof(struct sm_header);
	h_recv->seq = 0;
	h_recv->data = 0;
	h_recv->data2 = sanlock_version_combined;

	send(fd, h_recv, sizeof(struct sm_header), MSG_NOSIGNAL);
}

static void cmd_reg_event(int fd, struct sm_header *h_recv, uint32_t cmd)
{
	struct sm_header h;
	struct sanlk_lockspace lockspace;
	struct sanlk_host_event he;
	int rv;

	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.length = sizeof(struct sm_header);

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		h.data = -ENOTCONN;
		goto out;
	}

	/* currently unused */
	rv = recv(fd, &he, sizeof(he), MSG_WAITALL);
	if (rv != sizeof(he)) {
		h.data = -ENOTCONN;
		goto out;
	}

	rv = lockspace_reg_event(&lockspace, fd, h_recv->cmd_flags);

	h.data = rv;
out:
	log_cmd(cmd, "cmd_reg_event fd %d rv %d", fd, rv);
	send(fd, &h, sizeof(struct sm_header), MSG_NOSIGNAL);
}

static void cmd_end_event(int fd, struct sm_header *h_recv, uint32_t cmd)
{
	struct sm_header h;
	struct sanlk_lockspace lockspace;
	int rv;

	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.length = sizeof(struct sm_header);

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		h.data = -ENOTCONN;
		goto out;
	}

	rv = lockspace_end_event(&lockspace);

	h.data = rv;
out:
	log_cmd(cmd, "cmd_end_event fd %d rv %d", fd, rv);
	send(fd, &h, sizeof(struct sm_header), MSG_NOSIGNAL);
}

static void cmd_set_config(int fd, struct sm_header *h_recv, uint32_t cmd)
{
	struct sm_header h;
	struct sanlk_lockspace lockspace;
	int rv;

	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.length = sizeof(struct sm_header);

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		h.data = -ENOTCONN;
		goto out;
	}

	rv = lockspace_set_config(&lockspace, h_recv->cmd_flags, h_recv->data);

	h.data = rv;
out:
	log_cmd(cmd, "cmd_set_config fd %d rv %d", fd, rv);
	send(fd, &h, sizeof(struct sm_header), MSG_NOSIGNAL);
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
	uint32_t cmd = h_recv->cmd;

	switch (cmd) {
	case SM_CMD_REGISTER:
		rv = get_peer_pid(fd, &pid);
		if (rv < 0) {
			log_error("cmd_register ci %d fd %d get pid failed", ci, fd);
			break;
		}
		log_cmd(cmd, "cmd_register ci %d fd %d pid %d", ci, fd, pid);
		snprintf(client[ci].owner_name, SANLK_NAME_LEN, "%d", pid);
		client[ci].pid = pid;
		client[ci].deadfn = client_pid_dead;

		if (client[ci].tokens) {
			log_error("cmd_register ci %d fd %d tokens exist slots %d",
				  ci, fd, client[ci].tokens_slots);
			free(client[ci].tokens);
		}
		client[ci].tokens_slots = SANLK_MAX_RESOURCES;
		client[ci].tokens = malloc(sizeof(struct token *) * SANLK_MAX_RESOURCES);
		if (!client[ci].tokens) {
			rv = -ENOMEM;
			log_error("cmd_register ci %d fd %d ENOMEM", ci, fd);
			break;
		}
		memset(client[ci].tokens, 0, sizeof(struct token *) * SANLK_MAX_RESOURCES);
		auto_close = 0;
		break;
	case SM_CMD_RESTRICT:
		cmd_restrict(ci, fd, h_recv, cmd);
		auto_close = 0;
		break;
	case SM_CMD_VERSION:
		cmd_version(ci, fd, h_recv);
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
		cmd_status(ci, fd, h_recv, client_maxi, cmd);
		break;
	case SM_CMD_HOST_STATUS:
		strcpy(client[ci].owner_name, "host_status");
		cmd_host_status(ci, fd, h_recv, cmd);
		break;
	case SM_CMD_RENEWAL:
		strcpy(client[ci].owner_name, "renewal");
		cmd_renewal(fd, h_recv);
		break;
	case SM_CMD_LOG_DUMP:
		strcpy(client[ci].owner_name, "log_dump");
		cmd_log_dump(fd, h_recv);
		break;
	case SM_CMD_GET_LOCKSPACES:
		strcpy(client[ci].owner_name, "get_lockspaces");
		cmd_get_lockspaces(ci, fd, h_recv, cmd);
		break;
	case SM_CMD_GET_HOSTS:
		strcpy(client[ci].owner_name, "get_hosts");
		cmd_get_hosts(ci, fd, h_recv, cmd);
		break;
	case SM_CMD_REG_EVENT:
		strcpy(client[ci].owner_name, "reg_event");
		cmd_reg_event(fd, h_recv, cmd);
		break;
	case SM_CMD_END_EVENT:
		strcpy(client[ci].owner_name, "end_event");
		cmd_end_event(fd, h_recv, cmd);
		break;
	case SM_CMD_SET_CONFIG:
		strcpy(client[ci].owner_name, "set_config");
		cmd_set_config(fd, h_recv, cmd);
		break;
	};

	/*
	 * Previously just called close(fd) and did not set client[ci].fd = -1.
	 * This meant that a new client ci could get this fd and use it.
	 *
	 * When a poll error occurs because this ci was finished, then
	 * client_free(ci) would be called for this ci.  client_free would
	 * see cl->fd was still set and call close() on it, even though that
	 * fd was now in use by another ci.
	 *
	 * We could probably get by with just doing this here:
	 * client[ci].fd = -1;
	 * close(fd);
	 *
	 * and then handling the full client_free in response to
	 * the poll error (as done previously), but I see no reason
	 * to avoid the full client_free here.
	 */
	if (auto_close)
		client_free(ci);
}

