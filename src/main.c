/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
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

#define EXTERN
#include "sanlock_internal.h"
#include "diskio.h"
#include "log.h"
#include "paxos_lease.h"
#include "delta_lease.h"
#include "host_id.h"
#include "token_manager.h"
#include "direct.h"
#include "lockfile.h"
#include "watchdog.h"
#include "client_msg.h"
#include "sanlock_resource.h"
#include "sanlock_admin.h"

/* priorities are LOG_* from syslog.h */
int log_logfile_priority = LOG_ERR;
int log_syslog_priority = LOG_ERR;
int log_stderr_priority = LOG_ERR;

struct client {
	int used;
	int fd;  /* unset is -1 */
	int pid; /* unset is -1 */
	int cmd_active;
	int cmd_last;
	int pid_dead;
	int suspend;
	int need_free;
	int killing;
	char owner_name[SANLK_NAME_LEN+1];
	pthread_mutex_t mutex;
	void *workfn;
	void *deadfn;
	struct token *tokens[SANLK_MAX_RESOURCES];
};

#define CLIENT_NALLOC 1024
static int client_maxi;
static int client_size = 0;
static struct client *client = NULL;
static struct pollfd *pollfd = NULL;

static char command[COMMAND_MAX];
static int cmd_argc;
static char **cmd_argv;
static int external_shutdown;
static int token_id_counter = 1;
static int space_id_counter = 1;

struct cmd_args {
	struct list_head list; /* thread_pool data */
	int ci_in;
	int ci_target;
	int cl_fd;
	int cl_pid;
	struct sm_header header;
};

struct thread_pool {
	int num_workers;
	int max_workers;
	int free_workers;
	int quit;
	struct list_head work_data;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_cond_t quit_wait;
};

static struct thread_pool pool;

extern struct list_head spaces;
extern struct list_head spaces_remove;
extern pthread_mutex_t spaces_mutex;

/* FIXME: add a mutex for client array so we don't try to expand it
   while a cmd thread is using it.  Or, with a thread pool we know
   when cmd threads are running and can expand when none are. */

static int client_alloc(void)
{
	int i;

	client = malloc(CLIENT_NALLOC * sizeof(struct client));
	pollfd = malloc(CLIENT_NALLOC * sizeof(struct pollfd));

	if (!client || !pollfd) {
		log_error("can't alloc for client or pollfd array");
		return -ENOMEM;
	}

	for (i = 0; i < CLIENT_NALLOC; i++) {
		memset(&client[i], 0, sizeof(struct client));
		memset(&pollfd[i], 0, sizeof(struct pollfd));

		pthread_mutex_init(&client[i].mutex, NULL);
		client[i].fd = -1;
		client[i].pid = -1;

		pollfd[i].fd = -1;
		pollfd[i].events = 0;
	}
	client_size = CLIENT_NALLOC;
	return 0;
}

static void _client_free(int ci)
{
	struct client *cl = &client[ci];

	if (!cl->used) {
		/* should never happen */
		log_error("client_free ci %d not used", ci);
		goto out;
	}

	if (cl->pid != -1) {
		/* client_pid_dead() should have set pid to -1 */
		/* should never happen */
		log_error("client_free ci %d live pid %d", ci, cl->pid);
		goto out;
	}

	if (cl->fd == -1) {
		/* should never happen */
		log_error("client_free ci %d is free", ci);
		goto out;
	}

	if (cl->suspend) {
		/* could happen, use log_debug */
		log_error("client_free ci %d is suspended", ci);
		cl->need_free = 1;
		goto out;
	}

	if (cl->fd != -1)
		close(cl->fd);

	cl->used = 0;
	cl->fd = -1;
	cl->pid = -1;
	cl->cmd_active = 0;
	cl->pid_dead = 0;
	cl->suspend = 0;
	cl->need_free = 0;
	cl->killing = 0;
	memset(cl->owner_name, 0, sizeof(cl->owner_name));
	cl->workfn = NULL;
	cl->deadfn = NULL;
	memset(cl->tokens, 0, sizeof(struct token *) * SANLK_MAX_RESOURCES);

	/* make poll() ignore this connection */
	pollfd[ci].fd = -1;
	pollfd[ci].events = 0;
 out:
	return;
}

static void client_free(int ci)
{
	struct client *cl = &client[ci];

	pthread_mutex_lock(&cl->mutex);
	_client_free(ci);
	pthread_mutex_unlock(&cl->mutex);
}

/* the connection that we suspend and resume may or may not be the
   same connection as the target client where we set cmd_active */

static int client_suspend(int ci)
{
	struct client *cl = &client[ci];
	int rv = 0;

	pthread_mutex_lock(&cl->mutex);

	if (!cl->used) {
		/* should never happen */
		log_error("client_suspend ci %d not used", ci);
		rv = -1;
		goto out;
	}

	if (cl->fd == -1) {
		/* should never happen */
		log_error("client_suspend ci %d is free", ci);
		rv = -1;
		goto out;
	}

	if (cl->suspend) {
		/* should never happen */
		log_error("client_suspend ci %d is suspended", ci);
		rv = -1;
		goto out;
	}

	cl->suspend = 1;

	/* make poll() ignore this connection */
	pollfd[ci].fd = -1;
	pollfd[ci].events = 0;
 out:
	pthread_mutex_unlock(&cl->mutex);

	return rv;
}

static void client_resume(int ci)
{
	struct client *cl = &client[ci];

	pthread_mutex_lock(&cl->mutex);

	if (!cl->used) {
		/* should never happen */
		log_error("client_resume ci %d not used", ci);
		goto out;
	}

	if (cl->fd == -1) {
		/* should never happen */
		log_error("client_resume ci %d is free", ci);
		goto out;
	}

	if (!cl->suspend) {
		/* should never happen */
		log_error("client_resume ci %d not suspended", ci);
		goto out;
	}

	cl->suspend = 0;

	if (cl->need_free) {
		/* could happen, use log_debug */
		log_error("client_resume ci %d need_free", ci);
		_client_free(ci);
	} else {
		/* make poll() watch this connection */
		pollfd[ci].fd = cl->fd;
		pollfd[ci].events = POLLIN;
	}
 out:
	pthread_mutex_unlock(&cl->mutex);
}

static int client_add(int fd, void (*workfn)(int ci), void (*deadfn)(int ci))
{
	struct client *cl;
	int i;

	for (i = 0; i < client_size; i++) {
		cl = &client[i];
		pthread_mutex_lock(&cl->mutex);
		if (!cl->used) {
			cl->used = 1;
			cl->fd = fd;
			cl->workfn = workfn;
			cl->deadfn = deadfn ? deadfn : client_free;

			/* make poll() watch this connection */
			pollfd[i].fd = fd;
			pollfd[i].events = POLLIN;

			if (i > client_maxi)
				client_maxi = i;
			pthread_mutex_unlock(&cl->mutex);
			return i;
		}
		pthread_mutex_unlock(&cl->mutex);
	}

	return -1;
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

static void client_pid_dead(int ci)
{
	struct client *cl = &client[ci];
	int cmd_active;
	int i, pid;

	/* cmd_acquire_thread may still be waiting for the tokens
	   to be acquired.  if it is, cl->pid_dead tells it to release them
	   when finished.  Similarly, cmd_release_thread, cmd_inquire_thread
	   are accessing cl->tokens */

	pthread_mutex_lock(&cl->mutex);
	if (!cl->used || cl->fd == -1 || cl->pid == -1) {
		/* should never happen */
		pthread_mutex_unlock(&cl->mutex);
		log_error("client_pid_dead %d,%d,%d u %d a %d s %d bad state",
			  ci, cl->fd, cl->pid, cl->used,
			  cl->cmd_active, cl->suspend);
		return;
	}

	log_debug("client_pid_dead %d,%d,%d cmd_active %d suspend %d",
		  ci, cl->fd, cl->pid, cl->cmd_active, cl->suspend);

	cmd_active = cl->cmd_active;
	pid = cl->pid;
	cl->pid = -1;
	cl->pid_dead = 1;

	/* when cmd_active is set and cmd_a,r,i_thread is done and takes
	   cl->mutex to set cl->cmd_active to 0, it will see cl->pid_dead is 1
	   and know they need to release cl->tokens and call client_free */

	/* make poll() ignore this connection */
	pollfd[ci].fd = -1;
	pollfd[ci].events = 0;

	pthread_mutex_unlock(&cl->mutex);

	kill(pid, SIGKILL);

	if (cmd_active) {
		log_debug("client_pid_dead %d,%d,%d defer to cmd %d",
			  ci, cl->fd, pid, cmd_active);
		return;
	}

	/* use async release here because this is the main thread that we don't
	   want to block doing disk lease i/o */

	pthread_mutex_lock(&cl->mutex);
	for (i = 0; i < SANLK_MAX_RESOURCES; i++) {
		if (cl->tokens[i])
			release_token_async(cl->tokens[i]);
	}

	_client_free(ci);
	pthread_mutex_unlock(&cl->mutex);
}

/* At some point we may want to keep a record of each pid using a lockspace
   in the sp struct to avoid walking through each client's cl->tokens to see if
   it's using the lockspace.  It should be the uncommon situation where a
   lockspace renewal fails and we need to walk through all client tokens like
   this.  i.e. we'd probably not want to optimize for this case at the expense
   of the more common case where a pid exits, but we do want it to be robust.

   The locking is also made a bit ugly by these three routines that need to
   correlate which clients are using which lockspaces.  (client_using_space,
   kill_pids, all_pids_dead)  spaces_mutex is held when they are called, and
   they need to take cl->mutex.  This means that cmd_acquire_thread has to
   lock both spaces_mutex and cl->mutex when adding new tokens to the client.
   (It needs to check that the lockspace for the new tokens hasn't failed
   while the tokens were being acquired.)
   
   In kill_pids and all_pids_dead could we check cl->pid <= 0 without
   taking cl->mutex, since client_pid_dead in the main thread is the
   only place that changes that?  */

static int client_using_space(struct client *cl, struct space *sp)
{
	struct token *token;
	int i, rv = 0;

	for (i = 0; i < SANLK_MAX_RESOURCES; i++) {
		token = cl->tokens[i];
		if (!token)
			continue;
		if (strncmp(token->r.lockspace_name, sp->space_name, NAME_ID_SIZE))
			continue;
		rv = 1;
		log_spoke(sp, token, "client_using_space pid %d", cl->pid);
		break;
	}
	return rv;
}

/* FIXME: remove the usleep which intends to give the pid some time to exit so
   we avoid calling kill_pids in quick repetition */

static void kill_pids(struct space *sp)
{
	struct client *cl;
	int ci, pid;
	int sig = SIGTERM;
	int found = 0;

	log_space(sp, "kill_pids %d", sp->killing_pids);

	/* TODO: try killscript first if one is provided */

	if (sp->killing_pids > 11)
		return;

	if (sp->killing_pids > 10) {
		sp->killing_pids++;
		goto do_dump;
	}

	if (sp->killing_pids > 1)
		sig = SIGKILL;
	sp->killing_pids++;

	for (ci = 0; ci <= client_maxi; ci++) {
		pid = -1;

		cl = &client[ci];
		pthread_mutex_lock(&cl->mutex);

		if (!cl->used)
			goto unlock;
		if (cl->pid <= 0)
			goto unlock;
		if (!client_using_space(cl, sp))
			goto unlock;

		pid = cl->pid;
		cl->killing++;
		found++;
 unlock:
		pthread_mutex_unlock(&cl->mutex);

		if (pid > 0)
			kill(pid, sig);
	}

	if (found) {
		log_space(sp, "kill_pids %d found %d pids", sig, found);
		usleep(500000);
	}

	return;

 do_dump:
	for (ci = 0; ci <= client_maxi; ci++) {
		if (client[ci].pid && client[ci].killing) {
			log_error("kill_pids %d stuck", client[ci].pid);
		}
	}
}

static int all_pids_dead(struct space *sp)
{
	struct client *cl;
	int ci, pid;

	for (ci = 0; ci <= client_maxi; ci++) {
		pid = -1;

		cl = &client[ci];
		pthread_mutex_lock(&cl->mutex);

		if (!cl->used)
			goto unlock;
		if (cl->pid <= 0)
			goto unlock;
		if (!client_using_space(cl, sp))
			goto unlock;

		pid = cl->pid;
 unlock:
		pthread_mutex_unlock(&cl->mutex);

		if (pid > 0) {
			log_space(sp, "used by pid %d killing %d",
				  pid, cl->killing);
			return 0;
		}
	}
	log_space(sp, "used by no pids");
	return 1;
}

static unsigned int time_diff(struct timeval *begin, struct timeval *end)
{
	struct timeval result;
	timersub(end, begin, &result);
	return (result.tv_sec * 1000) + (result.tv_usec / 1000);
}

#define STANDARD_CHECK_INTERVAL 1000 /* milliseconds */
#define RECOVERY_CHECK_INTERVAL  200 /* milliseconds */

static int main_loop(void)
{
	void (*workfn) (int ci);
	void (*deadfn) (int ci);
	struct space *sp, *safe;
	struct timeval now, last_check;
	int poll_timeout, check_interval;
	unsigned int ms;
	int i, rv, empty;

	gettimeofday(&last_check, NULL);
	poll_timeout = STANDARD_CHECK_INTERVAL;
	check_interval = STANDARD_CHECK_INTERVAL;

	while (1) {
		rv = poll(pollfd, client_maxi + 1, poll_timeout);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0) {
			/* not sure */
		}
		for (i = 0; i <= client_maxi; i++) {
			if (client[i].fd < 0)
				continue;
			if (pollfd[i].revents & POLLIN) {
				workfn = client[i].workfn;
				if (workfn)
					workfn(i);
			}
			if (pollfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				deadfn = client[i].deadfn;
				if (deadfn)
					deadfn(i);
			}
		}


		gettimeofday(&now, NULL);
		ms = time_diff(&last_check, &now);
		if (ms < check_interval) {
			poll_timeout = check_interval - ms;
			continue;
		}
		last_check = now;

		pthread_mutex_lock(&spaces_mutex);
		list_for_each_entry_safe(sp, safe, &spaces, list) {
			if (sp->killing_pids) {
				if (all_pids_dead(sp)) {
					log_space(sp, "set thread_stop");
					pthread_mutex_lock(&sp->mutex);
					sp->thread_stop = 1;
					unlink_watchdog_file(sp);
					pthread_mutex_unlock(&sp->mutex);
					list_move(&sp->list, &spaces_remove);
				} else {
					kill_pids(sp);
				}
				check_interval = RECOVERY_CHECK_INTERVAL;
			} else {
				if (external_shutdown || sp->external_remove ||
				    !host_id_check(sp)) {
					log_space(sp, "set killing_pids");
					sp->killing_pids = 1;
					kill_pids(sp);
					check_interval = RECOVERY_CHECK_INTERVAL;
				} else {
					check_interval = STANDARD_CHECK_INTERVAL;
				}
			}
		}
		empty = list_empty(&spaces);
		pthread_mutex_unlock(&spaces_mutex);

		if (empty && external_shutdown)
			break;

		clear_spaces(0);

		gettimeofday(&now, NULL);
		ms = time_diff(&last_check, &now);
		if (ms < check_interval)
			poll_timeout = check_interval - ms;
		else
			poll_timeout = 1;
	}

	clear_spaces(1);

	return 0;
}

/* clear the unreceived portion of an aborted command */

static void client_recv_all(int ci, struct sm_header *h_recv, int pos)
{
	char trash[64];
	int rem = h_recv->length - sizeof(struct sm_header) - pos;
	int rv, total = 0;

	if (!rem)
		return;

	while (1) {
		rv = recv(client[ci].fd, trash, sizeof(trash), MSG_DONTWAIT);
		if (rv <= 0)
			break;
		total += rv;

		if (total > MAX_CLIENT_MSG)
			break;
	}

	log_debug("recv_all ci %d rem %d total %d", ci, rem, total);
}

static void release_cl_tokens(struct client *cl)
{
	struct token *token;
	int j;

	for (j = 0; j < SANLK_MAX_RESOURCES; j++) {
		token = cl->tokens[j];
		if (!token)
			continue;
		release_token(token);
		close_disks(token->disks, token->r.num_disks);
		del_resource(token);
		free(token);
	}
}

static void release_new_tokens(struct token *new_tokens[],
			       int alloc_count, int add_count,
			       int open_count, int acquire_count)
{
	int i;

	for (i = 0; i < acquire_count; i++)
		release_token(new_tokens[i]);

	for (i = 0; i < open_count; i++)
		close_disks(new_tokens[i]->disks, new_tokens[i]->r.num_disks);

	for (i = 0; i < add_count; i++)
		del_resource(new_tokens[i]);

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

		rv = _get_space_info(token->r.lockspace_name, &space);

		if (!rv && !space.killing_pids && space.host_id == token->host_id)
			continue;

		return -ENOSPC;
	}

	return 0;
}

static void cmd_acquire(struct cmd_args *ca)
{
	struct sm_header h;
	struct client *cl;
	struct token *token = NULL;
	struct token *new_tokens[SANLK_MAX_RESOURCES];
	struct sanlk_resource res;
	struct sanlk_options opt;
	struct space space;
	char *opt_str;
	uint64_t acquire_lver = 0;
	uint32_t new_num_hosts = 0;
	int token_len, disks_len;
	int fd, rv, i, j, empty_slots, opened;
	int alloc_count = 0, add_count = 0, open_count = 0, acquire_count = 0;
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

		if (res.num_disks > MAX_DISKS) {
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
			token->disks[j].fd = 0;
		}

		token->token_id = token_id_counter++;
		new_tokens[i] = token;
		alloc_count++;

		/* We use the token_id in log messages because the combination
		 * of full length space_name+resource_name in each log message
		 * would make excessively long lines. */

		log_token(token, "lockspace %.48s resource %.48s has token_id %u for pid %u",
			  token->r.lockspace_name, token->r.name, token->token_id, cl_pid);
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
		rv = get_space_info(token->r.lockspace_name, &space);
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
	}

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];
		rv = add_resource(token, cl_pid);
		if (rv < 0) {
			log_errot(token, "cmd_acquire %d,%d,%d add_resource %d",
				  cl_ci, cl_fd, cl_pid, rv);
			result = rv;
			goto done;
		}
		add_count++;
	}

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];
		opened = open_disks(token->disks, token->r.num_disks);
		if (!majority_disks(token, opened)) {
			log_errot(token, "cmd_acquire %d,%d,%d open_disks %d",
				  cl_ci, cl_fd, cl_pid, opened);
			result = -ENODEV;
			goto done;
		}
		open_count++;
	}

	for (i = 0; i < new_tokens_count; i++) {
		token = new_tokens[i];

		if (token->acquire_flags & SANLK_RES_LVER)
			acquire_lver = token->acquire_lver;
		if (token->acquire_flags & SANLK_RES_NUM_HOSTS)
			new_num_hosts = token->acquire_data32;

		rv = acquire_token(token, acquire_lver, new_num_hosts);
		if (rv < 0) {
			if (rv == SANLK_ACQUIRE_IDLIVE && com.quiet_fail) {
				log_token(token, "cmd_acquire %d,%d,%d paxos_lease %d",
					  cl_ci, cl_fd, cl_pid, rv);
			} else {
				log_errot(token, "cmd_acquire %d,%d,%d paxos_lease %d",
					  cl_ci, cl_fd, cl_pid, rv);
			}
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
		release_new_tokens(new_tokens, alloc_count, add_count,
				   open_count, acquire_count);
		release_cl_tokens(cl);
		client_free(cl_ci);
		result = -ENOTTY;
		goto reply;
	}

	/* 3. Failure acquiring leases, and pid is live */

	if (result && !pid_dead) {
		release_new_tokens(new_tokens, alloc_count, add_count,
				   open_count, acquire_count);
		goto reply;
	}

	/* 4. Failure acquiring leases, and pid is dead */

	if (result && pid_dead) {
		release_new_tokens(new_tokens, alloc_count, add_count,
				   open_count, acquire_count);
		release_cl_tokens(cl);
		client_free(cl_ci);
		goto reply;
	}

 reply:
	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = result;
	h.data2 = 0;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	if (!recv_done)
		client_recv_all(ca->ci_in, &ca->header, pos);

	client_resume(ca->ci_in);
}

static void cmd_release(struct cmd_args *ca)
{
	struct sm_header h;
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
		rv = release_token(token);
		if (rv < 0)
			result = rv;
		close_disks(token->disks, token->r.num_disks);
		del_resource(token);
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
		release_cl_tokens(cl);
		client_free(cl_ci);
	}

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = result;
	h.data2 = 0;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	client_resume(ca->ci_in);
}

static void cmd_inquire(struct cmd_args *ca)
{
	struct sm_header h;
	struct token *token;
	struct client *cl;
	char *state, *str;
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

	for (i = 0; i < SANLK_MAX_RESOURCES; i++) {
		if (cl->tokens[i])
			res_count++;
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

		if (i)
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

	log_debug("cmd_inquire %d,%d,%d result %d pid_dead %d count %d strlen %d",
		  cl_ci, cl_fd, cl_pid, result, pid_dead, res_count, state_strlen);

	if (pid_dead) {
		release_cl_tokens(cl);
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

static void cmd_add_lockspace(struct cmd_args *ca)
{
	struct sm_header h;
	struct space *sp;
	struct sanlk_lockspace lockspace;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	log_debug("cmd_add_lockspace %d,%d", ca->ci_in, fd);

	sp = malloc(sizeof(struct space));
	if (!sp) {
		result = -ENOMEM;
		goto reply;
	}

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_add_lockspace %d,%d recv %d %d",
			   ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	memset(sp, 0, sizeof(struct space));
	memcpy(sp->space_name, lockspace.name, NAME_ID_SIZE);
	sp->host_id = lockspace.host_id;
	memcpy(&sp->host_id_disk, &lockspace.host_id_disk,
	       sizeof(struct sanlk_disk));
	pthread_mutex_init(&sp->mutex, NULL);

	pthread_mutex_lock(&spaces_mutex);
	sp->space_id = space_id_counter++;
	pthread_mutex_unlock(&spaces_mutex);

	/* We use the space_id in log messages because the full length
	 * space_name in each log message woul dmake excessively long lines. */

	log_space(sp, "lockspace %.48s host_id %llu has space_id %u",
		  sp->space_name, (unsigned long long)sp->host_id,
		  sp->space_id);

	/* add_space returns once the host_id has been acquired and
	   sp space has been added to the spaces list */

	result = add_space(sp);

	if (result)
		free(sp);
 reply:
	log_debug("cmd_add_lockspace %d,%d done %d", ca->ci_in, fd, result);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = result;
	h.data2 = 0;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	client_resume(ca->ci_in);
}

static void cmd_rem_lockspace(struct cmd_args *ca)
{
	struct sm_header h;
	struct sanlk_lockspace lockspace;
	int fd, rv, result;

	fd = client[ca->ci_in].fd;

	log_debug("cmd_rem_lockspace %d,%d", ca->ci_in, fd);

	rv = recv(fd, &lockspace, sizeof(struct sanlk_lockspace), MSG_WAITALL);
	if (rv != sizeof(struct sanlk_lockspace)) {
		log_error("cmd_rem_lockspace %d,%d recv %d %d",
			  ca->ci_in, fd, rv, errno);
		result = -ENOTCONN;
		goto reply;
	}

	/* rem_space flags the sp as wanting to be removed, so follow with a
	   wait loop until it's actually gone */

	/* TODO: we should probably prevent add_lockspace during an
	   outstanding rem_lockspace and v.v.  This would prevent problems
	   with the space_exists name check below when the same lockspace
	   name was removed and added at once */

	result = rem_space(lockspace.name,
			   (struct sync_disk *)&lockspace.host_id_disk,
			   lockspace.host_id);

	if (result < 0)
		goto reply;

	while (1) {
		if (!space_exists(lockspace.name,
				  (struct sync_disk *)&lockspace.host_id_disk,
				  lockspace.host_id))
			break;
		sleep(1);
	}

 reply:
	log_debug("cmd_rem_lockspace %d,%d done %d", ca->ci_in, fd, result);

	memcpy(&h, &ca->header, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = result;
	h.data2 = 0;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	client_resume(ca->ci_in);
}

static void call_cmd(struct cmd_args *ca)
{
	switch (ca->header.cmd) {
	case SM_CMD_ACQUIRE:
		cmd_acquire(ca);
		break;
	case SM_CMD_RELEASE:
		cmd_release(ca);
		break;
	case SM_CMD_INQUIRE:
		cmd_inquire(ca);
		break;
	case SM_CMD_ADD_LOCKSPACE:
		strcpy(client[ca->ci_in].owner_name, "add_lockspace");
		cmd_add_lockspace(ca);
		break;
	case SM_CMD_REM_LOCKSPACE:
		strcpy(client[ca->ci_in].owner_name, "rem_lockspace");
		cmd_rem_lockspace(ca);
		break;
	};
}

static void *thread_pool_worker(void *data GNUC_UNUSED)
{
	struct cmd_args *ca;

	pthread_mutex_lock(&pool.mutex);

	while (1) {
		while (!pool.quit && list_empty(&pool.work_data)) {
			pool.free_workers++;
			pthread_cond_wait(&pool.cond, &pool.mutex);
			pool.free_workers--;
		}

		while (!list_empty(&pool.work_data)) {
			ca = list_first_entry(&pool.work_data, struct cmd_args, list);
			list_del(&ca->list);
			pthread_mutex_unlock(&pool.mutex);

			call_cmd(ca);
			free(ca);

			pthread_mutex_lock(&pool.mutex);
		}

		if (pool.quit)
			break;
	}

	pool.num_workers--;
	if (!pool.num_workers)
		pthread_cond_signal(&pool.quit_wait);
	pthread_mutex_unlock(&pool.mutex);
	return NULL;
}

static int thread_pool_add_work(struct cmd_args *ca)
{
	pthread_t th;
	int rv;

	pthread_mutex_lock(&pool.mutex);
	if (pool.quit) {
		pthread_mutex_unlock(&pool.mutex);
		return -1;
	}

	list_add_tail(&ca->list, &pool.work_data);

	if (!pool.free_workers && pool.num_workers < pool.max_workers) {
		rv = pthread_create(&th, NULL, thread_pool_worker, &pool);
		if (rv < 0) {
			list_del(&ca->list);
			pthread_mutex_unlock(&pool.mutex);
			return rv;
		}
		pool.num_workers++;
	}

	pthread_cond_signal(&pool.cond);
	pthread_mutex_unlock(&pool.mutex);
	return 0;
}

static void thread_pool_free(void)
{
	pthread_mutex_lock(&pool.mutex);
	pool.quit = 1;
	if (pool.num_workers > 0) {
		pthread_cond_broadcast(&pool.cond);
		pthread_cond_wait(&pool.quit_wait, &pool.mutex);
	}
	pthread_mutex_unlock(&pool.mutex);
}

static int thread_pool_create(int min_workers, int max_workers)
{
	pthread_t th;
	int i, rv;

	memset(&pool, 0, sizeof(pool));
	INIT_LIST_HEAD(&pool.work_data);
	pthread_mutex_init(&pool.mutex, NULL);
	pthread_cond_init(&pool.cond, NULL);
	pthread_cond_init(&pool.quit_wait, NULL);
	pool.max_workers = max_workers;

	for (i = 0; i < min_workers; i++) {
		rv = pthread_create(&th, NULL, thread_pool_worker, &pool);
		if (rv < 0)
			break;
		pool.num_workers++;
	}

	if (rv < 0)
		thread_pool_free();

	return rv;
}

static int print_daemon_state(char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "use_aio=%d "
		 "io_timeout=%d "
		 "host_id_renewal=%d "
		 "host_id_renewal_fail=%d "
		 "host_id_renewal_warn=%d "
		 "host_id_timeout=%d ",
		 to.use_aio,
		 to.io_timeout_seconds,
		 to.host_id_renewal_seconds,
		 to.host_id_renewal_fail_seconds,
		 to.host_id_renewal_warn_seconds,
		 to.host_id_timeout_seconds);

	return strlen(str) + 1;
}

static int print_client_state(struct client *cl, int ci, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "ci=%d "
		 "fd=%d "
		 "pid=%d "
		 "cmd_active=%d "
		 "cmd_last=%d "
		 "pid_dead=%d "
		 "killing=%d "
		 "suspend=%d "
		 "need_free=%d",
		 ci,
		 cl->fd,
		 cl->pid,
		 cl->cmd_active,
		 cl->cmd_last,
		 cl->pid_dead,
		 cl->killing,
		 cl->suspend,
		 cl->need_free);

	return strlen(str) + 1;
}

static int print_token_state(struct token *t, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "token_id=%u "
		 "acquire_result=%d "
		 "release_result=%d "
		 "leader.lver=%llu "
		 "leader.timestamp=%llu "
		 "leader.owner_id=%llu "
		 "leader.owner_generation=%llu",
		 t->token_id,
		 t->acquire_result,
		 t->release_result,
		 (unsigned long long)t->leader.lver,
		 (unsigned long long)t->leader.timestamp,
		 (unsigned long long)t->leader.owner_id,
		 (unsigned long long)t->leader.owner_generation);

	return strlen(str) + 1;
}

/*
 *  0. header
 *  1. dst (sanlk_state DAEMON)
 *  2. dst.str (dst.len)
 *  3. lst (sanlk_state LOCKSPACE)
 *  4. lst.str (lst.len)			print_space_state()
 *  5. lockspace (sanlk_lockspace)
 *  6. [repeat 3-5 for each space]
 *  7. cst (sanlk_state CLIENT)
 *  8. cst.str (cst.len)			print_client_state()
 *  9. rst (sanlk_state RESOURCE)
 * 10. rst.str (rst.len)			print_token_state()
 * 11. resource (sanlk_resource)
 * 12. disks (sanlk_disk * resource.num_disks)
 * 13. [repeat 9-12 for each token]
 * 14. [repeat 7-13 for each client]
 */

static void cmd_status(int fd, struct sm_header *h_recv)
{
	struct sm_header h;
	struct sanlk_state dst;
	struct sanlk_state lst;
	struct sanlk_state cst;
	struct sanlk_state rst;
	struct sanlk_lockspace lockspace;
	char str[SANLK_STATE_MAXSTR];
	struct token *token;
	struct space *sp;
	struct client *cl;
	int ci, i, j, str_len;

	/*
	 * send header: h
	 */

	memset(&h, 0, sizeof(h));
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = 0;

	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	/*
	 * send daemon state: dst, dst.str
	 */

	str_len = print_daemon_state(str);
	memset(&dst, 0, sizeof(dst));
	dst.type = SANLK_STATE_DAEMON;
	dst.str_len = str_len;

	send(fd, &dst, sizeof(dst), MSG_NOSIGNAL);
	if (str_len)
		send(fd, str, str_len, MSG_NOSIGNAL);

	if (h_recv->data == SANLK_STATE_DAEMON)
		return;

	/*
	 * send lockspace state: lst, lst.str, sanlk_lockspace
	 */

	pthread_mutex_lock(&spaces_mutex);
	list_for_each_entry(sp, &spaces, list) {
		str_len = print_space_state(sp, str);
		memset(&lst, 0, sizeof(lst));
		lst.type = SANLK_STATE_LOCKSPACE;
		lst.data64 = sp->host_id;
		strncpy(lst.name, sp->space_name, NAME_ID_SIZE);
		lst.str_len = str_len;

		send(fd, &lst, sizeof(lst), MSG_NOSIGNAL);
		if (str_len)
			send(fd, str, str_len, MSG_NOSIGNAL);

		memset(&lockspace, 0, sizeof(struct sanlk_lockspace));
		strncpy(lockspace.name, sp->space_name, NAME_ID_SIZE);
		lockspace.host_id = sp->host_id;
		memcpy(&lockspace.host_id_disk, &sp->host_id_disk, sizeof(struct sanlk_disk));

		send(fd, &lockspace, sizeof(lockspace), MSG_NOSIGNAL);
	}
	pthread_mutex_unlock(&spaces_mutex);

	if (h_recv->data == SANLK_STATE_LOCKSPACE)
		return;

	/*
	 * send client and resource state:
	 * cst, cst.str, (rst, rst.str, resource, disk*N)*M
	 */

	for (ci = 0; ci <= client_maxi; ci++) {
		cl = &client[ci];

		if (!cl->used)
			continue;

		str_len = print_client_state(cl, ci, str);
		memset(&cst, 0, sizeof(cst));
		cst.type = SANLK_STATE_CLIENT;
		cst.data32 = cl->pid;
		strncpy(cst.name, cl->owner_name, NAME_ID_SIZE);
		cst.str_len = str_len;

		send(fd, &cst, sizeof(cst), MSG_NOSIGNAL);
		if (str_len)
			send(fd, str, str_len, MSG_NOSIGNAL);

		for (i = 0; i < SANLK_MAX_RESOURCES; i++) {
			token = cl->tokens[i];
			if (!token)
				continue;

			str_len = print_token_state(token, str);
			memset(&rst, 0, sizeof(rst));
			rst.type = SANLK_STATE_RESOURCE;
			strncpy(rst.name, token->r.name, NAME_ID_SIZE);
			rst.str_len = str_len;

			send(fd, &rst, sizeof(rst), MSG_NOSIGNAL);
			if (str_len)
				send(fd, str, str_len, MSG_NOSIGNAL);

			send(fd, &token->r, sizeof(struct sanlk_resource), MSG_NOSIGNAL);

			for (j = 0; j < token->r.num_disks; j++) {
				send(fd, &token->disks[j], sizeof(struct sanlk_disk), MSG_NOSIGNAL);
			}
		}
	}
}

static void cmd_log_dump(int fd, struct sm_header *h_recv)
{
	send(fd, h_recv, sizeof(struct sm_header), MSG_DONTWAIT);

	write_log_dump(fd);
}

static void process_cmd_thread_lockspace(int ci_in, struct sm_header *h_recv)
{
	struct cmd_args *ca;
	struct sm_header h;
	int rv;

	ca = malloc(sizeof(struct cmd_args));
	if (!ca) {
		rv = -ENOMEM;
		goto fail;
	}
	ca->ci_in = ci_in;
	memcpy(&ca->header, h_recv, sizeof(struct sm_header));

	if (h_recv->cmd == SM_CMD_ADD_LOCKSPACE)
		strcpy(client[ci_in].owner_name, "add_lockspace");
	else if (h_recv->cmd == SM_CMD_REM_LOCKSPACE)
		strcpy(client[ci_in].owner_name, "rem_lockspace");
	else
		strcpy(client[ci_in].owner_name, "cmd_lockspace");

	rv = thread_pool_add_work(ca);
	if (rv < 0)
		goto fail_free;
	return;

 fail_free:
	free(ca);
 fail:
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = rv;
	h.data2 = 0;
	send(client[ci_in].fd, &h, sizeof(h), MSG_NOSIGNAL);
	close(client[ci_in].fd);
}

static void process_cmd_thread_resource(int ci_in, struct sm_header *h_recv)
{
	struct cmd_args *ca;
	struct sm_header h;
	struct client *cl;
	int result = 0;
	int rv, i, ci_target;

	ca = malloc(sizeof(struct cmd_args));
	if (!ca) {
		result = -ENOMEM;
		goto fail;
	}

	if (h_recv->data2 != -1) {
		/* lease for another registered client with pid specified by data2 */
		ci_target = -1;

		for (i = 0; i < client_size; i++) {
			cl = &client[i];
			pthread_mutex_lock(&cl->mutex);
			if (cl->pid != h_recv->data2) {
				pthread_mutex_unlock(&cl->mutex);
				continue;
			}
			ci_target = i;
			break;
		}
		if (ci_target < 0) {
			result = -ESRCH;
			goto fail;
		}
	} else {
		/* lease for this registered client */

		ci_target = ci_in;
		cl = &client[ci_target];
		pthread_mutex_lock(&cl->mutex);
	}

	if (!cl->used) {
		log_error("cmd %d %d,%d,%d not used",
			  h_recv->cmd, ci_target, cl->fd, cl->pid);
		result = -EBUSY;
		goto out;
	}

	if (cl->pid <= 0) {
		log_error("cmd %d %d,%d,%d no pid",
			  h_recv->cmd, ci_target, cl->fd, cl->pid);
		result = -EBUSY;
		goto out;
	}

	if (cl->pid_dead) {
		log_error("cmd %d %d,%d,%d pid_dead",
			  h_recv->cmd, ci_target, cl->fd, cl->pid);
		result = -EBUSY;
		goto out;
	}

	if (cl->need_free) {
		log_error("cmd %d %d,%d,%d need_free",
			  h_recv->cmd, ci_target, cl->fd, cl->pid);
		result = -EBUSY;
		goto out;
	}

	if (cl->killing) {
		log_error("cmd %d %d,%d,%d killing",
			  h_recv->cmd, ci_target, cl->fd, cl->pid);
		result = -EBUSY;
		goto out;
	}

	if (cl->cmd_active) {
		log_error("cmd %d %d,%d,%d cmd_active %d",
			  h_recv->cmd, ci_target, cl->fd, cl->pid,
			  cl->cmd_active);
		result = -EBUSY;
		goto out;
	}

	cl->cmd_active = h_recv->cmd;

	/* once cmd_active is set, client_pid_dead() will not clear cl->tokens
	   or call client_free, so it's the responsiblity of cmd_a,r,i_thread
	   to check if pid_dead when clearing cmd_active, and doing the cleanup
	   if pid is dead */
 out:
	pthread_mutex_unlock(&cl->mutex);

	if (result < 0)
		goto fail;

	ca->ci_in = ci_in;
	ca->ci_target = ci_target;
	ca->cl_pid = cl->pid;
	ca->cl_fd = cl->fd;
	memcpy(&ca->header, h_recv, sizeof(struct sm_header));

	rv = thread_pool_add_work(ca);
	if (rv < 0) {
		/* we don't have to worry about client_pid_dead having
		   been called while mutex was unlocked with cmd_active set,
		   because client_pid_dead is called from the main thread which
		   is running this function */

		log_error("create cmd thread failed");
		pthread_mutex_lock(&cl->mutex);
		cl->cmd_active = 0;
		pthread_mutex_unlock(&cl->mutex);
		result = rv;
		goto fail;
	}
	return;

 fail:
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = result;
	h.data2 = 0;
	send(client[ci_in].fd, &h, sizeof(h), MSG_NOSIGNAL);

	client_recv_all(ci_in, h_recv, 0);

	client_resume(ci_in);
	if (ca)
		free(ca);
}

static void process_cmd_daemon(int ci, struct sm_header *h_recv)
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
	case SM_CMD_SHUTDOWN:
		strcpy(client[ci].owner_name, "shutdown");
		external_shutdown = 1;
		break;
	case SM_CMD_STATUS:
		strcpy(client[ci].owner_name, "status");
		cmd_status(fd, h_recv);
		break;
	case SM_CMD_LOG_DUMP:
		strcpy(client[ci].owner_name, "log_dump");
		cmd_log_dump(fd, h_recv);
		break;
	};

	if (auto_close)
		close(fd);
}

static void process_connection(int ci)
{
	struct sm_header h;
	void (*deadfn)(int ci);
	int rv;

	memset(&h, 0, sizeof(h));

	rv = recv(client[ci].fd, &h, sizeof(h), MSG_WAITALL);
	if (!rv)
		return;
	if (rv < 0) {
		log_error("ci %d recv error %d", ci, errno);
		return;
	}
	if (rv != sizeof(h)) {
		log_error("ci %d recv size %d", ci, rv);
		goto dead;
	}
	if (h.magic != SM_MAGIC) {
		log_error("ci %d recv %d magic %x vs %x",
			  ci, rv, h.magic, SM_MAGIC);
		goto dead;
	}

	client[ci].cmd_last = h.cmd;

	switch (h.cmd) {
	case SM_CMD_REGISTER:
	case SM_CMD_SHUTDOWN:
	case SM_CMD_STATUS:
	case SM_CMD_LOG_DUMP:
		process_cmd_daemon(ci, &h);
		break;
	case SM_CMD_ADD_LOCKSPACE:
	case SM_CMD_REM_LOCKSPACE:
		rv = client_suspend(ci);
		if (rv < 0)
			return;
		process_cmd_thread_lockspace(ci, &h);
		break;
	case SM_CMD_ACQUIRE:
	case SM_CMD_RELEASE:
	case SM_CMD_INQUIRE:
		/* the main_loop needs to ignore this connection
		   while the thread is working on it */
		rv = client_suspend(ci);
		if (rv < 0)
			return;
		process_cmd_thread_resource(ci, &h);
		break;
	default:
		log_error("ci %d cmd %d unknown", ci, h.cmd);
	};

	return;

 dead:
	deadfn = client[ci].deadfn;
	if (deadfn)
		deadfn(ci);
}

static void process_listener(int ci GNUC_UNUSED)
{
	int fd;
	int on = 1;

	fd = accept(client[ci].fd, NULL, NULL);
	if (fd < 0)
		return;

	setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

	client_add(fd, process_connection, NULL);
}

static int setup_listener(void)
{
	int rv, fd, ci;

	rv = setup_listener_socket(&fd, com.uid, com.gid, DEFAULT_SOCKET_MODE);
	if (rv < 0)
		return rv;

	ci = client_add(fd, process_listener, NULL);
	if (ci < 0)
		return -1;

	strcpy(client[ci].owner_name, "listener");
	return 0;
}

static void sigterm_handler(int sig GNUC_UNUSED)
{
	external_shutdown = 1;
}

static int make_dirs(void)
{
	mode_t old_umask;
	int rv;

	old_umask = umask(0022);
	rv = mkdir(SANLK_RUN_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	rv = 0;
 out:
	umask(old_umask);
	return rv;
}

static void setup_priority(void)
{
	struct sched_param sched_param;
	int rv;

	if (!com.high_priority)
		return;

	rv = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (rv < 0) {
		log_error("mlockall failed");
	}

	rv = sched_get_priority_max(SCHED_RR);
	if (rv < 0) {
		log_error("could not get max scheduler priority err %d", errno);
		return;
	}

	sched_param.sched_priority = rv;
	rv = sched_setscheduler(0, SCHED_RR|SCHED_RESET_ON_FORK, &sched_param);
	if (rv < 0) {
		log_error("could not set RR|RESET_ON_FORK priority %d err %d",
			  sched_param.sched_priority, errno);
	}
}

static int do_daemon(void)
{
	struct sigaction act;
	int fd, rv;

	/* TODO: copy comprehensive daemonization method from libvirtd */

	if (!com.debug) {
		if (daemon(0, 0) < 0) {
			log_tool("cannot fork daemon\n");
			exit(EXIT_FAILURE);
		}
		umask(0);
	}

	rv = client_alloc();
	if (rv < 0)
		return rv;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigterm_handler;
	rv = sigaction(SIGTERM, &act, NULL);
	if (rv < 0)
		return rv;

	rv = make_dirs();
	if (rv < 0)
		return rv;

	setup_logging();

	setup_priority();

	fd = lockfile(SANLK_RUN_DIR, SANLK_LOCKFILE_NAME);
	if (fd < 0)
		goto out;

	rv = thread_pool_create(DEFAULT_MIN_WORKER_THREADS, com.max_worker_threads);
	if (rv < 0)
		goto out_lockfile;

	rv = setup_watchdog();
	if (rv < 0)
		goto out_threads;

	rv = setup_listener();
	if (rv < 0)
		goto out_threads;

	setup_token_manager();
	if (rv < 0)
		goto out_threads;

	setup_spaces();

	main_loop();

	close_token_manager();

	close_watchdog();

 out_threads:
	thread_pool_free();
 out_lockfile:
	unlink_lockfile(fd, SANLK_RUN_DIR, SANLK_LOCKFILE_NAME);
 out:
	close_logging();
	return rv;
}

static int user_to_uid(char *arg)
{
	struct passwd *pw;

	pw = getpwnam(arg);
	if (pw == NULL) {
		log_error("user '%s' not found, "
                          "using uid: %i", arg, DEFAULT_SOCKET_UID);
		return DEFAULT_SOCKET_UID;
	}

	return pw->pw_uid;
}

static int group_to_gid(char *arg)
{
	struct group *gr;

	gr = getgrnam(arg);
	if (gr == NULL) {
		log_error("group '%s' not found, "
                          "using uid: %i", arg, DEFAULT_SOCKET_UID);
		return DEFAULT_SOCKET_GID;
	}

	return gr->gr_gid;
}

static int parse_arg_lockspace(char *arg)
{
	sanlock_str_to_lockspace(arg, &com.lockspace);

	log_debug("lockspace %s host_id %llu path %s offset %llu",
		  com.lockspace.name,
		  (unsigned long long)com.lockspace.host_id,
		  com.lockspace.host_id_disk.path,
		  (unsigned long long)com.lockspace.host_id_disk.offset);

	return 0;
}

static int parse_arg_resource(char *arg)
{
	struct sanlk_resource *res;
	int rv, i;

	if (com.res_count >= SANLK_MAX_RESOURCES) {
		log_tool("resource args over max %d", SANLK_MAX_RESOURCES);
		return -1;
	}

	rv = sanlock_str_to_res(arg, &res);
	if (rv < 0) {
		log_tool("resource arg parse error %d\n", rv);
		return rv;
	}

	com.res_args[com.res_count] = res;
	com.res_count++;

	log_debug("resource %s %s num_disks %d flags %x lver %llu",
		  res->lockspace_name, res->name, res->num_disks, res->flags,
		  (unsigned long long)res->lver);
	for (i = 0; i < res->num_disks; i++) {
		log_debug("resource disk %s %llu", res->disks[i].path,
			  (unsigned long long)res->disks[i].offset);
	}
	return 0;
}

static void set_timeout(char *key, char *val)
{
	if (!strcmp(key, "io_timeout")) {
		to.io_timeout_seconds = atoi(val);
		log_debug("io_timeout_seconds %d", to.io_timeout_seconds);
		return;
	}

	if (!strcmp(key, "host_id_timeout")) {
		to.host_id_timeout_seconds = atoi(val);
		log_debug("host_id_timeout_seconds %d", to.host_id_timeout_seconds);
		return;
	}

	if (!strcmp(key, "host_id_renewal")) {
		to.host_id_renewal_seconds = atoi(val);
		log_debug("host_id_renewal_seconds %d", to.host_id_renewal_seconds);
		return;
	}

	if (!strcmp(key, "host_id_renewal_warn")) {
		to.host_id_renewal_warn_seconds = atoi(val);
		log_debug("host_id_renewal_warn_seconds %d", to.host_id_renewal_warn_seconds);
		return;
	}

	if (!strcmp(key, "host_id_renewal_fail")) {
		to.host_id_renewal_fail_seconds = atoi(val);
		log_debug("host_id_renewal_fail_seconds %d", to.host_id_renewal_fail_seconds);
		return;
	}

}

/* optstr format "abc=123,def=456,ghi=789" */

static void parse_arg_timeout(char *optstr)
{
	int copy_key, copy_val, i, kvi;
	char key[64], val[64];

	copy_key = 1;
	copy_val = 0;
	kvi = 0;

	for (i = 0; i < strlen(optstr); i++) {
		if (optstr[i] == ',') {
			set_timeout(key, val);
			memset(key, 0, sizeof(key));
			memset(val, 0, sizeof(val));
			copy_key = 1;
			copy_val = 0;
			kvi = 0;
			continue;
		}

		if (optstr[i] == '=') {
			copy_key = 0;
			copy_val = 1;
			kvi = 0;
			continue;
		}

		if (copy_key)
			key[kvi++] = optstr[i];
		else if (copy_val)
			val[kvi++] = optstr[i];

		if (kvi > 62) {
			log_error("invalid timeout parameter");
			return;
		}
	}

	set_timeout(key, val);
}

#define RELEASE_VERSION "1.2"

/* 
 * daemon: acquires leases for the local host_id, associates them with a local
 * pid, and releases them when the associated pid exits.
 *
 * client: ask daemon to acquire/release leases associated with a given pid.
 *
 * direct: acquires and releases leases directly for the local host_id by
 * reading and writing storage directly.
 */

static void print_usage(void)
{
	printf("Usage:\n");
	printf("sanlock <type> <action> [options]\n\n");

	printf("types:\n");
	printf("  version		print version\n");
	printf("  help			print usage\n");
	printf("  daemon		start daemon\n");
	printf("  client		send request to daemon (default type if none given)\n");
	printf("  direct		access storage directly (no coordination with daemon)\n");
	printf("\n");
	printf("client actions:		ask daemon to:\n");
	printf("  status		send internal state\n");
	printf("  log_dump		send internal debug buffer\n");
	printf("  shutdown		kill pids, release leases and exit\n");
	printf("  add_lockspace		add a lockspace, acquiring a host_id in it\n");
	printf("  rem_lockspace		remove a lockspace, releasing our host_id in it\n");
	printf("  command		acquire leases for the calling pid, then run command\n");
	printf("  acquire		acquire leases for a given pid\n");
	printf("  release		release leases for a given pid\n");
	printf("  inquire		display leases held by a given pid\n");
	printf("\n");
	printf("direct actions:		read/write storage directly to:\n");
	printf("  init			initialize disk areas for host_id and resource leases\n");
	printf("  dump			print initialized leases\n");
	printf("  read_leader		print values in leader_record\n");
	printf("  acquire		acquire leases\n");
	printf("  release		release leases\n");
	printf("  acquire_id		acquire a host_id lease\n");
	printf("  release_id		release a host_id lease\n");
	printf("  renew_id		renew a host_id lease\n");
	printf("  read_id		read a host_id lease, print the state\n");
	printf("  live_id		monitor a host_id lease for liveness\n");
	printf("\n");
	printf("daemon\n");
	printf("  -D			debug: no fork and print all logging to stderr\n");
	printf("  -R <num>		debug renewal: log debug info about renewals\n");
	printf("  -Q <num>		quiet error messages for common lock contention\n");
	printf("  -L <level>		write logging at level and up to logfile (-1 none)\n");
	printf("  -S <level>		write logging at level and up to syslog (-1 none)\n");
	printf("  -t <num>		max worker threads (default %d)\n", DEFAULT_MAX_WORKER_THREADS);
	printf("  -w <num>		use watchdog through wdmd (1 yes, 0 no, default %d)\n", DEFAULT_USE_WATCHDOG);
	printf("  -a <num>		use async io (1 yes, 0 no, default %d)\n", DEFAULT_USE_AIO);
	printf("  -h <num>		use high priority features (1 yes, 0 no, default %d)\n", DEFAULT_HIGH_PRIORITY);
	printf("                        includes max realtime scheduling priority, mlockall\n");
	printf("  -o <key=n,key=n,...>	change default timeouts in seconds, key (default):\n");
	printf("                        io_timeout (%d)\n", DEFAULT_IO_TIMEOUT_SECONDS);
	printf("                        host_id_renewal (%d)\n", DEFAULT_HOST_ID_RENEWAL_SECONDS);
	printf("                        host_id_renewal_warn (%d)\n", DEFAULT_HOST_ID_RENEWAL_WARN_SECONDS);
	printf("                        host_id_renewal_fail (%d)\n", DEFAULT_HOST_ID_RENEWAL_FAIL_SECONDS);
	printf("                        host_id_timeout (%d)\n", DEFAULT_HOST_ID_TIMEOUT_SECONDS);
	printf("\n");
	printf("client status\n");
	printf("  -D			debug: print extra internal state for debugging\n");
	printf("\n");
	printf("client log_dump\n");
	printf("\n");
	printf("client shutdown\n");
	printf("\n");
	printf("client add_lockspace -s LOCKSPACE\n");
	printf("\n");
	printf("client rem_lockspace -s LOCKSPACE\n");
	printf("\n");
	printf("client command -r RESOURCE -c <path> <args>\n");
	printf("  -n <num_hosts>	change num_hosts in leases when acquired\n");
	printf("  -c <path> <args>	run command with args, -c must be final option\n");
	printf("\n");
	printf("client acquire -p <pid> -r RESOURCE\n");
	printf("  -p <pid>		process that lease should be added for\n");
	printf("\n");
	printf("client release -p <pid> -r RESOURCE\n");
	printf("  -p <pid>		process whose lease should be released\n");
	printf("\n");
	printf("client inquire -p <pid>\n");
	printf("  -p <pid>		process whose resource leases should be displayed\n");
	printf("\n");

	printf("direct init -n <num_hosts> [-s LOCKSPACE] [-r RESOURCE]\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("  -n <num_hosts>	host_id's from 1 to num_hosts will be able to acquire\n");
	printf("                        a resource lease.  This is also number of sectors that\n");
	printf("                        are read when paxos is run to acquire a resource lease.\n");
	printf("  -m <max_hosts>	disk space is allocated to support this many hosts\n");
	printf("                        (default max_hosts %d)\n", DEFAULT_MAX_HOSTS);
	printf("  -s LOCKSPACE		initialize host_id leases for host_id's 1 to max_hosts\n");
	printf("                        (the specific host_id in the LOCKSPACE arg is ignored)\n");
	printf("  -r RESOURCE           initialize a resource lease for use by host_id's 1 to\n");
	printf("                        num_hosts (num_hosts can be extended up to max_hosts)\n");
	printf("\n");
	printf("direct dump <path>[:<offset>] [options]\n");
	printf("  -D			debug: print extra info for debugging\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("\n");
	printf("direct read_leader [-s LOCKSPACE] [-r RESOURCE]\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("\n");
	printf("direct acquire|release -i <num> -g <num> -r RESOURCE\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("  -n <num_hosts>	change num_hosts in leases when acquired\n");
	printf("  -i <num>		host_id of local host\n");
	printf("  -g <num>		host_id generation of local host\n");
	printf("\n");
	printf("direct acquire_id|renew_id|release_id|read_id|live_id -s LOCKSPACE\n");
	printf("  -a <num>		use async io (1 yes, 0 no)\n");
	printf("\n");

	printf("LOCKSPACE = <lockspace_name>:<host_id>:<path>:<offset>\n");
	printf("  <lockspace_name>	name of lockspace\n");
	printf("  <host_id>		local host identifier in lockspace\n");
	printf("  <path>		disk path where host_id leases are written\n");
	printf("  <offset>		offset on disk, in bytes\n");
	printf("\n");
	printf("RESOURCE = <lockspace_name>:<resource_name>:<path>:<offset>[:<lver>]\n");
	printf("  <lockspace_name>	name of lockspace\n");
	printf("  <resource_name>	name of resource being leased\n");
	printf("  <path>		disk path where resource leases are written\n");
	printf("  <offset>		offset on disk in bytes\n");
	printf("  <lver>                optional disk leader version of resource for acquire\n");
	printf("\n");
}

static int read_command_line(int argc, char *argv[])
{
	char optchar;
	char *optionarg;
	char *p;
	char *arg1 = argv[1];
	char *act;
	int i, j, len, begin_command = 0;

	if (argc < 2 || !strcmp(arg1, "help") || !strcmp(arg1, "--help") ||
	    !strcmp(arg1, "-h")) {
		print_usage();
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "version") || !strcmp(arg1, "--version") ||
	    !strcmp(arg1, "-V")) {
		printf("%s %s (built %s %s)\n",
		       argv[0], RELEASE_VERSION, __DATE__, __TIME__);
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "daemon")) {
		com.type = COM_DAEMON;
		i = 2;
	} else if (!strcmp(arg1, "direct")) {
		com.type = COM_DIRECT;
		if (argc < 3) {
			print_usage();
			exit(EXIT_FAILURE);
		}
		act = argv[2];
		i = 3;
	} else if (!strcmp(arg1, "client")) {
		com.type = COM_CLIENT;
		if (argc < 3) {
			print_usage();
			exit(EXIT_FAILURE);
		}
		act = argv[2];
		i = 3;
	} else {
		com.type = COM_CLIENT;
		act = argv[1];
		i = 2;
	}

	switch (com.type) {
	case COM_DAEMON:
		break;

	case COM_CLIENT:
		if (!strcmp(act, "status"))
			com.action = ACT_STATUS;
		else if (!strcmp(act, "log_dump"))
			com.action = ACT_LOG_DUMP;
		else if (!strcmp(act, "shutdown"))
			com.action = ACT_SHUTDOWN;
		else if (!strcmp(act, "add_lockspace"))
			com.action = ACT_ADD_LOCKSPACE;
		else if (!strcmp(act, "rem_lockspace"))
			com.action = ACT_REM_LOCKSPACE;
		else if (!strcmp(act, "command"))
			com.action = ACT_COMMAND;
		else if (!strcmp(act, "acquire"))
			com.action = ACT_ACQUIRE;
		else if (!strcmp(act, "release"))
			com.action = ACT_RELEASE;
		else if (!strcmp(act, "inquire"))
			com.action = ACT_INQUIRE;
		else {
			log_tool("client action \"%s\" is unknown", act);
			exit(EXIT_FAILURE);
		}
		break;

	case COM_DIRECT:
		if (!strcmp(act, "init"))
			com.action = ACT_INIT;
		else if (!strcmp(act, "dump"))
			com.action = ACT_DUMP;
		else if (!strcmp(act, "read_leader"))
			com.action = ACT_READ_LEADER;
		else if (!strcmp(act, "acquire"))
			com.action = ACT_ACQUIRE;
		else if (!strcmp(act, "release"))
			com.action = ACT_RELEASE;
		else if (!strcmp(act, "acquire_id"))
			com.action = ACT_ACQUIRE_ID;
		else if (!strcmp(act, "release_id"))
			com.action = ACT_RELEASE_ID;
		else if (!strcmp(act, "renew_id"))
			com.action = ACT_RENEW_ID;
		else if (!strcmp(act, "read_id"))
			com.action = ACT_READ_ID;
		else if (!strcmp(act, "live_id"))
			com.action = ACT_LIVE_ID;
		else {
			log_tool("direct action \"%s\" is unknown", act);
			exit(EXIT_FAILURE);
		}
		break;
	};


	/* the only action that has an option without dash-letter prefix */
	if (com.action == ACT_DUMP) {
		optionarg = argv[i++];
		com.dump_path = strdup(optionarg);
	}

	for (; i < argc; ) {
		p = argv[i];

		if ((p[0] != '-') || (strlen(p) != 2)) {
			log_tool("unknown option %s", p);
			log_tool("space required before option value");
			exit(EXIT_FAILURE);
		}

		optchar = p[1];
		i++;

		/* the only option that does not have optionarg */
		if (optchar == 'D') {
			com.debug = 1;
			log_stderr_priority = LOG_DEBUG;
			continue;
		}

		if (i >= argc) {
			log_tool("option '%c' requires arg", optchar);
			exit(EXIT_FAILURE);
		}

		optionarg = argv[i];

		switch (optchar) {
		case 'Q':
			com.quiet_fail = atoi(optionarg);
			break;
		case 'R':
			com.debug_renew = atoi(optionarg);
			break;
		case 'L':
			log_logfile_priority = atoi(optionarg);
			break;
		case 'S':
			log_syslog_priority = atoi(optionarg);
			break;
		case 'a':
			to.use_aio = atoi(optionarg);
			break;
		case 't':
			com.max_worker_threads = atoi(optionarg);
			if (com.max_worker_threads < DEFAULT_MIN_WORKER_THREADS)
				com.max_worker_threads = DEFAULT_MIN_WORKER_THREADS;
			break;
		case 'w':
			com.use_watchdog = atoi(optionarg);
			break;
		case 'h':
			com.high_priority = atoi(optionarg);
			break;
		case 'o':
			parse_arg_timeout(optionarg); /* to */
			break;

		case 'n':
			com.num_hosts = atoi(optionarg);
			break;
		case 'm':
			com.max_hosts = atoi(optionarg);
			break;
		case 'p':
			com.pid = atoi(optionarg);
			break;
		case 'i':
			com.local_host_id = atoll(optionarg);
			break;
		case 'g':
			com.local_host_generation = atoll(optionarg);
			break;

		case 's':
			parse_arg_lockspace(optionarg); /* com.lockspace */
			break;
		case 'r':
			parse_arg_resource(optionarg); /* com.res_args[] */
			break;

		case 'U':
			com.uid = user_to_uid(optionarg);
			break;
		case 'G':
			com.gid = group_to_gid(optionarg);
			break;

		case 'c':
			begin_command = 1;
			break;
		default:
			log_tool("unknown option: %c", optchar);
			exit(EXIT_FAILURE);
		};


		if (begin_command)
			break;

		i++;
	}

	/*
	 * the remaining args are for the command
	 *
	 * sanlock -r foo -n 2 -d bar:0 -c /bin/cmd -X -Y -Z
	 * argc = 12
	 * loop above breaks with i = 8, argv[8] = "/bin/cmd"
	 *
	 * cmd_argc = 4 = argc (12) - i (8)
	 * cmd_argv[0] = "/bin/cmd"
	 * cmd_argv[1] = "-X"
	 * cmd_argv[2] = "-Y"
	 * cmd_argv[3] = "-Z"
	 * cmd_argv[4] = NULL (required by execv)
	 */

	if (begin_command) {
		cmd_argc = argc - i;

		if (cmd_argc < 1) {
			log_tool("command option (-c) requires an arg");
			return -EINVAL;
		}

		len = (cmd_argc + 1) * sizeof(char *); /* +1 for final NULL */
		cmd_argv = malloc(len);
		if (!cmd_argv)
			return -ENOMEM;
		memset(cmd_argv, 0, len);

		for (j = 0; j < cmd_argc; j++) {
			cmd_argv[j] = strdup(argv[i++]);
			if (!cmd_argv[j])
				return -ENOMEM;
		}

		strncpy(command, cmd_argv[0], COMMAND_MAX - 1);
	}

	return 0;
}

static int do_client(void)
{
	struct sanlk_resource **res_args = NULL;
	struct sanlk_resource *res;
	char *res_state = NULL;
	int i, fd, rv = 0;

	if (com.action == ACT_COMMAND || com.action == ACT_ACQUIRE) {
		if (com.num_hosts) {
			for (i = 0; i < com.res_count; i++) {
				res = com.res_args[i];
				res->flags |= SANLK_RES_NUM_HOSTS;
				res->data32 = com.num_hosts;
			}
		}
	}

	switch (com.action) {
	case ACT_STATUS:
		rv = sanlock_status(com.debug);
		break;

	case ACT_LOG_DUMP:
		rv = sanlock_log_dump();
		break;

	case ACT_SHUTDOWN:
		log_tool("shutdown");
		rv = sanlock_shutdown();
		log_tool("shutdown done %d", rv);
		break;

	case ACT_COMMAND:
		log_tool("register");
		fd = sanlock_register();
		log_tool("register done %d", fd);

		if (fd < 0)
			goto out;

		log_tool("acquire fd %d", fd);
		rv = sanlock_acquire(fd, -1, 0, com.res_count, com.res_args, NULL);
		log_tool("acquire done %d", rv);

		if (rv < 0)
			goto out;

		if (!command[0]) {
			while (1)
				sleep(10);
		}
		execv(command, cmd_argv);
		perror("execv failed");

		/* release happens automatically when pid exits and
		   daemon detects POLLHUP on registered connection */
		break;

	case ACT_ADD_LOCKSPACE:
		log_tool("add_lockspace");
		rv = sanlock_add_lockspace(&com.lockspace, 0);
		log_tool("add_lockspace done %d", rv);
		break;

	case ACT_REM_LOCKSPACE:
		log_tool("rem_lockspace");
		rv = sanlock_rem_lockspace(&com.lockspace, 0);
		log_tool("rem_lockspace done %d", rv);
		break;

	case ACT_ACQUIRE:
		log_tool("acquire pid %d", com.pid);
		rv = sanlock_acquire(-1, com.pid, 0, com.res_count, com.res_args, NULL);
		log_tool("acquire done %d", rv);
		break;

	case ACT_RELEASE:
		log_tool("release pid %d", com.pid);
		rv = sanlock_release(-1, com.pid, 0, com.res_count, com.res_args);
		log_tool("release done %d", rv);
		break;

	case ACT_INQUIRE:
		log_tool("inquire pid %d", com.pid);
		rv = sanlock_inquire(-1, com.pid, 0, &com.res_count, &res_state);
		log_tool("inquire done %d res_count %d", rv, com.res_count);
		if (rv < 0)
			break;
		log_tool("\"%s\"", res_state);

		if (!com.debug)
			break;

		com.res_count = 0;

		rv = sanlock_state_to_args(res_state, &com.res_count, &res_args);
		log_tool("\nstate_to_args done %d res_count %d", rv, com.res_count);
		if (rv < 0)
			break;

		free(res_state);
		res_state = NULL;

		for (i = 0; i < com.res_count; i++) {
			res = res_args[i];
			log_tool("\"%s:%s:%s:%llu:%llu\"",
				 res->lockspace_name, res->name, res->disks[0].path,
				 (unsigned long long)res->disks[0].offset,
				 (unsigned long long)res->lver);
		}

		rv = sanlock_args_to_state(com.res_count, res_args, &res_state);
		log_tool("\nargs_to_state done %d", rv);
		if (rv < 0)
			break;
		log_tool("\"%s\"", res_state);
		break;

	default:
		log_tool("action not implemented");
		rv = -1;
	}
 out:
	return rv;
}

static int do_direct(void)
{
	struct leader_record leader;
	uint64_t timestamp, owner_id, owner_generation;
	int live;
	int rv;

	switch (com.action) {
	case ACT_INIT:
		rv = direct_init(&to, &com.lockspace, com.res_args[0],
				 com.max_hosts, com.num_hosts);
		log_tool("init done %d", rv);
		break;

	case ACT_DUMP:
		rv = direct_dump(&to, com.dump_path);
		log_tool("dump done %d", rv);
		break;

	case ACT_READ_LEADER:
		rv = direct_read_leader(&to, &com.lockspace, com.res_args[0], &leader);
		log_tool("read_leader done %d", rv);
		log_tool("magic 0x%x", leader.magic);
		log_tool("version 0x%x", leader.version);
		log_tool("sector_size %u", leader.sector_size);
		log_tool("num_hosts %llu",
			 (unsigned long long)leader.num_hosts);
		log_tool("max_hosts %llu",
			 (unsigned long long)leader.max_hosts);
		log_tool("owner_id %llu",
			 (unsigned long long)leader.owner_id);
		log_tool("owner_generation %llu",
			 (unsigned long long)leader.owner_generation);
		log_tool("lver %llu",
			 (unsigned long long)leader.lver);
		log_tool("space_name %.48s", leader.space_name);
		log_tool("resource_name %.48s", leader.resource_name);
		log_tool("timestamp %llu",
			 (unsigned long long)leader.timestamp);
		log_tool("checksum %u", leader.checksum);
		log_tool("write_id %llu",
			 (unsigned long long)leader.write_id);
		log_tool("write_generation %llu",
			 (unsigned long long)leader.write_generation);
		log_tool("write_timestamp %llu",
			 (unsigned long long)leader.write_timestamp);
		break;

	case ACT_ACQUIRE:
		rv = direct_acquire(&to, com.res_args[0], com.num_hosts,
				    com.local_host_id, com.local_host_generation,
				    &leader);
		log_tool("acquire done %d", rv);
		break;

	case ACT_RELEASE:
		rv = direct_release(&to, com.res_args[0], &leader);
		log_tool("release done %d", rv);
		break;

	case ACT_ACQUIRE_ID:
		rv = direct_acquire_id(&to, &com.lockspace);
		log_tool("acquire_id done %d", rv);
		break;

	case ACT_RELEASE_ID:
		rv = direct_release_id(&to, &com.lockspace);
		log_tool("release_id done %d", rv);
		break;

	case ACT_RENEW_ID:
		rv = direct_renew_id(&to, &com.lockspace);
		log_tool("rewew_id done %d", rv);
		break;

	case ACT_READ_ID:
		rv = direct_read_id(&to,
				    &com.lockspace,
				    &timestamp,
				    &owner_id,
				    &owner_generation);

		log_tool("read_id done %d timestamp %llu owner_id %llu owner_generation %llu",
			 rv,
			 (unsigned long long)timestamp,
			 (unsigned long long)owner_id,
			 (unsigned long long)owner_generation);
		break;

	case ACT_LIVE_ID:
		rv = direct_live_id(&to,
				    &com.lockspace,
				    &timestamp,
				    &owner_id,
				    &owner_generation,
				    &live);

		log_tool("live_id done %d live %d timestamp %llu owner_id %llu owner_generation %llu",
			 rv, live,
			 (unsigned long long)timestamp,
			 (unsigned long long)owner_id,
			 (unsigned long long)owner_generation);
		break;

	default:
		log_tool("direct action %d not known", com.action);
		rv = -1;
	}

	return rv;
}

int main(int argc, char *argv[])
{
	int rv;
	
	memset(&com, 0, sizeof(com));
	com.max_hosts = DEFAULT_MAX_HOSTS;
	com.use_watchdog = DEFAULT_USE_WATCHDOG;
	com.high_priority = DEFAULT_HIGH_PRIORITY;
	com.max_worker_threads = DEFAULT_MAX_WORKER_THREADS;
	com.uid = DEFAULT_SOCKET_UID;
	com.gid = DEFAULT_SOCKET_GID;
	com.pid = -1;

	to.use_aio = DEFAULT_USE_AIO;
	to.io_timeout_seconds = DEFAULT_IO_TIMEOUT_SECONDS;
	to.host_id_timeout_seconds = DEFAULT_HOST_ID_TIMEOUT_SECONDS;
	to.host_id_renewal_seconds = DEFAULT_HOST_ID_RENEWAL_SECONDS;
	to.host_id_renewal_fail_seconds = DEFAULT_HOST_ID_RENEWAL_FAIL_SECONDS;
	to.host_id_renewal_warn_seconds = DEFAULT_HOST_ID_RENEWAL_WARN_SECONDS;

	/* com and to values can be altered via command line options */

	rv = read_command_line(argc, argv);
	if (rv < 0)
		goto out;

	switch (com.type) {
	case COM_DAEMON:
		rv = do_daemon();
		break;

	case COM_CLIENT:
		rv = do_client();
		break;

	case COM_DIRECT:
		rv = do_direct();
		break;
	};
 out:
	return rv;
}

