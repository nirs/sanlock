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
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <uuid/uuid.h>
#include <sys/eventfd.h>

#define EXTERN
#include "sanlock_internal.h"
#include "sanlock_sock.h"
#include "sanlock_resource.h"
#include "sanlock_admin.h"
#include "diskio.h"
#include "log.h"
#include "lockspace.h"
#include "resource.h"
#include "direct.h"
#include "lockfile.h"
#include "watchdog.h"
#include "task.h"
#include "client_cmd.h"
#include "cmd.h"
#include "helper.h"
#include "timeouts.h"
#include "paxos_lease.h"

#define SIGRUNPATH 100 /* anything that's not SIGTERM/SIGKILL */

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

/* priorities are LOG_* from syslog.h */
int log_logfile_priority = LOG_WARNING;
int log_logfile_use_utc = 0;
int log_syslog_priority = LOG_ERR;
int log_stderr_priority = -1; /* -D sets this to LOG_DEBUG */

#define CLIENT_NALLOC 1024
static int client_maxi;
static int client_size = 0;
static struct pollfd *pollfd;
static char command[COMMAND_MAX];
static int cmd_argc;
static char **cmd_argv;
static struct thread_pool pool;
static struct random_data rand_data;
static char rand_state[32];
static pthread_mutex_t rand_mutex = PTHREAD_MUTEX_INITIALIZER;

static void close_helper(void)
{
	close(helper_kill_fd);
	close(helper_status_fd);
	helper_kill_fd = -1;
	helper_status_fd = -1;
	pollfd[helper_ci].fd = -1;
	pollfd[helper_ci].events = 0;
	helper_ci = -1;

	/* don't set helper_pid = -1 until we've tried waitpid */
}

/*
 * We cannot block the main thread on this write, so the pipe is
 * NONBLOCK, and write fails with EAGAIN when the pipe is full.
 * With 512 msg size and 64k default pipe size, the pipe will be full
 * if we quickly send kill messages for 128 pids.  We retry
 * the kill once a second, so we'll retry the write again in
 * a second.
 *
 * By setting the pipe size to 1MB in setup_helper, we could quickly send 2048
 * msgs before getting EAGAIN.
 */

static void send_helper_kill(struct space *sp, struct client *cl, int sig)
{
	struct helper_msg hm;
	int rv;

	/*
	 * We come through here once a second while the pid still has
	 * leases.  We only send a single RUNPATH message, so after
	 * the first RUNPATH goes through we set CL_RUNPATH_SENT to
	 * avoid futher RUNPATH's.
	 */

	if ((cl->flags & CL_RUNPATH_SENT) && (sig == SIGRUNPATH))
		return;

	if (helper_kill_fd == -1) {
		log_error("send_helper_kill pid %d no fd", cl->pid);
		return;
	}

	memset(&hm, 0, sizeof(hm));

	if (sig == SIGRUNPATH) {
		hm.type = HELPER_MSG_RUNPATH;
		memcpy(hm.path, cl->killpath, SANLK_HELPER_PATH_LEN);
		memcpy(hm.args, cl->killargs, SANLK_HELPER_ARGS_LEN);

		/* only include pid if it's requested as a killpath arg */
		if (cl->flags & CL_KILLPATH_PID)
			hm.pid = cl->pid;
	} else {
		hm.type = HELPER_MSG_KILLPID;
		hm.sig = sig;
		hm.pid = cl->pid;
	}

	log_erros(sp, "kill %d sig %d count %d", cl->pid, sig, cl->kill_count);

 retry:
	rv = write(helper_kill_fd, &hm, sizeof(hm));
	if (rv == -1 && errno == EINTR)
		goto retry;

	/* pipe is full, we'll try again in a second */
	if (rv == -1 && errno == EAGAIN) {
		helper_full_count++;
		log_space(sp, "send_helper_kill pid %d sig %d full_count %u",
			  cl->pid, sig, helper_full_count);
		return;
	}

	/* helper exited or closed fd, quit using helper */
	if (rv == -1 && errno == EPIPE) {
		log_erros(sp, "send_helper_kill EPIPE");
		close_helper();
		return;
	}

	if (rv != sizeof(hm)) {
		/* this shouldn't happen */
		log_erros(sp, "send_helper_kill pid %d error %d %d",
			  cl->pid, rv, errno);
		close_helper();
		return;
	}

	if (sig == SIGRUNPATH)
		cl->flags |= CL_RUNPATH_SENT;
}

/* FIXME: add a mutex for client array so we don't try to expand it
   while a cmd thread is using it.  Or, with a thread pool we know
   when cmd threads are running and can expand when none are. */

static int client_alloc(void)
{
	int i;

	/* pollfd is one element longer as we use an additional element for the
	 * eventfd notification mechanism */
	client = malloc(CLIENT_NALLOC * sizeof(struct client));
	pollfd = malloc((CLIENT_NALLOC+1) * sizeof(struct pollfd));

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
		log_debug("client_free ci %d is suspended", ci);
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
	cl->kill_count = 0;
	cl->kill_last = 0;
	cl->restricted = 0;
	cl->flags = 0;
	memset(cl->owner_name, 0, sizeof(cl->owner_name));
	memset(cl->killpath, 0, SANLK_HELPER_PATH_LEN);
	memset(cl->killargs, 0, SANLK_HELPER_ARGS_LEN);
	cl->workfn = NULL;
	cl->deadfn = NULL;

	if (cl->tokens)
		free(cl->tokens);
	cl->tokens = NULL;
	cl->tokens_slots = 0;

	/* make poll() ignore this connection */
	pollfd[ci].fd = -1;
	pollfd[ci].events = 0;
 out:
	return;
}

void client_free(int ci);
void client_free(int ci)
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

void client_resume(int ci);
void client_resume(int ci)
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
		log_debug("client_resume ci %d need_free", ci);
		_client_free(ci);
	} else {
		/* make poll() watch this connection */
		pollfd[ci].fd = cl->fd;
		pollfd[ci].events = POLLIN;

		/* interrupt any poll() that might already be running */
		eventfd_write(efd, 1);
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

/* clear the unreceived portion of an aborted command */

void client_recv_all(int ci, struct sm_header *h_recv, int pos);
void client_recv_all(int ci, struct sm_header *h_recv, int pos)
{
	char trash[64];
	int rem = h_recv->length - sizeof(struct sm_header) - pos;
	int rv, error = 0, total = 0, retries = 0;

	if (!rem)
		return;

	while (1) {
		rv = recv(client[ci].fd, trash, sizeof(trash), MSG_DONTWAIT);

		if (rv == -1 && errno == EAGAIN) {
			usleep(1000);
			if (retries < 20) {
				retries++;
				continue;
			}
		}

		if (rv == -1)
			error = errno;
		if (rv <= 0)
			break;
		total += rv;

		if (total >= rem)
			break;
	}

	log_debug("recv_all %d,%d,%d pos %d rv %d error %d retries %d rem %d total %d",
		  ci, client[ci].fd, client[ci].pid, pos, rv, error, retries, rem, total);
}

void send_result(int fd, struct sm_header *h_recv, int result);
void send_result(int fd, struct sm_header *h_recv, int result)
{
	struct sm_header h;

	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.version = SM_PROTO;
	h.length = sizeof(h);
	h.data = result;
	h.data2 = 0;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);
}

void client_pid_dead(int ci);
void client_pid_dead(int ci)
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

	if (cl->kill_count)
		log_error("dead %d ci %d count %d", cl->pid, ci, cl->kill_count);

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

	/* it would be nice to do this SIGKILL as a confirmation that the pid
	   is really gone (i.e. didn't just close the fd) if we always had root
	   permission to do it */

	/* kill(pid, SIGKILL); */

	if (cmd_active) {
		log_debug("client_pid_dead %d,%d,%d defer to cmd %d",
			  ci, cl->fd, pid, cmd_active);
		return;
	}

	/* use async release here because this is the main thread that we don't
	   want to block doing disk lease i/o */

	pthread_mutex_lock(&cl->mutex);
	for (i = 0; i < cl->tokens_slots; i++) {
		if (cl->tokens[i]) {
			release_token_async(cl->tokens[i]);
			free(cl->tokens[i]);
		}
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

	for (i = 0; i < cl->tokens_slots; i++) {
		token = cl->tokens[i];
		if (!token)
			continue;
		if (strncmp(token->r.lockspace_name, sp->space_name, NAME_ID_SIZE))
			continue;

		if (!cl->kill_count)
			log_token(token, "client_using_space pid %d", cl->pid);
		if (sp->space_dead)
			token->space_dead = sp->space_dead;
		rv = 1;
	}
	return rv;
}

static void kill_pids(struct space *sp)
{
	struct client *cl;
	uint64_t now, last_success;
	int id_renewal_fail_seconds;
	int ci, sig;
	int do_kill, in_grace;

	/*
	 * all remaining pids using sp are stuck, we've made max attempts to
	 * kill all, don't bother cycling through them
	 */
	if (sp->killing_pids > 1)
		return;

	id_renewal_fail_seconds = calc_id_renewal_fail_seconds(sp->io_timeout);

	/*
	 * If we happen to renew our lease after we've started killing pids,
	 * the period we allow for graceful shutdown will be extended. This
	 * is an incidental effect, although it may be nice. The previous
	 * behavior would still be ok, where we only ever allow up to
	 * kill_grace_seconds for graceful shutdown before moving to sigkill.
	 */
	pthread_mutex_lock(&sp->mutex);
	last_success = sp->lease_status.renewal_last_success;
	pthread_mutex_unlock(&sp->mutex);

	now = monotime();

	for (ci = 0; ci <= client_maxi; ci++) {
		do_kill = 0;

		cl = &client[ci];
		pthread_mutex_lock(&cl->mutex);

		if (!cl->used)
			goto unlock;

		if (cl->pid <= 0)
			goto unlock;

		/* NB this cl may not be using sp, but trying to
		   avoid the expensive client_using_space check */

		if (cl->kill_count >= kill_count_max)
			goto unlock;

		if (cl->kill_count && (now - cl->kill_last < 1))
			goto unlock;

		if (!client_using_space(cl, sp))
			goto unlock;

		cl->kill_last = now;
		cl->kill_count++;

		/*
		 * the transition from using killpath/sigterm to sigkill
		 * is when now >=
		 * last successful lease renewal +
		 * id_renewal_fail_seconds +
		 * kill_grace_seconds
		 */

		in_grace = now < (last_success + id_renewal_fail_seconds + kill_grace_seconds);

		if (sp->external_remove || (external_shutdown > 1)) {
			sig = SIGKILL;
		} else if ((kill_grace_seconds > 0) && in_grace && cl->killpath[0]) {
			sig = SIGRUNPATH;
		} else if (in_grace) {
			sig = SIGTERM;
		} else {
			sig = SIGKILL;
		}

		/*
		 * sigterm will be used in place of sigkill if restricted
		 * sigkill will be used in place of sigterm if restricted
		 */

		if ((sig == SIGKILL) && (cl->restricted & SANLK_RESTRICT_SIGKILL))
			sig = SIGTERM;

		if ((sig == SIGTERM) && (cl->restricted & SANLK_RESTRICT_SIGTERM))
			sig = SIGKILL;

		do_kill = 1;
 unlock:
		pthread_mutex_unlock(&cl->mutex);

		if (!do_kill)
			continue;

		send_helper_kill(sp, cl, sig);
	}
}

static int all_pids_dead(struct space *sp)
{
	struct client *cl;
	int stuck = 0, check = 0;
	int ci;

	for (ci = 0; ci <= client_maxi; ci++) {
		cl = &client[ci];
		pthread_mutex_lock(&cl->mutex);

		if (!cl->used)
			goto unlock;
		if (cl->pid <= 0)
			goto unlock;
		if (!client_using_space(cl, sp))
			goto unlock;

		if (cl->kill_count >= kill_count_max)
			stuck++;
		else
			check++;
 unlock:
		pthread_mutex_unlock(&cl->mutex);
	}

	if (stuck && !check && sp->killing_pids < 2) {
		log_erros(sp, "killing pids stuck %d", stuck);
		/* cause kill_pids to give up */
		sp->killing_pids = 2;
	}

	if (stuck || check)
		return 0;

	if (sp->flags & SP_EXTERNAL_USED) {
		if (!sp->used_retries || !(sp->used_retries % 1000))
			log_erros(sp, "used external blocking lockspace removal");
		sp->used_retries++;
		return 0;
	}

	if (sp->flags & SP_USED_BY_ORPHANS) {
		/*
		 * lock ordering: spaces_mutex (main_loop), then
		 * resource_mutex (resource_orphan_count)
		 */
		int orphans = resource_orphan_count(sp->space_name);
		if (orphans) {
			if (!sp->used_retries || !(sp->used_retries % 1000))
				log_erros(sp, "used by orphan %d blocking lockspace removal", orphans);
			sp->used_retries++;
			return 0;
		}
	}

	if (sp->renew_fail || sp->used_retries)
		log_erros(sp, "all pids clear");
	else
		log_space(sp, "all pids clear");

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
	int i, rv, empty, check_all;
	char *check_buf = NULL;
	int check_buf_len = 0;
	uint64_t ebuf;

	gettimeofday(&last_check, NULL);
	poll_timeout = STANDARD_CHECK_INTERVAL;
	check_interval = STANDARD_CHECK_INTERVAL;

	while (1) {
		/* as well as the clients, check the eventfd */
		pollfd[client_maxi+1].fd = efd;
		pollfd[client_maxi+1].events = POLLIN;

		rv = poll(pollfd, client_maxi + 2, poll_timeout);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0) {
			/* not sure */
		}
		for (i = 0; i <= client_maxi + 1; i++) {
			if (pollfd[i].fd == efd && pollfd[i].revents & POLLIN) {
				/* a client_resume completed */
				eventfd_read(efd, &ebuf);
				continue;
			}
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
		check_interval = STANDARD_CHECK_INTERVAL;

		/*
		 * check the condition of each lockspace,
		 * if pids are being killed, have pids all exited?
		 * is its host_id being renewed?, if not kill pids
		 */

		pthread_mutex_lock(&spaces_mutex);
		list_for_each_entry_safe(sp, safe, &spaces, list) {

			if (sp->killing_pids && all_pids_dead(sp)) {
				/*
				 * move sp to spaces_rem so main_loop
				 * will no longer see it.
				 */
				log_space(sp, "set thread_stop");
				pthread_mutex_lock(&sp->mutex);
				sp->thread_stop = 1;
				deactivate_watchdog(sp);
				pthread_mutex_unlock(&sp->mutex);
				list_move(&sp->list, &spaces_rem);
				continue;
			}

			if (sp->killing_pids) {
				/*
				 * continue to kill the pids with increasing
				 * levels of severity until they all exit
				 */
				kill_pids(sp);
				check_interval = RECOVERY_CHECK_INTERVAL;
				continue;
			}

			/*
			 * check host_id lease renewal
			 */

			if (sp->align_size > check_buf_len) {
				if (check_buf)
					free(check_buf);
				check_buf_len = sp->align_size;
				check_buf = malloc(check_buf_len);
			}
			if (check_buf)
				memset(check_buf, 0, check_buf_len);

			check_all = 0;

			rv = check_our_lease(sp, &check_all, check_buf);
			if (rv)
				sp->renew_fail = 1;

			if (rv || sp->external_remove || (external_shutdown > 1)) {
				log_space(sp, "set killing_pids check %d remove %d",
					  rv, sp->external_remove);
				sp->space_dead = 1;
				sp->killing_pids = 1;
				kill_pids(sp);
				check_interval = RECOVERY_CHECK_INTERVAL;

			} else if (check_all) {
				check_other_leases(sp, check_buf);
			}
		}
		empty = list_empty(&spaces);
		pthread_mutex_unlock(&spaces_mutex);

		if (external_shutdown && empty)
			break;

		if (external_shutdown == 1) {
			log_debug("ignore shutdown, lockspace exists");
			external_shutdown = 0;
		}

		free_lockspaces(0);
		rem_resources();

		gettimeofday(&now, NULL);
		ms = time_diff(&last_check, &now);
		if (ms < check_interval)
			poll_timeout = check_interval - ms;
		else
			poll_timeout = 1;
	}

	free_lockspaces(1);

	daemon_shutdown_reply();

	return 0;
}

static void *thread_pool_worker(void *data)
{
	struct task task;
	struct cmd_args *ca;

	memset(&task, 0, sizeof(struct task));
	setup_task_aio(&task, main_task.use_aio, WORKER_AIO_CB_SIZE);
	snprintf(task.name, NAME_ID_SIZE, "worker%ld", (long)data);

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

			call_cmd_thread(&task, ca);
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

	close_task_aio(&task);
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
		rv = pthread_create(&th, NULL, thread_pool_worker,
				    (void *)(long)pool.num_workers);
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
		rv = pthread_create(&th, NULL, thread_pool_worker,
				    (void *)(long)i);
		if (rv < 0)
			break;
		pool.num_workers++;
	}

	if (rv < 0)
		thread_pool_free();

	return rv;
}

/*
 * cmd comes from a transient client/fd set up just to pass the cmd,
 * and is not being done on behalf of another registered client/fd.
 * The command is processed independently of the lifetime of a specific
 * client or the tokens held by a specific client.
 */

static void process_cmd_thread_unregistered(int ci_in, struct sm_header *h_recv)
{
	struct cmd_args *ca;
	int rv;

	ca = malloc(sizeof(struct cmd_args));
	if (!ca) {
		rv = -ENOMEM;
		goto fail;
	}
	ca->ci_in = ci_in;
	memcpy(&ca->header, h_recv, sizeof(struct sm_header));

	snprintf(client[ci_in].owner_name, SANLK_NAME_LEN, "cmd%d", h_recv->cmd);

	rv = thread_pool_add_work(ca);
	if (rv < 0)
		goto fail_free;
	return;

 fail_free:
	free(ca);
 fail:
	send_result(client[ci_in].fd, h_recv, rv);
	close(client[ci_in].fd);
}

/*
 * cmd either comes from a registered client/fd, or is targeting a registered
 * client/fd.  The processing of the cmd is closely coordinated with the
 * lifetime of a specific client and to tokens held by that client.  Handling
 * of the client's death or changing of the client's tokens will be serialized
 * with the processing of this command.  This means that the end of processing
 * this command needs to check if the client failed during the command
 * processing and handle the cleanup of the client if so.
 */

static void process_cmd_thread_registered(int ci_in, struct sm_header *h_recv)
{
	struct cmd_args *ca;
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
			if (h_recv->cmd != SM_CMD_INQUIRE) {
				/* inquire can be used to check if a pid exists */
				log_error("cmd %d target pid %d not found",
					  h_recv->cmd, h_recv->data2);
			}
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

	if (cl->kill_count && h_recv->cmd == SM_CMD_ACQUIRE) {
		/* when pid is being killed, we want killpath to be able
		   to inquire and release for it */
		log_error("cmd %d %d,%d,%d kill_count %d",
			  h_recv->cmd, ci_target, cl->fd, cl->pid, cl->kill_count);
		result = -EBUSY;
		goto out;
	}

	if (cl->cmd_active) {
		if (com.quiet_fail && cl->cmd_active == SM_CMD_ACQUIRE) {
			result = -EBUSY;
			goto out;
		}
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
	client_recv_all(ci_in, h_recv, 0);
	send_result(client[ci_in].fd, h_recv, result);
	client_resume(ci_in);

	if (ca)
		free(ca);
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
		log_error("ci %d fd %d pid %d recv errno %d",
			  ci, client[ci].fd, client[ci].pid, errno);
		goto dead;
	}
	if (rv != sizeof(h)) {
		log_error("ci %d fd %d pid %d recv size %d",
			  ci, client[ci].fd, client[ci].pid, rv);
		goto dead;
	}
	if (h.magic != SM_MAGIC) {
		log_error("ci %d recv %d magic %x vs %x",
			  ci, rv, h.magic, SM_MAGIC);
		goto dead;
	}
	if (client[ci].restricted & SANLK_RESTRICT_ALL) {
		log_error("ci %d fd %d pid %d cmd %d restrict all",
			  ci, client[ci].fd, client[ci].pid, h.cmd);
		goto dead;
	}
	if (h.version && (h.cmd != SM_CMD_VERSION) &&
	    (h.version & 0xFFFF0000) > (SM_PROTO & 0xFFFF0000)) {
		log_error("ci %d recv %d proto %x vs %x",
			  ci, rv, h.version , SM_PROTO);
		goto dead;
	}

	client[ci].cmd_last = h.cmd;

	switch (h.cmd) {
	case SM_CMD_REGISTER:
	case SM_CMD_RESTRICT:
	case SM_CMD_VERSION:
	case SM_CMD_SHUTDOWN:
	case SM_CMD_STATUS:
	case SM_CMD_HOST_STATUS:
	case SM_CMD_RENEWAL:
	case SM_CMD_LOG_DUMP:
	case SM_CMD_GET_LOCKSPACES:
	case SM_CMD_GET_HOSTS:
	case SM_CMD_REG_EVENT:
	case SM_CMD_END_EVENT:
	case SM_CMD_SET_CONFIG:
		call_cmd_daemon(ci, &h, client_maxi);
		break;
	case SM_CMD_ADD_LOCKSPACE:
	case SM_CMD_INQ_LOCKSPACE:
	case SM_CMD_REM_LOCKSPACE:
	case SM_CMD_REQUEST:
	case SM_CMD_EXAMINE_RESOURCE:
	case SM_CMD_EXAMINE_LOCKSPACE:
	case SM_CMD_ALIGN:
	case SM_CMD_WRITE_LOCKSPACE:
	case SM_CMD_WRITE_RESOURCE:
	case SM_CMD_READ_LOCKSPACE:
	case SM_CMD_READ_RESOURCE:
	case SM_CMD_READ_RESOURCE_OWNERS:
	case SM_CMD_SET_LVB:
	case SM_CMD_GET_LVB:
	case SM_CMD_SHUTDOWN_WAIT:
	case SM_CMD_SET_EVENT:
		rv = client_suspend(ci);
		if (rv < 0)
			return;
		process_cmd_thread_unregistered(ci, &h);
		break;
	case SM_CMD_ACQUIRE:
	case SM_CMD_RELEASE:
	case SM_CMD_INQUIRE:
	case SM_CMD_CONVERT:
	case SM_CMD_KILLPATH:
		/* the main_loop needs to ignore this connection
		   while the thread is working on it */
		rv = client_suspend(ci);
		if (rv < 0)
			return;
		process_cmd_thread_registered(ci, &h);
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
	struct sockaddr_un addr;
	int rv, fd, ci;

	rv = sanlock_socket_address(SANLK_RUN_DIR, &addr);
	if (rv < 0)
		return rv;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	unlink(addr.sun_path);
	rv = bind(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (rv < 0)
		goto exit_fail;

	rv = chmod(addr.sun_path, DEFAULT_SOCKET_MODE);
	if (rv < 0)
		goto exit_fail;

	rv = chown(addr.sun_path, com.uid, com.gid);
	if (rv < 0) {
		log_error("could not set socket %s permissions: %s",
			addr.sun_path, strerror(errno));
		goto exit_fail;
	}

	rv = listen(fd, 5);
	if (rv < 0)
		goto exit_fail;

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	ci = client_add(fd, process_listener, NULL);
	if (ci < 0)
		goto exit_fail;

	strcpy(client[ci].owner_name, "listener");
	return 0;

 exit_fail:
	close(fd);
	return -1;
}

static void sigterm_handler(int sig GNUC_UNUSED,
			    siginfo_t *info GNUC_UNUSED,
			    void *ctx GNUC_UNUSED)
{
	external_shutdown = 1;
}

static void setup_priority(void)
{
	struct sched_param sched_param;
	int rv = 0;

	if (com.mlock_level == 1)
		rv = mlockall(MCL_CURRENT);
	else if (com.mlock_level == 2)
		rv = mlockall(MCL_CURRENT | MCL_FUTURE);

	if (rv < 0) {
		log_error("mlockall %d failed: %s",
			  com.mlock_level, strerror(errno));
	}

	if (!com.high_priority)
		return;

	rv = sched_get_priority_max(SCHED_RR);
	if (rv < 0) {
		log_error("could not get max scheduler priority err %d", errno);
		return;
	}

	sched_param.sched_priority = rv;
	rv = sched_setscheduler(0, SCHED_RR|SCHED_RESET_ON_FORK, &sched_param);
	if (rv < 0) {
		log_error("set scheduler RR|RESET_ON_FORK priority %d failed: %s",
			  sched_param.sched_priority, strerror(errno));
	}
}

/* return a random int between a and b inclusive */

int get_rand(int a, int b);

int get_rand(int a, int b)
{
	int32_t val;
	int rv;

	pthread_mutex_lock(&rand_mutex);
	rv = random_r(&rand_data, &val);
	pthread_mutex_unlock(&rand_mutex);
	if (rv < 0)
		return rv;

	return a + (int) (((float)(b - a + 1)) * val / (RAND_MAX+1.0));
}

static void setup_host_name(void)
{
	struct utsname name;
	char uuid[37];
	uuid_t uu;

	memset(rand_state, 0, sizeof(rand_state));
	memset(&rand_data, 0, sizeof(rand_data));

	initstate_r(time(NULL), rand_state, sizeof(rand_state), &rand_data);

	/* use host name from command line */

	if (com.our_host_name[0]) {
		memcpy(our_host_name_global, com.our_host_name, SANLK_NAME_LEN);
		return;
	}

	/* make up something that's likely to be different among hosts */

	memset(&our_host_name_global, 0, sizeof(our_host_name_global));
	memset(&name, 0, sizeof(name));
	memset(&uuid, 0, sizeof(uuid));

	uname(&name);
	uuid_generate(uu);
	uuid_unparse_lower(uu, uuid);

	snprintf(our_host_name_global, NAME_ID_SIZE, "%s.%s",
		 uuid, name.nodename);
}

static void setup_limits(void)
{
	int rv;
	struct rlimit rlim = { .rlim_cur = -1, .rlim_max= -1 };

	rv = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (rv < 0) {
		log_error("cannot set the limits for memlock %i", errno);
		exit(EXIT_FAILURE);
	}

	rv = setrlimit(RLIMIT_RTPRIO, &rlim);
	if (rv < 0) {
		log_error("cannot set the limits for rtprio %i", errno);
		exit(EXIT_FAILURE);
	}

	rv = setrlimit(RLIMIT_CORE, &rlim);
	if (rv < 0) {
		log_error("cannot set the limits for core dumps %i", errno);
		exit(EXIT_FAILURE);
	}
}

static void setup_groups(void)
{
	int rv;

	if (!com.uname || !com.gname)
		return;

	rv = initgroups(com.uname, com.gid);
	if (rv < 0) {
		log_error("error initializing groups errno %i", errno);
	}
}

static void setup_uid_gid(void)
{
	int rv;

	if (!com.uname || !com.gname)
		return;

	rv = setgid(com.gid);
	if (rv < 0) {
		log_error("cannot set group id to %i errno %i", com.gid, errno);
	}

	rv = setuid(com.uid);
	if (rv < 0) {
		log_error("cannot set user id to %i errno %i", com.uid, errno);
	}

	/* When a program is owned by a user (group) other than the real user
	 * (group) ID of the process, the PR_SET_DUMPABLE option gets cleared.
	 * See RLIMIT_CORE in setup_limits and man 5 core.
	 */
	rv = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	if (rv < 0) {
		log_error("cannot set dumpable process errno %i", errno);
	}
}

static void setup_signals(void)
{
	struct sigaction act;
	int rv, i, sig_list[] = { SIGHUP, SIGINT, SIGTERM, 0 };

	memset(&act, 0, sizeof(act));

	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = sigterm_handler;

	for (i = 0; sig_list[i] != 0; i++) {
		rv = sigaction(sig_list[i], &act, NULL);
		if (rv < 0) {
			log_error("cannot set the signal handler for: %i", sig_list[i]);
			exit(EXIT_FAILURE);
		}
	}
}

/*
 * first pipe for daemon to send requests to helper; they are not acknowledged
 * and the daemon does not get any result back for the requests.
 *
 * second pipe for helper to send general status/heartbeat back to the daemon
 * every so often to confirm it's not dead/hung.  If the helper gets stuck or
 * killed, the daemon will not get the status and won't bother sending requests
 * to the helper, and use SIGTERM instead
 */

static int setup_helper(void)
{
	int pid;
	int pw_fd = -1; /* parent write */
	int cr_fd = -1; /* child read */
	int pr_fd = -1; /* parent read */
	int cw_fd = -1; /* child write */
	int pfd[2];

	/* we can't allow the main daemon thread to block */
	if (pipe2(pfd, O_NONBLOCK | O_CLOEXEC))
		return -errno;

	/* uncomment for rhel7 where this should be available */
	/* fcntl(pfd[1], F_SETPIPE_SZ, 1024*1024); */

	cr_fd = pfd[0];
	pw_fd = pfd[1];

	if (pipe2(pfd, O_NONBLOCK | O_CLOEXEC)) {
		close(cr_fd);
		close(pw_fd);
		return -errno;
	}

	pr_fd = pfd[0];
	cw_fd = pfd[1];

	pid = fork();
	if (pid < 0) {
		close(cr_fd);
		close(pw_fd);
		close(pr_fd);
		close(cw_fd);
		return -errno;
	}

	if (pid) {
		close(cr_fd);
		close(cw_fd);
		helper_kill_fd = pw_fd;
		helper_status_fd = pr_fd;
		helper_pid = pid;
		return 0;
	} else {
		close(pr_fd);
		close(pw_fd);
		run_helper(cr_fd, cw_fd, (log_stderr_priority == LOG_DEBUG));
		exit(0);
	}
}

static void process_helper(int ci)
{
	struct helper_status hs;
	int rv;

	memset(&hs, 0, sizeof(hs));

	rv = read(client[ci].fd, &hs, sizeof(hs));
	if (!rv || rv == -EAGAIN)
		return;
	if (rv < 0) {
		log_error("process_helper rv %d errno %d", rv, errno);
		goto fail;
	}
	if (rv != sizeof(hs)) {
		log_error("process_helper recv size %d", rv);
		goto fail;
	}

	if (hs.type == HELPER_STATUS && !hs.status)
		helper_last_status = monotime();

	return;

 fail:
	close_helper();
}

static void helper_dead(int ci GNUC_UNUSED)
{
	int pid = helper_pid;
	int rv, status;

	close_helper();

	helper_pid = -1;

	rv = waitpid(pid, &status, WNOHANG);

	if (rv != pid) {
		/* should not happen */
		log_error("helper pid %d dead wait %d", pid, rv);
		return;
	}

	if (WIFEXITED(status)) {
		log_error("helper pid %d exit status %d", pid,
			  WEXITSTATUS(status));
		return;
	}

	if (WIFSIGNALED(status)) {
		log_error("helper pid %d term signal %d", pid,
			  WTERMSIG(status));
		return;
	}

	/* should not happen */
	log_error("helper pid %d state change", pid);
}

static int do_daemon(void)
{
	int fd, rv;


	/* This can take a while so do it before forking. */
	setup_groups();

	if (!com.debug) {
		/* TODO: copy comprehensive daemonization method from libvirtd */
		if (daemon(0, 0) < 0) {
			log_tool("cannot fork daemon\n");
			exit(EXIT_FAILURE);
		}
	}

	setup_limits();
	setup_helper();

	/* main task never does disk io, so we don't really need to set
	 * it up, but other tasks get their use_aio value by copying
	 * the main_task settings */

	sprintf(main_task.name, "%s", "main");
	setup_task_aio(&main_task, com.aio_arg, 0);

	rv = client_alloc();
	if (rv < 0)
		return rv;

	helper_ci = client_add(helper_status_fd, process_helper, helper_dead);
	if (helper_ci < 0)
		return rv;
	strcpy(client[helper_ci].owner_name, "helper");

	setup_signals();
	setup_logging();

	fd = lockfile(SANLK_RUN_DIR, SANLK_LOCKFILE_NAME, com.uid, com.gid);
	if (fd < 0) {
		close_logging();
		return fd;
	}

	setup_host_name();

	setup_uid_gid();

	log_warn("sanlock daemon started %s host %s", VERSION, our_host_name_global);

	setup_priority();

	rv = thread_pool_create(DEFAULT_MIN_WORKER_THREADS, com.max_worker_threads);
	if (rv < 0)
		goto out;

	rv = setup_listener();
	if (rv < 0)
		goto out_threads;

	setup_token_manager();
	if (rv < 0)
		goto out_threads;

	/* initialize global eventfd for client_resume notification */
	if ((efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) == -1) {
		log_error("couldn't create eventfd");
		goto out_threads;
	}

	main_loop();

	close_token_manager();

 out_threads:
	thread_pool_free();
 out:
	/* order reversed from setup so lockfile is last */
	close_logging();
	unlink_lockfile(fd, SANLK_RUN_DIR, SANLK_LOCKFILE_NAME);
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
                          "using uid: %i", arg, DEFAULT_SOCKET_GID);
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
	printf("sanlock <command> <action> ...\n\n");

	printf("commands:\n");
	printf("  daemon        start daemon\n");
	printf("  client        send request to daemon (default type if none given)\n");
	printf("  direct        access storage directly (no coordination with daemon)\n");
	printf("  help          print this usage (defaults in parens)\n");
	printf("  version       print version\n");
	printf("\n");
	printf("sanlock daemon [options]\n");
	printf("  -D            no fork and print all logging to stderr\n");
	printf("  -Q 0|1        quiet error messages for common lock contention (%d)\n", DEFAULT_QUIET_FAIL);
	printf("  -R 0|1        renewal debugging, log debug info about renewals (0)\n");
	printf("  -H <num>      renewal history size (%d)\n", DEFAULT_RENEWAL_HISTORY_SIZE);
	printf("  -L <pri>      write logging at priority level and up to logfile (4 LOG_WARNING)\n");
	printf("                (use -1 for none)\n");
	printf("  -S <pri>      write logging at priority level and up to syslog (3 LOG_ERR)\n");
	printf("                (use -1 for none)\n");
	printf("  -U <uid>      user id\n");
	printf("  -G <gid>      group id\n");
	printf("  -t <num>      max worker threads (%d)\n", DEFAULT_MAX_WORKER_THREADS);
	printf("  -g <sec>      seconds for graceful recovery (%d)\n", DEFAULT_GRACE_SEC);
	printf("  -w 0|1        use watchdog through wdmd (%d)\n", DEFAULT_USE_WATCHDOG);
	printf("  -h 0|1        use high priority (RR) scheduling (%d)\n", DEFAULT_HIGH_PRIORITY);
	printf("  -l <num>      use mlockall (0 none, 1 current, 2 current and future) (%d)\n", DEFAULT_MLOCK_LEVEL);
	printf("  -b <sec>      seconds a host id bit will remain set in delta lease bitmap\n");
	printf("                (default: 6 * io_timeout)\n");
	printf("  -e <str>      local host name used in delta leases\n");
	printf("                (default: generate new uuid)\n");
	printf("\n");
	printf("sanlock client <action> [options]\n");
	printf("sanlock client status [-D] [-o p|s]\n");
	printf("sanlock client gets [-h 0|1]\n");
	printf("sanlock client host_status -s LOCKSPACE [-D]\n");
	printf("sanlock client renewal -s LOCKSPACE\n");
	printf("sanlock client set_event -s LOCKSPACE -i <host_id> [-g gen] -e <event> -d <data>\n");
	printf("sanlock client set_config -s LOCKSPACE [-u 0|1] [-O 0|1]\n");
	printf("sanlock client log_dump\n");
	printf("sanlock client shutdown [-f 0|1] [-w 0|1]\n");
	printf("sanlock client init -s LOCKSPACE | -r RESOURCE [-z 0|1] [-Z 512|4096]\n");
	printf("sanlock client read -s LOCKSPACE | -r RESOURCE\n");
	printf("sanlock client align -s LOCKSPACE\n");
	printf("sanlock client add_lockspace -s LOCKSPACE\n");
	printf("sanlock client inq_lockspace -s LOCKSPACE\n");
	printf("sanlock client rem_lockspace -s LOCKSPACE\n");
	printf("sanlock client command -r RESOURCE -c <path> <args>\n");
	printf("sanlock client acquire -r RESOURCE -p <pid>\n");
	printf("sanlock client convert -r RESOURCE -p <pid>\n");
	printf("sanlock client release -r RESOURCE -p <pid>\n");
	printf("sanlock client inquire -p <pid>\n");
	printf("sanlock client request -r RESOURCE -f <force_mode>\n");
	printf("sanlock client examine -r RESOURCE | -s LOCKSPACE\n");
	printf("\n");
	printf("sanlock direct <action> [-a 0|1] [-o 0|1] [-Z 512|4096]\n");
	printf("sanlock direct init -s LOCKSPACE | -r RESOURCE\n");
	printf("sanlock direct read_leader -s LOCKSPACE | -r RESOURCE\n");
	printf("sanlock direct dump <path>[:<offset>[:<size>]]\n");
	printf("\n");
	printf("LOCKSPACE = <lockspace_name>:<host_id>:<path>:<offset>\n");
	printf("  <lockspace_name>	name of lockspace\n");
	printf("  <host_id>		local host identifier in lockspace\n");
	printf("  <path>		path to storage reserved for leases\n");
	printf("  <offset>		offset on path (bytes)\n");
	printf("\n");
	printf("RESOURCE = <lockspace_name>:<resource_name>:<path>:<offset>[:<lver>]\n");
	printf("  <lockspace_name>	name of lockspace\n");
	printf("  <resource_name>	name of resource\n");
	printf("  <path>		path to storage reserved for leases\n");
	printf("  <offset>		offset on path (bytes)\n");
	printf("  <lver>                optional leader version or SH for shared lease\n");
	printf("\n");
	printf("Limits:\n");
	printf("offset alignment with 512 byte sectors: %d (1MB)\n", 1024 * 1024);
	printf("offset alignment with 4096 byte sectors: %d (8MB)\n", 1024 * 1024 * 8);
	printf("maximum name length for lockspaces and resources: %d\n", SANLK_NAME_LEN);
	printf("maximum path length: %d\n", SANLK_PATH_LEN);
	printf("maximum host_id: %d\n", DEFAULT_MAX_HOSTS);
	printf("maximum client process connections: 1000\n"); /* NALLOC */
	printf("\n");
}

static int read_command_line(int argc, char *argv[])
{
	char optchar;
	char *optionarg;
	char *p;
	char *arg1 = argv[1];
	char *act;
	int i, j, len, sec, begin_command = 0;

	if (argc < 2 || !strcmp(arg1, "help") || !strcmp(arg1, "--help") ||
	    !strcmp(arg1, "-h")) {
		print_usage();
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "version")) {
		printf("%u.%u.%u\n",
		       sanlock_version_major, sanlock_version_minor,
		       sanlock_version_patch);
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "--version") || !strcmp(arg1, "-V")) {
		printf("%s %s (built %s %s)\n",
		       argv[0], VERSION, __DATE__, __TIME__);
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
		else if (!strcmp(act, "host_status"))
			com.action = ACT_HOST_STATUS;
		else if (!strcmp(act, "renewal"))
			com.action = ACT_RENEWAL;
		else if (!strcmp(act, "gets"))
			com.action = ACT_GETS;
		else if (!strcmp(act, "log_dump"))
			com.action = ACT_LOG_DUMP;
		else if (!strcmp(act, "shutdown"))
			com.action = ACT_SHUTDOWN;
		else if (!strcmp(act, "add_lockspace"))
			com.action = ACT_ADD_LOCKSPACE;
		else if (!strcmp(act, "inq_lockspace"))
			com.action = ACT_INQ_LOCKSPACE;
		else if (!strcmp(act, "rem_lockspace"))
			com.action = ACT_REM_LOCKSPACE;
		else if (!strcmp(act, "command"))
			com.action = ACT_COMMAND;
		else if (!strcmp(act, "acquire"))
			com.action = ACT_ACQUIRE;
		else if (!strcmp(act, "convert"))
			com.action = ACT_CONVERT;
		else if (!strcmp(act, "release"))
			com.action = ACT_RELEASE;
		else if (!strcmp(act, "inquire"))
			com.action = ACT_INQUIRE;
		else if (!strcmp(act, "request"))
			com.action = ACT_REQUEST;
		else if (!strcmp(act, "examine"))
			com.action = ACT_EXAMINE;
		else if (!strcmp(act, "align"))
			com.action = ACT_CLIENT_ALIGN;
		else if (!strcmp(act, "init"))
			com.action = ACT_CLIENT_INIT;
		else if (!strcmp(act, "write"))
			com.action = ACT_CLIENT_INIT;
		else if (!strcmp(act, "read"))
			com.action = ACT_CLIENT_READ;
		else if (!strcmp(act, "version"))
			com.action = ACT_VERSION;
		else if (!strcmp(act, "set_event"))
			com.action = ACT_SET_EVENT;
		else if (!strcmp(act, "set_config"))
			com.action = ACT_SET_CONFIG;
		else {
			log_tool("client action \"%s\" is unknown", act);
			exit(EXIT_FAILURE);
		}
		break;

	case COM_DIRECT:
		if (!strcmp(act, "init"))
			com.action = ACT_DIRECT_INIT;
		else if (!strcmp(act, "dump"))
			com.action = ACT_DUMP;
		else if (!strcmp(act, "next_free"))
			com.action = ACT_NEXT_FREE;
		else if (!strcmp(act, "read_leader"))
			com.action = ACT_READ_LEADER;
		else if (!strcmp(act, "write_leader"))
			com.action = ACT_WRITE_LEADER;
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
		else {
			log_tool("direct action \"%s\" is unknown", act);
			exit(EXIT_FAILURE);
		}
		break;
	};


	/* actions that have an option without dash-letter prefix */
	if (com.action == ACT_DUMP || com.action == ACT_NEXT_FREE) {
		if (argc < 4)
			exit(EXIT_FAILURE);
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
		case 'H':
			com.renewal_history_size = atoi(optionarg);
			break;
		case 'L':
			log_logfile_priority = atoi(optionarg);
			break;
		case 'S':
			log_syslog_priority = atoi(optionarg);
			break;
		case 'F':
			com.file_path = strdup(optionarg);
			break;
		case 'a':
			com.all = atoi(optionarg);
			com.aio_arg = atoi(optionarg);
			if (com.aio_arg && com.aio_arg != 1)
				com.aio_arg = 1;
			break;
		case 't':
			com.max_worker_threads = atoi(optionarg);
			if (com.max_worker_threads < DEFAULT_MIN_WORKER_THREADS)
				com.max_worker_threads = DEFAULT_MIN_WORKER_THREADS;
			break;
		case 'w':
			com.use_watchdog = atoi(optionarg);
			com.wait = atoi(optionarg);
			break;
		case 'h':
			if (com.action == ACT_GETS || com.action == ACT_CLIENT_READ)
				com.get_hosts = atoi(optionarg);
			else
				com.high_priority = atoi(optionarg);
			break;
		case 'l':
			com.mlock_level = atoi(optionarg);
			break;
		case 'o':
			if (com.action == ACT_STATUS) {
				com.sort_arg = *optionarg;
			} else {
				com.io_timeout_arg = atoi(optionarg);
				if (!com.io_timeout_arg)
					com.io_timeout_arg = DEFAULT_IO_TIMEOUT;
			}
			break;
		case 'b':
			com.set_bitmap_seconds = atoi(optionarg);
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
		case 'd':
			com.he_data = strtoull(optionarg, NULL, 0);
			break;
		case 'e':
			strncpy(com.our_host_name, optionarg, NAME_ID_SIZE);
			com.he_event = strtoull(optionarg, NULL, 0);
			break;
		case 'i':
			com.host_id = strtoull(optionarg, NULL, 0);
			break;
		case 'g':
			if (com.type == COM_DAEMON) {
				sec = atoi(optionarg);
				if (sec <= 60 && sec >= 0)
					kill_grace_seconds = sec;
			} else {
				com.host_generation = strtoull(optionarg, NULL, 0);
			}
			break;
		case 'f':
			com.force_mode = strtoul(optionarg, NULL, 0);
			break;
		case 's':
			parse_arg_lockspace(optionarg); /* com.lockspace */
			break;
		case 'r':
			parse_arg_resource(optionarg); /* com.res_args[] */
			break;
		case 'U':
			com.uname = optionarg;
			com.uid = user_to_uid(optionarg);
			break;
		case 'G':
			com.gname = optionarg;
			com.gid = group_to_gid(optionarg);
			break;
		case 'O':
			com.orphan_set = 1;
			com.orphan = atoi(optionarg);
			break;
		case 'P':
			com.persistent = atoi(optionarg);
			break;
		case 'u':
			com.used_set = 1;
			com.used = atoi(optionarg);
			break;
		case 'z':
			com.clear_arg = 1;
			break;

		case 'c':
			begin_command = 1;
			break;

		case 'Z':
			com.sector_size = atoi(optionarg);
			if ((com.sector_size != 512) && (com.sector_size != 4096))
				com.sector_size = 0;
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

#define MAX_CONF_LINE 128

static void get_val_int(char *line, int *val_out)
{
	char key[MAX_CONF_LINE];
	char val[MAX_CONF_LINE];
	int rv;

	rv = sscanf(line, "%[^=]=%s", key, val);
	if (rv != 2)
		return;

	*val_out = atoi(val);
}

static void get_val_str(char *line, char *val_out)
{
	char key[MAX_CONF_LINE];
	char val[MAX_CONF_LINE];
	int rv;

	rv = sscanf(line, "%[^=]=%s", key, val);
	if (rv != 2)
		return;

	strcpy(val_out, val);
}

static void read_config_file(void)
{
	FILE *file;
	struct stat buf;
	char line[MAX_CONF_LINE];
	char str[MAX_CONF_LINE];
	int i, val;

	if (stat(SANLK_CONF_PATH, &buf) < 0) {
		if (errno != ENOENT)
			log_error("%s stat failed: %d", SANLK_CONF_PATH, errno);
		return;
	}

	file = fopen(SANLK_CONF_PATH, "r");
	if (!file)
		return;

	while (fgets(line, MAX_CONF_LINE, file)) {
		if (line[0] == '#')
			continue;
		if (line[0] == '\n')
			continue;

		memset(str, 0, sizeof(str));

		for (i = 0; i < MAX_CONF_LINE; i++) {
			if (line[i] == ' ')
				break;
			if (line[i] == '=')
				break;
			if (line[i] == '\0')
				break;
			if (line[i] == '\n')
				break;
			if (line[i] == '\t')
				break;
			str[i] = line[i];
		}

		if (!strcmp(str, "quiet_fail")) {
			get_val_int(line, &val);
			com.quiet_fail = val;

		} else if (!strcmp(str, "debug_renew")) {
			get_val_int(line, &val);
			com.debug_renew = val;

		} else if (!strcmp(str, "logfile_priority")) {
			get_val_int(line, &val);
			log_logfile_priority = val;

		} else if (!strcmp(str, "logfile_use_utc")) {
			get_val_int(line, &val);
			log_logfile_use_utc = val;

		} else if (!strcmp(str, "syslog_priority")) {
			get_val_int(line, &val);
			log_syslog_priority = val;

		} else if (!strcmp(str, "names_log_priority")) {
			get_val_int(line, &val);
			com.names_log_priority = val;

		} else if (!strcmp(str, "use_watchdog")) {
			get_val_int(line, &val);
			com.use_watchdog = val;

		} else if (!strcmp(str, "high_priority")) {
			get_val_int(line, &val);
			com.high_priority = val;

		} else if (!strcmp(str, "mlock_level")) {
			get_val_int(line, &val);
			com.mlock_level = val;

		} else if (!strcmp(str, "sh_retries")) {
			get_val_int(line, &val);
			com.sh_retries = val;

		} else if (!strcmp(str, "uname")) {
			memset(str, 0, sizeof(str));
			get_val_str(line, str);
			com.uname = strdup(str);
			com.uid = user_to_uid(str);

		} else if (!strcmp(str, "gname")) {
			memset(str, 0, sizeof(str));
			get_val_str(line, str);
			com.gname = strdup(str);
			com.gid = group_to_gid(str);

		} else if (!strcmp(str, "our_host_name")) {
			memset(str, 0, sizeof(str));
			get_val_str(line, str);
			strncpy(com.our_host_name, str, NAME_ID_SIZE);

		} else if (!strcmp(str, "renewal_read_extend_sec")) {
			/* zero is a valid setting so we need the _set field to say it's set */
			get_val_int(line, &val);
			com.renewal_read_extend_sec_set = 1;
			com.renewal_read_extend_sec = val;

		} else if (!strcmp(str, "renewal_history_size")) {
			get_val_int(line, &val);
			com.renewal_history_size = val;

		} else if (!strcmp(str, "paxos_debug_all")) {
			get_val_int(line, &val);
			com.paxos_debug_all = val;

		} else if (!strcmp(str, "debug_io")) {
			memset(str, 0, sizeof(str));
			get_val_str(line, str);
			if (strstr(str, "submit"))
				com.debug_io_submit = 1;
			if (strstr(str, "complete"))
				com.debug_io_complete = 1;
		}
	}

	fclose(file);
}

/* only used by do_client */
static char *lsf_to_str(uint32_t flags)
{
	static char lsf_str[16];

	memset(lsf_str, 0, 16);

	if (flags & SANLK_LSF_ADD)
		strcat(lsf_str, "ADD ");

	if (flags & SANLK_LSF_REM)
		strcat(lsf_str, "REM ");

	return lsf_str;
}

static const char *host_state_str(uint32_t flags)
{
	int val = flags & SANLK_HOST_MASK;

	if (val == SANLK_HOST_FREE)
		return "FREE";
	if (val == SANLK_HOST_LIVE)
		return "LIVE";
	if (val == SANLK_HOST_FAIL)
		return "FAIL";
	if (val == SANLK_HOST_DEAD)
		return "DEAD";
	if (val == SANLK_HOST_UNKNOWN)
		return "UNKNOWN";
	return "ERROR";
}

static int do_client_gets(void)
{
	struct sanlk_lockspace *lss = NULL, *ls;
	struct sanlk_host *hss = NULL, *hs;
	int ls_count = 0, hss_count = 0;
	int i, j, rv;

	rv = sanlock_get_lockspaces(&lss, &ls_count, 0);
	if (rv < 0)
		log_tool("gets error %d", rv);

	if (rv < 0 && rv != -ENOSPC) {
		if (lss)
			free(lss);
		return rv;
	}

	if (!lss)
		return 0;

	ls = lss;

	for (i = 0; i < ls_count; i++) {
		log_tool("s %.48s:%llu:%s:%llu %s",
			 ls->name,
			 (unsigned long long)ls->host_id,
			 ls->host_id_disk.path,
			 (unsigned long long)ls->host_id_disk.offset,
			 !ls->flags ? "" : lsf_to_str(ls->flags));

		if (!com.get_hosts)
			goto next;

		hss = NULL;
		hss_count = 0;

		rv = sanlock_get_hosts(ls->name, 0, &hss, &hss_count, 0);
		if (rv == -EAGAIN) {
			log_tool("hosts not ready");
			goto next;
		}
		if (rv < 0) {
			log_tool("hosts error %d", rv);
			goto next;
		}

		if (!hss)
			goto next;

		hs = hss;

		for (j = 0; j < hss_count; j++) {
			log_tool("h %llu gen %llu timestamp %llu %s",
				 (unsigned long long)hs->host_id,
				 (unsigned long long)hs->generation,
				 (unsigned long long)hs->timestamp,
				 host_state_str(hs->flags));
			hs++;
		}
		free(hss);
 next:
		ls++;
	}

	free(lss);
	return 0;
}

static int do_client_read(void)
{
	struct sanlk_host *hss = NULL, *hs;
	char *res_str = NULL;
	uint32_t io_timeout = 0;
	int rv, i, hss_count = 0;

	if (com.lockspace.host_id_disk.path[0]) {
		if (com.sector_size == 512)
			com.lockspace.flags |= SANLK_LSF_ALIGN1M;
		else if (com.sector_size == 4096)
			com.lockspace.flags |= SANLK_LSF_ALIGN8M;

		rv = sanlock_read_lockspace(&com.lockspace, 0, &io_timeout);
	} else {
		if (com.sector_size == 512)
			com.res_args[0]->flags |= SANLK_RES_ALIGN1M;
		else if (com.sector_size == 4096)
			com.res_args[0]->flags |= SANLK_RES_ALIGN8M;

		if (!com.get_hosts) {
			rv = sanlock_read_resource(com.res_args[0], 0);
		} else {
			rv = sanlock_read_resource_owners(com.res_args[0], 0,
							  &hss, &hss_count);
		}
	}

	if (rv < 0) {
		log_tool("read error %d", rv);
		goto out;
	}

	if (com.lockspace.host_id_disk.path[0]) {
		log_tool("s %.48s:%llu:%s:%llu",
			 com.lockspace.name,
			 (unsigned long long)com.lockspace.host_id,
			 com.lockspace.host_id_disk.path,
			 (unsigned long long)com.lockspace.host_id_disk.offset);
		log_tool("io_timeout %u", io_timeout);
		goto out;
	}

	rv = sanlock_res_to_str(com.res_args[0], &res_str);
	if (rv < 0) {
		log_tool("res_to_str error %d", rv);
		goto out;
	}

	log_tool("r %s", res_str);

	free(res_str);

	if (!hss)
		goto out;

	hs = hss;

	for (i = 0; i < hss_count; i++) {
		if (hs->timestamp)
			log_tool("h %llu gen %llu timestamp %llu",
				 (unsigned long long)hs->host_id,
				 (unsigned long long)hs->generation,
				 (unsigned long long)hs->timestamp);
		else
			log_tool("h %llu gen %llu",
				 (unsigned long long)hs->host_id,
				 (unsigned long long)hs->generation);
		hs++;
	}
 out:
	if (hss)
		free(hss);
	return rv;
}

static void do_client_version(void)
{
	uint32_t version = 0;
	uint32_t proto = 0;
	int rv;

	rv = sanlock_version(0, &version, &proto);
	if (rv < 0) {
		log_tool("daemon version error %d", rv);
	}

	log_tool("client version %u.%u.%u (0x%08x)",
		 sanlock_version_major,
		 sanlock_version_minor,
		 sanlock_version_patch,
		 sanlock_version_combined);

	log_tool("daemon version %u.%u.%u (0x%08x)",
		 (version & 0xFF000000) >> 24,
		 (version & 0x00FF0000) >> 16,
		 (version & 0x0000FF00) >> 8,
		 version);

	log_tool("client socket protocol %u.%u",
		  (SM_PROTO & 0xFFFF0000) >> 16,
		  (SM_PROTO & 0x0000FFFF));

	log_tool("daemon socket protocol %u.%u",
		  (proto & 0xFFFF0000) >> 16,
		  (proto & 0x0000FFFF));
}

static int do_client(void)
{
	struct sanlk_host_event he;
	struct sanlk_resource **res_args = NULL;
	struct sanlk_resource *res;
	char *res_state = NULL;
	uint32_t flags = 0;
	uint32_t config_cmd = 0;
	int i, fd;
	int rv = 0;

	if (com.action == ACT_COMMAND || com.action == ACT_ACQUIRE) {
		for (i = 0; i < com.res_count; i++) {
			res = com.res_args[i];

			if (com.num_hosts) {
				res->flags |= SANLK_RES_NUM_HOSTS;
				res->data32 = com.num_hosts;
			}

			if (com.persistent)
				res->flags |= SANLK_RES_PERSISTENT;
		}

	}

	switch (com.action) {
	case ACT_STATUS:
		rv = sanlock_status(com.debug, com.sort_arg);
		break;

	case ACT_HOST_STATUS:
		rv = sanlock_host_status(com.debug, com.lockspace.name);
		break;

	case ACT_RENEWAL:
		rv = sanlock_renewal(com.lockspace.name);
		break;

	case ACT_GETS:
		rv = do_client_gets();
		break;

	case ACT_LOG_DUMP:
		rv = sanlock_log_dump(LOG_DUMP_SIZE);
		break;

	case ACT_SHUTDOWN:
		log_tool("shutdown force %d wait %d", com.force_mode, com.wait);
		rv = sanlock_shutdown(com.force_mode, com.wait);
		log_tool("shutdown done %d", rv);
		break;

	case ACT_COMMAND:
		log_tool("register");
		fd = sanlock_register();
		log_tool("register done %d", fd);

		if (fd < 0)
			goto out;

		flags |= com.orphan ? SANLK_ACQUIRE_ORPHAN : 0;
		log_tool("acquire fd %d", fd);
		rv = sanlock_acquire(fd, -1, flags, com.res_count, com.res_args, NULL);
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
		if (com.io_timeout_arg != DEFAULT_IO_TIMEOUT) {
			log_tool("add_lockspace_timeout %d", com.io_timeout_arg);
			rv = sanlock_add_lockspace_timeout(&com.lockspace, 0,
							   com.io_timeout_arg);
			log_tool("add_lockspace_timeout done %d", rv);
		} else {
			log_tool("add_lockspace");
			rv = sanlock_add_lockspace(&com.lockspace, 0);
			log_tool("add_lockspace done %d", rv);
		}
		break;

	case ACT_INQ_LOCKSPACE:
		log_tool("inq_lockspace");
		rv = sanlock_inq_lockspace(&com.lockspace, 0);
		log_tool("inq_lockspace done %d", rv);
		break;

	case ACT_REM_LOCKSPACE:
		log_tool("rem_lockspace");
		rv = sanlock_rem_lockspace(&com.lockspace, 0);
		log_tool("rem_lockspace done %d", rv);
		break;

	case ACT_ACQUIRE:
		log_tool("acquire pid %d", com.pid);
		flags |= com.orphan ? SANLK_ACQUIRE_ORPHAN : 0;
		rv = sanlock_acquire(-1, com.pid, flags, com.res_count, com.res_args, NULL);
		log_tool("acquire done %d", rv);
		break;

	case ACT_CONVERT:
		log_tool("convert pid %d", com.pid);
		rv = sanlock_convert(-1, com.pid, 0, com.res_args[0]);
		log_tool("convert done %d", rv);
		break;

	case ACT_RELEASE:
		log_tool("release pid %d", com.pid);
		/*
		 * Odd case to specify: release all orphan resources for the named lockspace.
		 * Uses -s lockspace_name instead of using -r, but the function takes a
		 * struct resource, so we take the lockspace arg and copy the name into
		 * a resource struct.  When releasing one named orphan resource, the
		 * usual -r lockspace_name:resource_name arg is used.
		 */
		if (com.orphan && !com.res_count && com.lockspace.name[0]) {
			struct sanlk_resource *res_ls = malloc(sizeof(struct sanlk_resource));
			if (!res_ls)
				break;
			memset(res_ls, 0, sizeof(struct sanlk_resource));
			strcpy(res_ls->lockspace_name, com.lockspace.name);
			com.res_args[0] = res_ls;
			com.res_count = 1;
		}
		flags |= com.orphan ? SANLK_REL_ORPHAN : 0;
		flags |= com.all ? SANLK_REL_ALL: 0;
		rv = sanlock_release(-1, com.pid, flags, com.res_count, com.res_args);
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

	case ACT_REQUEST:
		log_tool("request");
		rv = sanlock_request(0, com.force_mode, com.res_args[0]);
		log_tool("request done %d", rv);
		break;

	case ACT_EXAMINE:
		log_tool("examine");
		if (com.lockspace.host_id_disk.path[0])
			rv = sanlock_examine(0, &com.lockspace, NULL);
		else
			rv = sanlock_examine(0, NULL, com.res_args[0]);
		log_tool("examine done %d", rv);
		break;

	case ACT_CLIENT_ALIGN:
		log_tool("align");
		rv = sanlock_align(&com.lockspace.host_id_disk);
		log_tool("align done %d", rv);
		break;

	case ACT_CLIENT_INIT:
		log_tool("init");
		if (com.lockspace.host_id_disk.path[0]) {
			if (com.sector_size == 512)
				com.lockspace.flags |= SANLK_LSF_ALIGN1M;
			else if (com.sector_size == 4096)
				com.lockspace.flags |= SANLK_LSF_ALIGN8M;

			rv = sanlock_write_lockspace(&com.lockspace,
						     com.max_hosts, 0,
						     com.io_timeout_arg);
		} else {
			if (com.sector_size == 512)
				com.res_args[0]->flags |= SANLK_RES_ALIGN1M;
			else if (com.sector_size == 4096)
				com.res_args[0]->flags |= SANLK_RES_ALIGN8M;

			rv = sanlock_write_resource(com.res_args[0],
						    com.max_hosts,
						    com.num_hosts,
						    com.clear_arg ? SANLK_WRITE_CLEAR : 0);
		}

		log_tool("init done %d", rv);
		break;

	case ACT_CLIENT_READ:
		rv = do_client_read();
		break;

	case ACT_VERSION:
		do_client_version();
		break;

	case ACT_SET_EVENT:
		log_tool("set_event %llu %llu event 0x%llx data 0x%llx",
			 (unsigned long long)com.host_id,
			 (unsigned long long)com.host_generation,
			 (unsigned long long)com.he_event,
			 (unsigned long long)com.he_data);
		he.host_id = com.host_id;
		he.generation = com.host_generation;
		he.event = com.he_event;
		he.data = com.he_data;
		rv = sanlock_set_event(com.lockspace.name, &he, 0);
                log_tool("set_event done %d", rv);
                break;

	case ACT_SET_CONFIG:
		if (com.orphan_set)
			config_cmd = com.orphan ? SANLK_CONFIG_USED_BY_ORPHANS :
						  SANLK_CONFIG_UNUSED_BY_ORPHANS;

		else if (com.used_set)
			config_cmd = com.used ? SANLK_CONFIG_USED :
						SANLK_CONFIG_UNUSED;

		log_tool("set_config %s %u", com.lockspace.name, config_cmd);
		rv = sanlock_set_config(com.lockspace.name, 0, config_cmd, NULL);
		log_tool("set_config done %d", rv);
		break;

	default:
		log_tool("action not implemented");
		rv = -1;
	}
 out:
	return rv;
}

#define MAX_LINE 128

static int read_file_leader(struct leader_record *leader, int is_ls)
{
	FILE *file;
	char line[MAX_LINE];
	char field[MAX_LINE];
	char val[MAX_LINE];
	uint32_t checksum = 0;
	uint32_t new_checksum;
	struct leader_record lr;
	int rv;

	file = fopen(com.file_path, "r");
	if (!file) {
		log_tool("open error %d %s", errno, com.file_path);
		return -1;
	}

	memcpy(&lr, leader, sizeof(lr));

	memset(line, 0, sizeof(line));

	while (fgets(line, MAX_LINE, file)) {

		memset(field, 0, sizeof(field));
		memset(val, 0, sizeof(val));

		rv = sscanf(line, "%s %s", field, val);
		if (rv != 2) {
			log_tool("ignore line: \"%s\"", line);
			continue;
		}

		if (!strcmp(field, "magic")) {
			sscanf(val, "0x%x", &lr.magic);

		} else if (!strcmp(field, "version")) {
			sscanf(val, "0x%x", &lr.version);

		} else if (!strcmp(field, "flags")) {
			sscanf(val, "0x%x", &lr.flags);

		} else if (!strcmp(field, "sector_size")) {
			sscanf(val, "%u", &lr.sector_size);

		} else if (!strcmp(field, "num_hosts")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.num_hosts);

		} else if (!strcmp(field, "max_hosts")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.max_hosts);

		} else if (!strcmp(field, "owner_id")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.owner_id);

		} else if (!strcmp(field, "owner_generation")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.owner_generation);

		} else if (!strcmp(field, "lver")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.lver);

		} else if (!strcmp(field, "space_name")) {
			strncpy(lr.space_name, val, NAME_ID_SIZE);

		} else if (!strcmp(field, "resource_name")) {
			strncpy(lr.resource_name, val, NAME_ID_SIZE);

		} else if (!strcmp(field, "timestamp")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.timestamp);

		} else if (!strcmp(field, "checksum")) {
			sscanf(val, "0x%x", &checksum);

		} else if (!strcmp(field, "io_timeout")) {
			sscanf(val, "%hu", &lr.io_timeout);

		} else if (is_ls && !strcmp(field, "extra1")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.write_id);

		} else if (is_ls && !strcmp(field, "extra2")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.write_generation);

		} else if (is_ls && !strcmp(field, "extra3")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.write_timestamp);

		} else if (!is_ls && !strcmp(field, "write_id")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.write_id);

		} else if (!is_ls && !strcmp(field, "write_generation")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.write_generation);

		} else if (!is_ls && !strcmp(field, "write_timestamp")) {
			sscanf(val, "%llu", (unsigned long long *)&lr.write_timestamp);
		} else {
			log_tool("ignore field: \"%s\"", field);
		}

		memset(line, 0, sizeof(line));
	}
	fclose(file);

	new_checksum = leader_checksum(&lr);

	if (!com.force_mode) {
		lr.checksum = new_checksum;
		log_tool("use new generated checksum %x", new_checksum);
	} else {
		lr.checksum = checksum;
		log_tool("warning: using specified checksum %x (generated is %x)",
			 checksum, new_checksum);
	}

	memcpy(leader, &lr, sizeof(lr));
	return 0;
}

static void print_leader(struct leader_record *leader, int is_ls)
{
	log_tool("magic 0x%0x", leader->magic);
	log_tool("version 0x%x", leader->version);
	log_tool("flags 0x%x", leader->flags);
	log_tool("sector_size %u", leader->sector_size);
	log_tool("num_hosts %llu", (unsigned long long)leader->num_hosts);
	log_tool("max_hosts %llu", (unsigned long long)leader->max_hosts);
	log_tool("owner_id %llu", (unsigned long long)leader->owner_id);
	log_tool("owner_generation %llu", (unsigned long long)leader->owner_generation);
	log_tool("lver %llu", (unsigned long long)leader->lver);
	log_tool("space_name %.48s", leader->space_name);
	log_tool("resource_name %.48s", leader->resource_name);
	log_tool("timestamp %llu", (unsigned long long)leader->timestamp);
	log_tool("checksum 0x%0x", leader->checksum);
	log_tool("io_timeout %u", leader->io_timeout);

	if (!is_ls) {
		log_tool("write_id %llu", (unsigned long long)leader->write_id);
		log_tool("write_generation %llu", (unsigned long long)leader->write_generation);
		log_tool("write_timestamp %llu", (unsigned long long)leader->write_timestamp);
	} else {
		log_tool("extra1 %llu", (unsigned long long)leader->write_id);
		log_tool("extra2 %llu", (unsigned long long)leader->write_generation);
		log_tool("extra3 %llu", (unsigned long long)leader->write_timestamp);
	}
}

static int do_direct_read_leader(void)
{
	struct leader_record leader;
	int rv;

	rv = direct_read_leader(&main_task, com.io_timeout_arg,
				&com.lockspace, com.res_args[0],
				&leader);

	log_tool("read_leader done %d", rv);

	print_leader(&leader, com.res_args[0] ? 0 : 1);

	return rv;
}

/*
 * read the current leader record from disk, override any values found in
 * the file, write back the result.
 */

static int do_direct_write_leader(void)
{
	struct leader_record leader;
	char *res_str = NULL;
	int is_ls = com.res_args[0] ? 0 : 1;
	int rv;

	memset(&leader, 0, sizeof(leader));

	direct_read_leader(&main_task, com.io_timeout_arg,
			   &com.lockspace, com.res_args[0],
			   &leader);

	rv = read_file_leader(&leader, is_ls);
	if (rv < 0)
		return rv;

	/* make a record in the logs that this has been done */

	if (is_ls) {
		syslog(LOG_WARNING, "write_leader lockspace %.48s:%llu:%s:%llu",
		       com.lockspace.name,
		       (unsigned long long)com.lockspace.host_id,
		       com.lockspace.host_id_disk.path,
		       (unsigned long long)com.lockspace.host_id_disk.offset);
	} else {
		rv = sanlock_res_to_str(com.res_args[0], &res_str);
		if (rv < 0) {
			syslog(LOG_WARNING, "write_leader resource %.48s:%.48s",
			       com.res_args[0]->lockspace_name, com.res_args[0]->name);
		} else {
			syslog(LOG_WARNING, "write_leader resource %s", res_str);
		}
	}

	rv = direct_write_leader(&main_task, com.io_timeout_arg,
				 &com.lockspace, com.res_args[0],
				 &leader);

	log_tool("write_leader done %d", rv);

	print_leader(&leader, is_ls);

	if (res_str)
		free(res_str);

	return rv;
}

static int do_direct_init(void)
{
	char *res_str = NULL;
	int rv;

	if (com.lockspace.host_id_disk.path[0]) {
		syslog(LOG_WARNING, "init lockspace %.48s:%llu:%s:%llu",
		       com.lockspace.name,
		       (unsigned long long)com.lockspace.host_id,
		       com.lockspace.host_id_disk.path,
		       (unsigned long long)com.lockspace.host_id_disk.offset);

		rv = direct_write_lockspace(&main_task, &com.lockspace,
					    com.max_hosts, com.io_timeout_arg);
	} else {
		rv = sanlock_res_to_str(com.res_args[0], &res_str);
		if (rv < 0) {
			syslog(LOG_WARNING, "init resource %.48s:%.48s",
			       com.res_args[0]->lockspace_name, com.res_args[0]->name);
		} else {
			syslog(LOG_WARNING, "init resource %s", res_str);
		}

		rv = direct_write_resource(&main_task, com.res_args[0],
					   com.max_hosts, com.num_hosts, com.clear_arg);
	}

	log_tool("init done %d", rv);

	if (res_str)
		free(res_str);

	return rv;
}

static int do_direct(void)
{
	struct leader_record leader;
	int rv;

	/* we want a record of any out-of-band changes to disk */
	openlog("sanlock-direct", LOG_CONS | LOG_PID, LOG_DAEMON);

	setup_task_aio(&main_task, com.aio_arg, DIRECT_AIO_CB_SIZE);
	sprintf(main_task.name, "%s", "main_direct");

	switch (com.action) {

	case ACT_DIRECT_INIT:
		rv = do_direct_init();
		break;

	case ACT_DUMP:
		rv = direct_dump(&main_task, com.dump_path, com.force_mode);
		break;

	case ACT_NEXT_FREE:
		rv = direct_next_free(&main_task, com.dump_path);
		break;

	case ACT_READ_LEADER:
		rv = do_direct_read_leader();
		break;
	
	case ACT_WRITE_LEADER:
		rv = do_direct_write_leader();
		break;

	case ACT_ACQUIRE:
		syslog(LOG_WARNING, "acquire");
		rv = direct_acquire(&main_task, com.io_timeout_arg,
				    com.res_args[0], com.num_hosts,
				    com.host_id, com.host_generation,
				    &leader);
		log_tool("acquire done %d", rv);
		break;

	case ACT_RELEASE:
		syslog(LOG_WARNING, "release");
		rv = direct_release(&main_task, com.io_timeout_arg,
				    com.res_args[0], &leader);
		log_tool("release done %d", rv);
		break;

	case ACT_ACQUIRE_ID:
		syslog(LOG_WARNING, "acquire_id");
		setup_host_name();

		rv = direct_acquire_id(&main_task, com.io_timeout_arg,
				       &com.lockspace, our_host_name_global);
		log_tool("acquire_id done %d", rv);
		break;

	case ACT_RELEASE_ID:
		syslog(LOG_WARNING, "release_id");
		rv = direct_release_id(&main_task, com.io_timeout_arg, &com.lockspace);
		log_tool("release_id done %d", rv);
		break;

	case ACT_RENEW_ID:
		syslog(LOG_WARNING, "renew_id");
		rv = direct_renew_id(&main_task, com.io_timeout_arg, &com.lockspace);
		log_tool("rewew_id done %d", rv);
		break;

	default:
		log_tool("direct action %d not known", com.action);
		rv = -1;
	}

	close_task_aio(&main_task);
	closelog();
	return rv;
}

static void set_sanlock_version(void)
{
	char version_str[64];
	char *major_str, *minor_str, *patch_str;
	char *d1, *d2;

	strncpy(version_str, VERSION, 64);

	d1 = strstr(version_str, ".");
	if (!d1)
		return;

	d2 = strstr(d1 + 1, ".");
	if (!d2)
		return;

	major_str = version_str;
	minor_str = d1 + 1;
	patch_str = d2 + 1;

	*d1 = '\0';
	*d2 = '\0';

	sanlock_version_major = atoi(major_str);
	sanlock_version_minor = atoi(minor_str);
	sanlock_version_patch = atoi(patch_str);

	sanlock_version_build = 0; /* TODO */

	sanlock_version_combined = 0;
	sanlock_version_combined |= sanlock_version_major << 24;
	sanlock_version_combined |= sanlock_version_minor << 16;
	sanlock_version_combined |= sanlock_version_patch << 8;
	sanlock_version_combined |= sanlock_version_build;
}

int main(int argc, char *argv[])
{
	int rv;

	BUILD_BUG_ON(sizeof(struct sanlk_disk) != sizeof(struct sync_disk));
	BUILD_BUG_ON(sizeof(struct leader_record) > LEADER_RECORD_MAX);
	BUILD_BUG_ON(sizeof(struct helper_msg) != SANLK_HELPER_MSG_LEN);

	/* initialize global EXTERN variables */

	set_sanlock_version();

	kill_count_max = 100;
	kill_grace_seconds = DEFAULT_GRACE_SEC;
	helper_ci = -1;
	helper_pid = -1;
	helper_kill_fd = -1;
	helper_status_fd = -1;

	pthread_mutex_init(&spaces_mutex, NULL);
	INIT_LIST_HEAD(&spaces);
	INIT_LIST_HEAD(&spaces_rem);
	INIT_LIST_HEAD(&spaces_add);

	memset(&com, 0, sizeof(com));
	com.use_watchdog = DEFAULT_USE_WATCHDOG;
	com.high_priority = DEFAULT_HIGH_PRIORITY;
	com.mlock_level = DEFAULT_MLOCK_LEVEL;
	com.names_log_priority = LOG_WARNING;
	com.max_worker_threads = DEFAULT_MAX_WORKER_THREADS;
	com.io_timeout_arg = DEFAULT_IO_TIMEOUT;
	com.aio_arg = DEFAULT_USE_AIO;
	com.pid = -1;
	com.sh_retries = DEFAULT_SH_RETRIES;
	com.quiet_fail = DEFAULT_QUIET_FAIL;
	com.renewal_read_extend_sec_set = 0;
	com.renewal_read_extend_sec = 0;
	com.renewal_history_size = DEFAULT_RENEWAL_HISTORY_SIZE;
	com.paxos_debug_all = 0;

	if (getgrnam("sanlock") && getpwnam("sanlock")) {
		com.uname = (char *)"sanlock";
		com.gname = (char *)"sanlock";
		com.uid = user_to_uid(com.uname);
		com.gid = group_to_gid(com.uname);
	} else {
		com.uname = NULL;
		com.gname = NULL;
		com.uid = DEFAULT_SOCKET_UID;
		com.gid = DEFAULT_SOCKET_GID;
	}

	memset(&main_task, 0, sizeof(main_task));

	/*
	 * read_config_file() overrides com default settings,
	 * read_command_line() overrides com default settings and
	 * config file settings.
	 */
	read_config_file();

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

