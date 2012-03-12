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

#define RELEASE_VERSION "2.1"

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
	cl->restrict = 0;
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
	int rv, error = 0, total = 0;

	if (!rem)
		return;

	while (1) {
		rv = recv(client[ci].fd, trash, sizeof(trash), MSG_DONTWAIT);
		if (rv == -1)
			error = errno;
		if (rv <= 0)
			break;
		total += rv;

		if (total >= rem)
			break;
	}

	log_debug("recv_all %d,%d,%d pos %d rv %d error %d rem %d total %d",
		  ci, client[ci].fd, client[ci].pid, pos, rv, error, rem, total);
}

void send_result(int fd, struct sm_header *h_recv, int result);
void send_result(int fd, struct sm_header *h_recv, int result)
{
	struct sm_header h;

	memcpy(&h, h_recv, sizeof(struct sm_header));
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

	for (i = 0; i < SANLK_MAX_RESOURCES; i++) {
		token = cl->tokens[i];
		if (!token)
			continue;
		if (strncmp(token->r.lockspace_name, sp->space_name, NAME_ID_SIZE))
			continue;

		if (!cl->kill_count)
			log_spoke(sp, token, "client_using_space pid %d", cl->pid);
		if (sp->space_dead)
			token->flags |= T_LS_DEAD;
		rv = 1;
	}
	return rv;
}

/* TODO: try killscript first if one is provided */

static void kill_pids(struct space *sp)
{
	struct client *cl;
	uint64_t now;
	int ci, fd, pid, sig;
	int do_kill;

	/*
	 * all remaining pids using sp are stuck, we've made max attempts to
	 * kill all, don't bother cycling through them
	 */
	if (sp->killing_pids > 1)
		return;

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

		if (cl->kill_count >= main_task.kill_count_max)
			goto unlock;

		if (cl->kill_count && (now - cl->kill_last < 1))
			goto unlock;

		if (!client_using_space(cl, sp))
			goto unlock;

		cl->kill_last = now;
		cl->kill_count++;

		fd = cl->fd;
		pid = cl->pid;

		if (cl->restrict & SANLK_RESTRICT_SIGKILL)
			sig = SIGTERM;
		else if (cl->restrict & SANLK_RESTRICT_SIGTERM)
			sig = SIGKILL;
		else if (cl->kill_count <= main_task.kill_count_term)
			sig = SIGTERM;
		else
			sig = SIGKILL;

		do_kill = 1;
 unlock:
		pthread_mutex_unlock(&cl->mutex);

		if (!do_kill)
			continue;

		if (cl->kill_count == main_task.kill_count_max) {
			log_erros(sp, "kill %d,%d,%d sig %d count %d final attempt",
				  ci, fd, pid, sig, cl->kill_count);
		} else {
			log_space(sp, "kill %d,%d,%d sig %d count %d",
				  ci, fd, pid, sig, cl->kill_count);
		}

		kill(pid, sig);
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

		if (cl->kill_count >= main_task.kill_count_max)
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
	int i, rv, empty, check_all;
	char *check_buf = NULL;
	int check_buf_len = 0;

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
				unlink_watchdog_file(sp);
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

			rv = check_our_lease(&main_task, sp, &check_all, check_buf);

			if (rv || sp->external_remove || (external_shutdown > 1)) {
				log_space(sp, "set killing_pids check %d remove %d",
					  rv, sp->external_remove);
				sp->space_dead = 1;
				sp->killing_pids = 1;
				kill_pids(sp);
				check_interval = RECOVERY_CHECK_INTERVAL;

			} else if (check_all) {
				check_other_leases(&main_task, sp, check_buf);
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

		gettimeofday(&now, NULL);
		ms = time_diff(&last_check, &now);
		if (ms < check_interval)
			poll_timeout = check_interval - ms;
		else
			poll_timeout = 1;
	}

	free_lockspaces(1);

	return 0;
}

static void *thread_pool_worker(void *data)
{
	struct task task;
	struct cmd_args *ca;

	memset(&task, 0, sizeof(struct task));
	setup_task_timeouts(&task, main_task.io_timeout_seconds);
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

/* cmd comes from a transient client/fd set up just to pass the cmd,
   and is not being done on behalf of another registered client/fd */

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

/* cmd either comes from a registered client/fd,
   or is targeting a registered client/fd */

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

	if (cl->kill_count) {
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
	if (client[ci].restrict & SANLK_RESTRICT_ALL) {
		log_error("ci %d fd %d pid %d cmd %d restrict all",
			  ci, client[ci].fd, client[ci].pid, h.cmd);
		goto dead;
	}

	client[ci].cmd_last = h.cmd;

	switch (h.cmd) {
	case SM_CMD_REGISTER:
	case SM_CMD_RESTRICT:
	case SM_CMD_SHUTDOWN:
	case SM_CMD_STATUS:
	case SM_CMD_HOST_STATUS:
	case SM_CMD_LOG_DUMP:
		call_cmd_daemon(ci, &h, client_maxi);
		break;
	case SM_CMD_ADD_LOCKSPACE:
	case SM_CMD_INQ_LOCKSPACE:
	case SM_CMD_REM_LOCKSPACE:
	case SM_CMD_REQUEST:
	case SM_CMD_EXAMINE_RESOURCE:
	case SM_CMD_EXAMINE_LOCKSPACE:
	case SM_CMD_ALIGN:
	case SM_CMD_INIT_LOCKSPACE:
	case SM_CMD_INIT_RESOURCE:
		rv = client_suspend(ci);
		if (rv < 0)
			return;
		process_cmd_thread_unregistered(ci, &h);
		break;
	case SM_CMD_ACQUIRE:
	case SM_CMD_RELEASE:
	case SM_CMD_INQUIRE:
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

	rv = sanlock_socket_address(&addr);
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

static void sigterm_handler(int sig GNUC_UNUSED)
{
	external_shutdown = 1;
}

static void setup_priority(void)
{
	struct sched_param sched_param;
	int rv;

	if (!com.high_priority)
		return;

	rv = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (rv < 0) {
		log_error("mlockall failed: %s", strerror(errno));
	}

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

	/* main task never does disk io, so we don't really need to set
	 * it up, but other tasks get their use_aio value by copying
	 * the main_task settings */

	sprintf(main_task.name, "%s", "main");
	setup_task_timeouts(&main_task, com.io_timeout_arg);
	setup_task_aio(&main_task, com.aio_arg, 0);
	 
	rv = client_alloc();
	if (rv < 0)
		return rv;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigterm_handler;
	rv = sigaction(SIGTERM, &act, NULL);
	if (rv < 0)
		return rv;

	fd = lockfile(SANLK_RUN_DIR, SANLK_LOCKFILE_NAME);
	if (fd < 0)
		return fd;

	setup_logging();

	setup_host_name();

	log_error("sanlock daemon started %s aio %d %d renew %d %d host %s time %llu",
		  RELEASE_VERSION,
		  main_task.use_aio, main_task.io_timeout_seconds,
		  main_task.id_renewal_seconds, main_task.id_renewal_fail_seconds,
		  our_host_name_global,
		  (unsigned long long)time(NULL));

	setup_priority();

	rv = thread_pool_create(DEFAULT_MIN_WORKER_THREADS, com.max_worker_threads);
	if (rv < 0)
		goto out_logging;

	rv = setup_watchdog();
	if (rv < 0)
		goto out_threads;

	rv = setup_listener();
	if (rv < 0)
		goto out_threads;

	setup_token_manager();
	if (rv < 0)
		goto out_threads;

	main_loop();

	close_token_manager();

	close_watchdog();

 out_threads:
	thread_pool_free();
 out_logging:
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
	printf("  -Q 0|1        quiet error messages for common lock contention (0)\n");
	printf("  -R 0|1        renewal debugging, log debug info about renewals (0)\n");
	printf("  -L <pri>      write logging at priority level and up to logfile (3 LOG_ERR))\n");
	printf("                (use -1 for none)\n");
	printf("  -S <pri>      write logging at priority level and up to syslog (3 LOG_ERR)\n");
	printf("                (use -1 for none)\n");
	printf("  -U <uid>      user id\n");
	printf("  -G <gid>      group id\n");
	printf("  -t <num>      max worker threads (%d)\n", DEFAULT_MAX_WORKER_THREADS);
	printf("  -w 0|1        use watchdog through wdmd (%d)\n", DEFAULT_USE_WATCHDOG);
	printf("  -h 0|1        use high priority features (%d)\n", DEFAULT_HIGH_PRIORITY);
	printf("                (realtime scheduling, mlockall)\n");
	printf("  -a 0|1        use async io (%d)\n", DEFAULT_USE_AIO);
	printf("  -o 0|1        io timeout in seconds (%d)\n", DEFAULT_IO_TIMEOUT);
	printf("\n");
	printf("sanlock client <action> [options]\n");
	printf("sanlock client status [-D] [-o p|s]\n");
	printf("sanlock client host_status -s LOCKSPACE [-D]\n");
	printf("sanlock client log_dump\n");
	printf("sanlock client shutdown [-f 0|1]\n");
	printf("sanlock client init -s LOCKSPACE | -r RESOURCE\n");
	printf("sanlock client align -s LOCKSPACE\n");
	printf("sanlock client add_lockspace -s LOCKSPACE\n");
	printf("sanlock client inq_lockspace -s LOCKSPACE\n");
	printf("sanlock client rem_lockspace -s LOCKSPACE\n");
	printf("sanlock client command -r RESOURCE -c <path> <args>\n");
	printf("sanlock client acquire -r RESOURCE -p <pid>\n");
	printf("sanlock client release -r RESOURCE -p <pid>\n");
	printf("sanlock client inquire -p <pid>\n");
	printf("sanlock client request -r RESOURCE -f <force_mode>\n");
	printf("sanlock client examine -r RESOURCE | -s LOCKSPACE\n");
	printf("\n");
	printf("sanlock direct <action> [-a 0|1] [-o 0|1]\n");
	printf("sanlock direct init -s LOCKSPACE | -r RESOURCE\n");
	printf("sanlock direct read_leader -s LOCKSPACE | -r RESOURCE\n");
	printf("sanlock direct read_id -s LOCKSPACE\n");
	printf("sanlock direct live_id -s LOCKSPACE\n");
	printf("sanlock direct dump <path>[:<offset>]\n");
	printf("\n");
	printf("LOCKSPACE = <lockspace_name>:<host_id>:<path>:<offset>\n");
	printf("  <lockspace_name>	name of lockspace\n");
	printf("  <host_id>		local host identifier in lockspace\n");
	printf("  <path>		disk to storage reserved for leases\n");
	printf("  <offset>		offset on path (bytes)\n");
	printf("\n");
	printf("RESOURCE = <lockspace_name>:<resource_name>:<path>:<offset>[:<lver>]\n");
	printf("  <lockspace_name>	name of lockspace\n");
	printf("  <resource_name>	name of resource\n");
	printf("  <path>		disk to storage reserved for leases\n");
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
		else if (!strcmp(act, "host_status"))
			com.action = ACT_HOST_STATUS;
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
		case 'L':
			log_logfile_priority = atoi(optionarg);
			break;
		case 'S':
			log_syslog_priority = atoi(optionarg);
			break;
		case 'a':
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
			break;
		case 'h':
			com.high_priority = atoi(optionarg);
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
		case 'n':
			com.num_hosts = atoi(optionarg);
			break;
		case 'm':
			com.max_hosts = atoi(optionarg);
			break;
		case 'p':
			com.pid = atoi(optionarg);
			break;
		case 'e':
			strncpy(com.our_host_name, optionarg, NAME_ID_SIZE);
			break;
		case 'i':
			com.local_host_id = atoll(optionarg);
			break;
		case 'g':
			com.local_host_generation = atoll(optionarg);
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
		rv = sanlock_status(com.debug, com.sort_arg);
		break;

	case ACT_HOST_STATUS:
		rv = sanlock_host_status(com.debug, com.lockspace.name);
		break;

	case ACT_LOG_DUMP:
		rv = sanlock_log_dump(LOG_DUMP_SIZE);
		break;

	case ACT_SHUTDOWN:
		log_tool("shutdown");
		rv = sanlock_shutdown(com.force_mode);
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
		if (com.lockspace.host_id_disk.path[0])
			rv = sanlock_init(&com.lockspace, NULL,
					  com.max_hosts, com.num_hosts);
		else
			rv = sanlock_init(NULL, com.res_args[0],
					  com.max_hosts, com.num_hosts);
		log_tool("init done %d", rv);
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

	setup_task_timeouts(&main_task, com.io_timeout_arg);
	setup_task_aio(&main_task, com.aio_arg, DIRECT_AIO_CB_SIZE);
	sprintf(main_task.name, "%s", "main_direct");

	switch (com.action) {
	case ACT_DIRECT_INIT:
		rv = direct_init(&main_task, &com.lockspace, com.res_args[0],
				 com.max_hosts, com.num_hosts);
		log_tool("init done %d", rv);
		break;

	case ACT_DUMP:
		rv = direct_dump(&main_task, com.dump_path, com.force_mode);
		break;

	case ACT_READ_LEADER:
		rv = direct_read_leader(&main_task, &com.lockspace, com.res_args[0], &leader);
		log_tool("read_leader done %d", rv);
		log_tool("magic 0x%0x", leader.magic);
		log_tool("version 0x%x", leader.version);
		log_tool("flags 0x%x", leader.flags);
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
		log_tool("checksum 0x%0x", leader.checksum);
		log_tool("write_id %llu",
			 (unsigned long long)leader.write_id);
		log_tool("write_generation %llu",
			 (unsigned long long)leader.write_generation);
		log_tool("write_timestamp %llu",
			 (unsigned long long)leader.write_timestamp);
		break;

	case ACT_ACQUIRE:
		rv = direct_acquire(&main_task, com.res_args[0], com.num_hosts,
				    com.local_host_id, com.local_host_generation,
				    &leader);
		log_tool("acquire done %d", rv);
		break;

	case ACT_RELEASE:
		rv = direct_release(&main_task, com.res_args[0], &leader);
		log_tool("release done %d", rv);
		break;

	case ACT_ACQUIRE_ID:
		setup_host_name();

		rv = direct_acquire_id(&main_task, &com.lockspace,
				       our_host_name_global);
		log_tool("acquire_id done %d", rv);
		break;

	case ACT_RELEASE_ID:
		rv = direct_release_id(&main_task, &com.lockspace);
		log_tool("release_id done %d", rv);
		break;

	case ACT_RENEW_ID:
		rv = direct_renew_id(&main_task, &com.lockspace);
		log_tool("rewew_id done %d", rv);
		break;

	case ACT_READ_ID:
		rv = direct_read_id(&main_task,
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
		rv = direct_live_id(&main_task,
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

	close_task_aio(&main_task);
	return rv;
}

int main(int argc, char *argv[])
{
	int rv;

	BUILD_BUG_ON(sizeof(struct sanlk_disk) != sizeof(struct sync_disk));
	BUILD_BUG_ON(sizeof(struct leader_record) > LEADER_RECORD_MAX);

	/* initialize global variables */
	pthread_mutex_init(&spaces_mutex, NULL);
	INIT_LIST_HEAD(&spaces);
	INIT_LIST_HEAD(&spaces_rem);
	INIT_LIST_HEAD(&spaces_add);
	
	memset(&com, 0, sizeof(com));
	com.use_watchdog = DEFAULT_USE_WATCHDOG;
	com.high_priority = DEFAULT_HIGH_PRIORITY;
	com.max_worker_threads = DEFAULT_MAX_WORKER_THREADS;
	com.io_timeout_arg = DEFAULT_IO_TIMEOUT;
	com.aio_arg = DEFAULT_USE_AIO;
	com.uid = DEFAULT_SOCKET_UID;
	com.gid = DEFAULT_SOCKET_GID;
	com.pid = -1;
	com.sh_retries = DEFAULT_SH_RETRIES;

	memset(&main_task, 0, sizeof(main_task));

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

