#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
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
#include <pthread.h>

#include "disk_paxos.h"

static int client_maxi;
static int client_size = 0;
static struct client *client = NULL;
static struct pollfd *pollfd = NULL;

#define COMMAND_MAX 4096
char opt_command[COMMAND_MAX];
char opt_killscript[COMMAND_MAX];
char resource_id[PATH_MAX];
uint64_t our_host_id;
uint64_t num_hosts;

char lockfile_path[PATH_MAX];
int supervise_pid;
int killscript_pid;
int supervise_pid_exit_status;
int starting_lease_thread;
int stopping_lease_threads;
int killing_supervise_pid;

#define MAX_LEASES 64
pthread_t lease_threads[MAX_LEASES];
pthread_mutex_t lease_status_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lease_status_cond = PTHREAD_COND_INITIALIZER;
struct lease_status lease_status[MAX_LEASES];

pthread_t wd_thread;
pthread_mutex_t wd_mutex = PTHREAD_MUTEX_INITIALIZER;
int wd_touch;
int wd_unlink;
int wd_fd;
char wd_path[PATH_MAX];
time_t wd_touch_time; /* timestamp of last wd touch */

/* sm starts recovery if one of its leases hasn't renewed in this time */
int lease_renewal_fail_seconds = 30;

/* sm tries to renew a lease this often */
int lease_renewal_seconds = 10;

/* sm touches a watchdog file this often */
int wd_touch_seconds = 4;

/* wd daemon reboots if it finds a wd file older than this (unused?) */
int wd_reboot_seconds = 10;

/* disk paxos takes over lease if it's not been renewed for this long */
int lease_timeout_seconds = 60;

/* use killscript if this many seconds remain (or >) until lease can be taken */
int script_shutdown_seconds = 20;

/* use SIGTERM if this many seconds remain (or >) until lease can be taken */
int sigterm_shutdown_seconds = 20;

/* check pid and lease status this often when things appear to be stable */

int stable_poll_ms = 2000;

/* check pid and lease status this often when things are changing */

int unstable_poll_ms = 500;

/* renewal timestamp of lease we renewed longest ago */
time_t oldest_renewal_time;

struct lease_status {
	int acquire_last_result;
	int renewal_last_result;
	int release_last_result;
	uint64_t acquire_last_time;
	uint64_t acquire_good_time;
	uint64_t renewal_last_time;
	uint64_t renewal_good_time;
	uint64_t release_last_time;
	uint64_t release_good_time;

	int stop_thread;
	int thread_running;
	uint32_t token_type;
	char token_name[TOKEN_NAME_SIZE];
};

struct client {
	int fd;
	void *workfn;
	void *deadfn;
};

int do_read(int fd, void *buf, size_t count)
{
	int rv, off = 0;

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0)
			return -1;
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv == -1)
			return -1;
		off += rv;
	}
	return 0;
}

#define CLIENT_NALLOC 2

static void client_alloc(void)
{
	int i;

	if (!client) {
		client = malloc(CLIENT_NALLOC * sizeof(struct client));
		pollfd = malloc(CLIENT_NALLOC * sizeof(struct pollfd));
	} else {
		client = realloc(client, (client_size + CLIENT_NALLOC) *
					 sizeof(struct client));
		pollfd = realloc(pollfd, (client_size + CLIENT_NALLOC) *
					 sizeof(struct pollfd));
		if (!pollfd)
			log_error("can't alloc for pollfd");
	}
	if (!client || !pollfd)
		log_error("can't alloc for client array");

	for (i = client_size; i < client_size + CLIENT_NALLOC; i++) {
		client[i].workfn = NULL;
		client[i].deadfn = NULL;
		client[i].fd = -1;
		pollfd[i].fd = -1;
		pollfd[i].revents = 0;
	}
	client_size += CLIENT_NALLOC;
}

void client_dead(int ci)
{
	close(client[ci].fd);
	client[ci].workfn = NULL;
	client[ci].fd = -1;
	pollfd[ci].fd = -1;
}

int client_add(int fd, void (*workfn)(int ci), void (*deadfn)(int ci))
{
	int i;

	if (!client)
		client_alloc();
 again:
	for (i = 0; i < client_size; i++) {
		if (client[i].fd == -1) {
			client[i].workfn = workfn;
			if (deadfn)
				client[i].deadfn = deadfn;
			else
				client[i].deadfn = client_dead;
			client[i].fd = fd;
			pollfd[i].fd = fd;
			pollfd[i].events = POLLIN;
			if (i > client_maxi)
				client_maxi = i;
			return i;
		}
	}

	client_alloc();
	goto again;
}

/* return number of opened disks */

int open_disks(struct token *token)
{
	struct paxos_disk *disk;
	int num_opens = 0;
	int d, fd;

	for (d = 0; d < token->num_disks; d++) {
		disk = &token->disks[d];
		fd = open(disk->path, O_RDWR | O_DIRECT | O_SYNC, 0);
		if (fd < 0) {
			log_error("open error %d %s", fd, disk->path);
			continue;
		}

		disk->fd = fd;
		num_opens++;
	}
	return num_opens;
}

void close_disks(struct token *token)
{
	struct paxos_disk *disk;
	int d;

	for (d = 0; d < token->num_disks; d++) {
		disk = &token->disks[d];
		close(disk->fd);
	}
}

void free_token(struct token *token)
{
	free(token->disks);
	free(token);
}

int check_killscript_pid(void)
{
	int rv, status;

	if (!killscript_pid)
		return 0;

	rv = waitpid(killscript_pid, &status, WNOHANG);
	if (rv > 0)
		killscript_pid = 0;
	else if (!rv) {
		/* TODO: call again before sync_manager exit */
	}
}

/*
 * return values:
 * 1 if pid is running (or pid has not been set yet)
 * 0 is pid is not running
 * < 0 on a waitpid error, don't know what these conditions are
 */

int check_supervise_pid(void)
{
	int rv, status, kill_status;

	if (!supervise_pid)
		return 1;

	rv = waitpid(supervise_pid, &status, WNOHANG);
	if (!rv)
		return 1;
	if (rv < 0)
		return rv;

	if (WIFEXITED(status)) {
		supervise_pid_exit_status = WEXITSTATUS(status);
		check_killscript_pid();
		supervise_pid = 0;
		return 0;
	}

	return 1;
}

int run_killscript(void)
{
	int pid;

	pid = fork();
	if (pid < 0)
		return pid;

	if (pid) {
		killscript_pid = pid;
		return 0;
	} else {
		execl(opt_killscript, NULL);
		return -1;
	}
}

int run_command(char *command)
{
	int pid;

	pid = fork();
	if (pid < 0)
		return pid;

	if (pid) {
		supervise_pid = pid;
		return 0;
	} else {
		execl(command, NULL);
		return -1;
	}
}

void kill_supervise_pid(void)
{
	uint64_t expire_time, remaining_seconds;

	if (!supervise_pid)
		return 0;

	expire_time = oldest_renewal_time + lease_timeout_seconds;

	if (time(NULL) >= expire_time)
		goto do_kill:

	remaining_seconds = expire_time - time(NULL);

	if (!killscript_command[0])
		goto do_term;

	/* While we have more than script_shutdown_seconds until our
	   lease expires, we can try using killscript. */

	if (killing_supervise_pid > 2)
		goto do_term;

	if (remaining_seconds >= script_shutdown_seconds) {
		killing_supervise_pid = 2;
		run_killscript();
		return;
	}

	/* While we have more than sigterm_shutdown_seconds until our
	   lease expires, we can try using kill(SIGTERM). */
 do_term:
	if (killing_supervise_pid > 3)
		goto do_kill;

	if (remaining_seconds >= sigterm_shutdown_seconds) {
		killing_supervise_pid = 3;
		kill(supervise_pid, SIGTERM);
		return;
	}

	/* No time left for any kind of friendly shutdown. */
 do_kill:
	killing_supervise_pid = 4;
	kill(supervise_pid, SIGKILL);
}

void *watchdog_thread(void *arg)
{
	int rv, fd, touch, unlink;
	time_t t;

	while (1) {
		pthread_mutex_lock(&watchdog_mutex);
		touch = wd_touch; 
		unlink = wd_unlink;
		pthread_mutex_unlock(&watchdog_mutex);

		if (unlink) {
			unlink(wd_path);
			break;
		}

		if (!touch)
			continue;

		t = 0;

		if (!wd_fd) {
			fd = open(wd_path, O_WRONLY|O_CREAT|O_NONBLOCK, 0666);
			if (fd < 0) {
				/* log error */
			} else {
				wd_fd = fd;
				t = time(NULL);
			}
		} else {
			rv = futimes(wd_fd, NULL);
			if (rv < 0) {
				/* log error */
			} else {
				t = time(NULL);
			}
		}

		if (t) {
			pthread_mutex_lock(&watchdog_mutex);
			wd_touch_time = t;
			pthread_mutex_unlock(&watchdog_mutex);
		}

		sleep(wd_touch_seconds);
	}
	return NULL;
}

int touch_watchdog(void)
{
	int rv;

	if (wd_thread)
		return 0;

	wd_touch_time = 0;
	wd_touch = 1;
	wd_fd = 0;
	wd_unlink = 0;

	snprintf(wd_path, PATH_MAX, "/var/run/sync_manager/watchdog/%s",
		 resource_id);

	rv = pthread_create(&wd_thread, &attr, watchdog_thread, NULL);
	if (rv < 0)
		return rv;

	/* TODO: wait loop here looking for wd_path to exist */

	return 0;
}

void notouch_watchdog(void)
{
	pthread_mutex_lock(&wd_mutex);
	wd_touch = 0;
	pthread_mutex_unlock(&wd_mutex);
}

void unlink_watchdog(void)
{
	void *ret;

	pthread_mutex_lock(&wd_mutex);
	wd_unlink = 1;
	pthread_mutex_unlock(&wd_mutex);

	if (!wd_thread)
		return;

	pthread_join(wd_thread, &ret);
}

int check_watchdog_thread(void)
{
	time_t t;

	pthread_mutex_lock(&wd_mutex);
	if (!wd_touch) {
		pthread_mutex_unlock(&wd_mutex);
		return 0;
	}
	t = wd_touch_time;
	pthread_mutex_unlock(&wd_mutex);

	if (time(NULL) - t > touch_fail_seconds)
		return -1;
	return 0;
}

/* return < 0 on error, 1 on success */

int acquire_lease(struct token *token, uint64_t *timestamp)
{
	struct leader_record leader;
	int rv;

	rv = disk_paxos_acquire(token, 0, opt_paxos_timeout, &leader);
	if (rv < 0)
		return rv;

	*timestamp = leader.timestamp;

	return 1;
}

/* return < 0 on error, 1 on success */

int release_lease(struct token *token, uint64_t *timestamp)
{
	struct leader_record leader;
	int rv;

	rv = disk_paxos_release(token, &leader);
	if (rv < 0)
		return rv;

	*timestamp = leader.timestamp;

	return 1;
}

/* return < 0 on error, 1 on success */

int renew_lease(struct token *token, uint64_t *timestamp)
{
	struct leader_record leader;
	int rv;

	rv = disk_paxos_renew(token, &leader);
	if (rv < 0)
		return rv;

	*timestamp = leader.timestamp;

	return 1;
}

void set_lease_status(int num, int op, int r, uint64_t t)
{
	pthread_mutex_lock(&lease_status_mutex);
	switch (op) {
	case OP_ACQUIRE:
		lease_status[num].acquire_last_result = r;
		lease_status[num].acquire_last_time = t;
		if (r == DP_OK)
			lease_status[num].acquire_good_time = t;
		/* fall through, acquire works as renewal */

	case OP_RENEWAL:
		lease_status[num].renewal_last_result = r;
		lease_status[num].renewal_last_time = t;
		if (r == DP_OK)
			lease_status[num].renewal_good_time = t;
		break;

	case OP_RELEASE:
		lease_status[num].release_last_result = r;
		lease_status[num].release_last_time = t;
		if (r == DP_OK)
			lease_status[num].release_good_time = t;
		break;
	default:
		/* log error */
	};
	pthread_mutex_unlock(&lease_status_mutex);
}

void get_lease_status(int num, int op, int *r)
{
	pthread_mutex_lock(&lease_status_mutex);
	if (op == OP_ACQUIRE) {
		*r = lease_status[num].acquire_last_result;
	} else if (op == OP_RENEWAL) {
		*r = lease_status[num].renewal_last_result;
	} else if (op == OP_RELEASE) {
		*r = lease_status[num].release_last_result;
	}
	pthread_mutex_unlock(&lease_status_mutex);
}

int check_leases_renewed(void)
{
	uint64_t oldest = 0;
	int fail_count = 0;
	int i;

	pthread_mutex_lock(&lease_status_mutex);
	for (i = 0; i < MAX_LEASES; i++) {
		if (!lease_status[i].thread_running)
			continue;

		/* this lease has not been acquired */
		if (!lease_status[i].renewal_good_time)
			continue;

		/* TODO: what about threads being stopped (stop_thread == 1)
		   when individual leases are released while continuing to run
		   with others? */

		if (!oldest || (oldest < lease_status[i].renewal_good_time))
			oldest = lease_status[i].renewal_good_time;

		if (time(NULL) - lease_status[i].renewal_good_time >=
		    lease_renewal_fail_seconds) {
			fail_count++;
			continue;
		}
	}
	pthread_mutex_unlock(&lease_status_mutex);

	oldest_renewal_time = oldest;

	if (fail_count)
		return -1;

	return 0;
}

/* tell all threads to release and exit */

void stop_lease_threads(void)
{
	int i;

	pthread_mutex_lock(&lease_status_mutex);
	for (i = 0; i < MAX_LEASES; i++) {
		if (lease_status[i].thread_running)
			lease_status[i].stop_thread = 1;
	}
	pthread_cond_broadcast(&lease_status_cond);
	pthread_mutex_unlock(&lease_status_mutex);
}

/* wait for all stopped threads to be done */

int count_running_lease_threads(void)
{
	int i, count = 0;

	pthread_mutex_lock(&lease_status_mutex);
	for (i = 0; i < MAX_LEASES; i++)
		if (lease_status[i].thread_running)
			count++;
	pthread_mutex_unlock(&lease_status_mutex);

	return count;
}

/* cleanup after stop_lease_threads() and !count_running_lease_threads() */

void cleanup_lease_threads(void)
{
	void *ret;
	int i;

	for (i = 0; i < MAX_LEASES; i++) {
		if (lease_threads[i]) {
			pthread_join(lease_threads[i], &ret);
			lease_threads[i] = NULL;
		}
	}
}

void set_thread_running(int num, int val)
{
	pthread_mutex_lock(&lease_status_mutex);
	lease_status[num].thread_running = val;
	pthread_mutex_unlock(&lease_status_mutex);
}

void *lease_thread(void *arg)
{
	struct token *token = (struct token *)arg;
	struct timespec ts;
	uint64_t timestamp;
	int num = token->num;
	int rv, num_opened;

	set_thread_running(num, 1);

	num_opened = open_disks(token);
	if (!majority_disks(token, num_opened)) {
		set_lease_status(num, OP_ACQUIRE, -ENODEV, 0);
		goto out_running;
	}

	rv = acquire_lease(token, &timestamp);
	set_lease_status(num, OP_ACQUIRE, rv, timestamp);
	if (rv < 0)
		goto out_disks;

	while (1) {
#if 0
		sleep(lease_renewal_seconds);
		pthread_mutex_lock(&lease_status_mutex);
		stop = lease_status[num].stop_thread;
		pthread_mutex_unlock(&lease_status_mutex);
		if (stop)
			break;
#endif

		pthread_mutex_lock(&lease_status_mutex);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += lease_renewal_seconds;
		rv = 0;
		while (!lease_status[num].stop_thread && rv == 0) {
			rv = pthread_cond_timedwait(&lease_status_cond,
						    &lease_status_mutex, &ts);
		}
		stop = lease_status[num].stop_thread;
		pthread_mutex_unlock(&lease_status_mutex);
		if (stop)
			break;

		rv = renew_lease(token, &timestamp);
		set_lease_status(num, OP_RENEWAL, rv, timestamp);
	}

	rv = release_lease(token, &timestamp);
	set_lease_status(num, OP_RELEASE, rv, timestamp);

 out_disks:
	close_disks(token);
 out_running:
	set_thread_running(num, 0);
	free_token(token);
	return NULL;
}

int add_lease_thread(char *name, uint32_t type, int num_disks,
		     struct paxos_disk *disks, int *num_ret)
{
	struct token *token;
	pthread_attr_t attr
	int i, rv, num, found = 0;

	token = malloc(sizeof(struct token));
	if (!token)
		return -ENOMEM;

	for (i = 0; i < MAX_LEASES; i++) {
		if (!lease_threads[i]) {
			found = 1;
			break;
		}
	}
	if (!found) {
		rv = -ENOSPC;
		goto out;
	}
	num = i;

	pthread_mutex_lock(&lease_status_mutex);
	for (i = 0; i < MAX_LEASES; i++) {
		if (!lease_status[i].thread_running)
			continue;
		if (lease_status[i].token_type != type)
			continue;
		if (strcmp(lease_status[i].token_name, name))
			continue;
		pthread_mutex_unlock(&lease_status_mutex);
		rv = -EINVAL;
		goto out;
	}
	if (lease_status[num].thread_running) {
		pthread_mutex_unlock(&lease_status_mutex);
		rv = -EINVAL;
		goto out;
	}
	strcpy(lease_status[num].token_name, name);
	lease_status[num].token_type = type;
	pthread_mutex_unlock(&lease_status_mutex);

	token->num = num;
	strncpy(token->name, name, TOKEN_NAME_SIZE);
	token->type = type;
	token->num_disks = num_disks;
	token->disks = disks;

	pthread_attr_init(&attr);
	rv = pthread_create(&lease_threads[num], &attr, lease_thread, token);
	pthread_attr_destroy(&attr);
 out:
	if (rv < 0)
		free(token);
	else
		*num_ret = num;
	return rv;
}

void del_lease_thread(int num)
{
	pthread_mutex_lock(&lease_status_mutex);
	lease_status[num].stop_thread = 1;
	pthread_mutex_unlock(&lease_status_mutex);

	/* TODO: don't block main loop waiting for the thread to quit;
	   have main loop check for stopped threads that are ready to be
	   cleaned up. */
}

/*
 * updating a lease tells other hosts we are running a vm,
 * if we can't update a lease, then another host may start
 * running the vm; this is the most important error case
 * to protect against (running vm and not updating lease).
 *
 * failure to update watchdog doesn't risk vm disk corruption,
 * but we want to try to shut down the vms as cleanly and quickly
 * as possible, ideally before the watchdog kills the host.
 *
 * If we can't update a disk lease,
 * kill the vm pid and stop updating watchdog.
 *
 * If we can't update a watchdog file, kill the vm pid (SIGKILL or SIGTERM?)
 * (and release disk leases when the pid is gone if we run that long).
 *
 * failure to release disk leases shouldn't jeopardize any vm corruption,
 * so it should be safe to unlink the watchdog files.
 */

int main_loop(void)
{
	int i, r, rv, pid_status, wd_status, poll_timeout;
	int poll_timeout = unstable_check_ms;
	int error = 0;

	while (1) {
		rv = poll(pollfd, client_maxi + 1, poll_timeout);
		if (rv == -1 && errno == EINTR) {
			continue;
		}
		if (rv < 0) {
			/* errors here unlikely, do we want to shut down,
			   i.e. kill pid / release leases, or continue
			   running with no poll? */
		}
		if (rv > 0) {
			for (i = 0; i <= client_maxi; i++) {
				if (client[i].fd < 0)
					continue;
				if (pollfd[i].revents & POLLIN) {
					workfn = client[i].workfn;
					workfn(i);
				}
				if (pollfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
					deadfn = client[i].deadfn;
					deadfn(i);
				}
			}
		}

		/*
		 * sync_manager has just been started and given an initial
		 * lease to acquire (which is always num 0).  Once the initial
		 * lease is acquired, the command should be run if one was
		 * provided.
		 */

		if (starting_lease_thread) {
			get_lease_status(0, OP_ACQUIRE, &r);
			if (r < 0) {
				/* lease_thread 0 failed to acquire lease */
				starting_lease_thread = 0;
				stopping_lease_threads = 1;
				error = r;

			} else if (r > 0) {
				/* lease_thread 0 has acquired lease */
				starting_lease_thread = 0;

				if (opt_command[0]) {
					rv = run_command(opt_command);
					if (rv < 0) {
						stopping_lease_threads = 1;
						stop_lease_threads();
						error = rv;
					}
				}
			} else {
				/* no result yet from acquire_lease by
				   lease_thread 0 */
			}

			continue;
		}

		/*
		 * sync_manager is shutting down after the supervised pid
		 * has stopped.  Waiting for lease threads to stop before
		 * unlinking watchdog file and exiting.
		 */

		if (stopping_lease_threads) {
			rv = count_running_lease_threads();
			if (!rv) {
				cleanup_lease_threads();
				if (!error)
					error = supervise_pid_exit_status;
				break;
			}

			continue;
		}

		/*
		 * if watchdog is supposed to be updated (we haven't
		 * called notouch), check that it's working.
		 */

		wd_status = check_watchdog_thread();

		if (wd_status < 0) {
			killing_supervise_pid = 1;
			kill_supervise_pid();
		}

		/*
		 * The main running case (not stopping or starting).
		 * We also continue to run through here after killing the pid,
		 * until the pid has exited at which point we shift to
		 * the stopping_lease_threads mode.
		 * Watch the pid and renew its associated leases while it
		 * continues to run.  The watchdog is one way to deal with
		 * the error case where the pid continues running but we fail
		 * to renew the leases.
		 */

		pid_status = check_supervise_pid();

		if (!pid_status) {
			/*
		 	 * pid has stopped running, stop the lease threads;
			 * this may or may not be due to us killing it.
		 	 */
			stopping_lease_threads = 1;
			stop_lease_threads();

		} else if (pid_status < 0) {
			/*
			 * can't get status, don't know if pid is running
			 * (use a secondary method to check process?)
			 *
			 * If the status of the pid is uncertain we need to
			 * continue updating the lease in case it's still
			 * running.  Limit how long we continue touching the
			 * watchdog, i.e. commit suicide eventually?
			 */
			killing_supervise_pid = 1;
			kill_supervise_pid();

			rv = check_leases_renewed();
			if (rv < 0) {
				/* just killed pid, don't need to again */
				notouch_watchdog();
			}

		} else if (pid_status > 0) {
			/*
			 * pid is running (or no pid has been set yet)
			 */
			rv = check_leases_renewed();
			if (rv < 0) {
				killing_supervise_pid = 1;
				kill_supervise_pid();
				notouch_watchdog();
			}
		}

		/* Don't check on pid and leases as often when things are in
		   a stable state: pid running and leases being updated in
		   timely fashion. */

		if ((pid_status > 0) && !killing_supervise_pid &&
		    (time(NULL) - oldest_renewal_time < lease_renewal_seconds))
			poll_timeout = stable_check_ms;
		else
			poll_timeout = unstable_check_ms;
	}

	/*
	 * TODO: what should the exit status of sync_manager be?
	 * Should it always be the exit status of the supervise_pid?
	 * Even if sync_manager kills the supervise_pid?
	 */
	if (killing_supervise_pid) {
	}

	return error;
}

void process_listener(int ci)
{
	int fd, rv;

	fd = accept(client[ci].fd, NULL, NULL);
	if (fd < 0)
		return;

	rv = do_read(fd, &h, sizeof(h));

	/* TODO: message format */

	/*
	 * read requests to:
	 * set supervise_pid (if no command was provided when daemon was started)
	 * kill supervised_pid (and release tokens when it's gone)
	 * add_lease_thread
	 * del_lease_thread
	 * transfer a token (reassign to another host when releasing it?)
	 * list leases and their status
	 * change num_hosts (is this really needed?)
	 */

	/* What kind of results/reply does the caller want?  How does it
	 * want to collect the reply?  Is the caller a new sync_tool utility,
	 * or other? */

	close(fd);
}

/* multiplex all sync_manager requests one one socket? */

int setup_listener(void)
{
	int fd;

	/* create unix socket, listen */

	client_add(fd, process_listener, NULL);
}

int lockfile(void)
{
	char buf[16];
	struct flock lock;
	int fd, error;

	snprintf(lockfile_path, PATH_MAX,
		 "/var/run/sync_manager/sync_manager_%s", resource_id);

	fd = open(lockfile_path, O_CREAT|O_WRONLY, 0666);
	if (fd < 0) {
		fprintf(stderr, "cannot open/create lock file %s\n",
			lockfile_path);
		return fd;
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	error = fcntl(fd, F_SETLK, &lock);
	if (error) {
		fprintf(stderr, "is already running\n");
		return error;
	}

	error = ftruncate(fd, 0);
	if (error) {
		fprintf(stderr, "cannot clear lock file %s\n", lockfile_path);
		return error;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d\n", getpid());

	error = write(fd, buf, strlen(buf));
	if (error <= 0) {
		fprintf(stderr, "cannot write lock file %s\n", lockfile_path);
		return rv;
	}

	return 0;
}

/*
 * resource_id, our_host_id, num_hosts, command,
 * timeouts (how many different timeouts?)
 * fill in token: name, type, num_disks, disk path(s), offset
 */ 

int read_arguments(int argc, char *argv[], struct token *token)
{
}

int main(int argc, char *argv[])
{
	int rv, num;

	rv = read_arguments(argc, argv);
	if (rv < 0)
		goto out;

	rv = lockfile();
	if (rv < 0)
		goto out;

	rv = setup_listener();
	if (rv < 0)
		goto out_lockfile;

	rv = touch_watchdog();
	if (rv < 0)
		goto out_lockfile;

	if (opt_token_name[0]) {
		rv = add_lease_thread(opt_token_name, opt_token_type,
				      opt_num_disks, opt_disks, &num);
		if (rv < 0)
			goto out_watchdog;

		starting_lease_thread = 1;

		/* once the lease is acquired, the main loop will run
		   opt_command if there is one */
	}

	/* there was no initial lease, just a command (a lease may be
	   added later) */

	if (!starting_lease_thread && opt_command[0]) {
		rv = run_command(opt_command);
		if (rv < 0)
			goto out_watchdog;
	}

	rv = main_loop();

 out_watchdog:
	unlink_watchdog();
 out_lockfile:
	unlink(lockfile_path);
 out:
	return rv;
}

