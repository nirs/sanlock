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
#include "sm.h"

static int client_maxi;
static int client_size = 0;
static struct client *client = NULL;
static struct pollfd *pollfd = NULL;

#define COMMAND_MAX 1024
char command[COMMAND_MAX];
char killscript[COMMAND_MAX];
char resource_id[NAME_ID_SIZE + 1];
uint64_t our_host_id;
uint64_t num_hosts;
struct paxos_disk tmp_disks[MAX_DISKS];
int cmd_argc;
char **cmd_argv;

int opt_watchdog = 1;
char lockfile_path[PATH_MAX];
int supervise_pid;
int killscript_pid;
int supervise_pid_exit_status;
int starting_lease_thread;
int stopping_lease_threads;
int killing_supervise_pid;
int external_shutdown;

#define MAX_LEASES 64
pthread_t lease_threads[MAX_LEASES];
pthread_mutex_t lease_status_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lease_status_cond = PTHREAD_COND_INITIALIZER;
struct lease_status lease_status[MAX_LEASES];
struct token *tokens[MAX_LEASES];
time_t oldest_renewal_time; /* timestamp of oldest lease renewal */

pthread_t wd_thread;
pthread_mutex_t wd_mutex = PTHREAD_MUTEX_INITIALIZER;
int wd_touch;
int wd_unlink;
int wd_fd;
char wd_path[PATH_MAX];
int wd_create_result;
int wd_touch_last_result;
time_t wd_create_time;
time_t wd_touch_last_time;
time_t wd_touch_good_time;

#define LOG_STR_LEN 256
char log_str[LOG_STR_LEN];
#define SM_DUMP_SIZE (1024*1024)
char log_dump[SM_DUMP_SIZE];
int log_point;
int log_wrap;
int log_logfile_priority; /* syslog.h */
int log_syslog_priority; /* syslog.h */
int log_stderr_priority; /* syslog.h */
char logfile_path[PATH_MAX];
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * lease_timeout_seconds
 * disk paxos takes over lease if it's not been renewed for this long
 *
 * lease_renewal_fail_seconds
 * sm starts recovery if one of its leases hasn't renewed in this time
 *
 * lease_renewal_seconds
 * sm tries to renew a lease this often
 *
 * wd_touch_seconds
 * sm touches a watchdog file this often
 *
 * wd_reboot_seconds
 * wd daemon reboots if it finds a wd file older than this (unused?)
 *
 * wd_touch_fail_seconds
 * sm starts recovery if the wd thread hasn't touched wd file in this time
 *
 * script_shutdown_seconds
 * use killscript if this many seconds remain (or >) until lease can be taken
 *
 * sigterm_shutdown_seconds
 * use SIGTERM if this many seconds remain (or >) until lease can be taken
 *
 * stable_poll_ms
 * check pid and lease status this often when things appear to be stable
 *
 * unstable_poll_ms
 * check pid and lease status this often when things are changing
 */

struct sm_timeouts {
	int lease_timeout_seconds;
	int lease_renewal_fail_seconds;
	int lease_renewal_seconds;
	int wd_touch_seconds;
	int wd_reboot_seconds;
	int wd_touch_fail_seconds;
	int script_shutdown_seconds;
	int sigterm_shutdown_seconds;
	int stable_poll_ms;
	int unstable_poll_ms;
};

struct sm_timeouts to;

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

	char token_name[NAME_ID_SIZE + 1];
};

struct client {
	int fd;
	void *workfn;
	void *deadfn;
};

/* log_dump can be sent over unix socket */

void log_save_dump(int level, char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		log_dump[log_point++] = log_str[i];

		if (log_point == SM_DUMP_SIZE) {
			log_point = 0;
			log_wrap = 1;
		}
	}
}

/* add a log entry, a thread will write log entries to logfile and/or syslog */

void log_save_file(int level, char *buf, int len)
{
}

void log_level(struct token *token, int level, char *fmt, ...)
{
	va_list ap;
	int ret, pos = 0;
	int len = LOG_STR_LEN - 2; /* leave room for \n\0 */

	pthread_mutex_lock(&log_mutex);

	ret = snprintf(log_str + pos, len - pos, "%s %ld %s ",
		       resource_id, time(NULL), token ? token->name : "-");
	pos += ret;

	va_start(ap, fmt);
	ret = vsnprintf(log_str + pos, len - pos, fmt, ap);
	va_end(ap);

	if (ret >= len - pos)
		pos = len - 1;
	else
		pos += ret;

	log_str[pos++] = '\n';
	log_str[pos++] = '\0';

	log_save_dump(level, log_str, pos - 1);

	if (level <= log_logfile_priority || level <= log_syslog_priority)
		log_save_file(level, log_str, pos - 1);

	if (level <= log_stderr_priority)
		fprintf(stderr, "%s", log_str);

	pthread_mutex_unlock(&log_mutex);
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
 * 0 is pid is not running (or no pid was started and main loop is killing)
 * < 0 on a waitpid error, don't know what these conditions are
 */

int check_supervise_pid(void)
{
	int rv, status, kill_status;

	if (!supervise_pid && killing_supervise_pid)
		return 0;

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
		execl(killscript, NULL);
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
		execv(command, cmd_argv);
		return -1;
	}
}

/* TODO: limit repeated calls to killscript/kill() when this function
   is called repeatedly */

void kill_supervise_pid(void)
{
	uint64_t expire_time, remaining_seconds;

	if (!killing_supervise_pid)
		killing_supervise_pid = 1;

	if (!supervise_pid)
		return 0;

	expire_time = oldest_renewal_time + to.lease_timeout_seconds;

	if (time(NULL) >= expire_time)
		goto do_kill:

	remaining_seconds = expire_time - time(NULL);

	if (!killscript_command[0])
		goto do_term;

	/* While we have more than script_shutdown_seconds until our
	   lease expires, we can try using killscript. */

	if (killing_supervise_pid > 2)
		goto do_term;

	if (remaining_seconds >= to.script_shutdown_seconds) {
		killing_supervise_pid = 2;
		run_killscript();
		return;
	}

	/* While we have more than sigterm_shutdown_seconds until our
	   lease expires, we can try using kill(SIGTERM). */
 do_term:
	if (killing_supervise_pid > 3)
		goto do_kill;

	if (remaining_seconds >= to.sigterm_shutdown_seconds) {
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
	int rv, fd, touch, unlink, create;
	time_t t;

	while (1) {
		create = 0;

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

		if (!wd_fd) {
			fd = open(wd_path, O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK,
				  0666);
			if (fd < 0) {
				rv = fd;
			} else {
				rv = 0;
				wd_fd = fd;
			}
			create = 1;
		} else {
			rv = futimes(wd_fd, NULL);
		}
		t = time(NULL);

		pthread_mutex_lock(&watchdog_mutex);
		if (create) {
			wd_create_result = fd;
			wd_create_time = t;
		}
		wd_touch_last_result = rv;
		wd_touch_last_time = t;
		if (!rv)
			wd_touch_good_time = t;
		pthread_mutex_unlock(&watchdog_mutex);

		/* TODO: use a pthread_cond_timedwait() here so
		   unlink_watchdog can be quicker? */

		sleep(to.wd_touch_seconds);
	}
	return NULL;
}

void unlink_watchdog(void)
{
	void *ret;

	if (!opt_watchdog)
		return 0;

	pthread_mutex_lock(&wd_mutex);
	wd_unlink = 1;
	pthread_mutex_unlock(&wd_mutex);

	if (!wd_thread)
		return;

	pthread_join(wd_thread, &ret);
	wd_thread = NULL;
}

int touch_watchdog(void)
{
	time_t t, start;
	int rv;

	if (!opt_watchdog)
		return 0;

	if (wd_thread)
		return 0;

	wd_touch_time = 0;
	wd_touch = 1;
	wd_fd = 0;
	wd_unlink = 0;
	wd_create_result = 0;
	wd_create_time = 0;
	wd_touch_last_result = 0;
	wd_touch_last_time = 0;

	snprintf(wd_path, PATH_MAX,
		 "/var/run/sync_manager/watchdog/%s", resource_id);

	rv = pthread_create(&wd_thread, &attr, watchdog_thread, NULL);
	if (rv < 0)
		return rv;

	start = time(NULL);

	while (1) {
		pthread_mutex_lock(&wd_mutex);
		rv = wd_create_result;
		t = wd_create_time;
		pthread_mutex_unlock(&wd_mutex);

		if (t)
			break;

		if (time(NULL) - start > to.wd_touch_fail_seconds) {
			rv = -1;
			break;
		}

		usleep(10000);
	}

	if (rv < 0)
		unlink_watchdog();
	else
		rv = 0;

	return rv;
}

void notouch_watchdog(void)
{
	pthread_mutex_lock(&wd_mutex);
	wd_touch = 0;
	pthread_mutex_unlock(&wd_mutex);
}

int check_watchdog_thread(void)
{
	int touch, rv;
	time_t t;

	if (!opt_watchdog)
		return 0;

	if (!wd_thread)
		return 0;

	pthread_mutex_lock(&wd_mutex);
	touch = wd_touch;
	t = wd_touch_good_time;
	pthread_mutex_unlock(&wd_mutex);

	if (!touch)
		return 0;

	if (time(NULL) - t > to.wd_touch_fail_seconds)
		return -1;
	return 0;
}

/* return < 0 on error, 1 on success */

int acquire_lease(struct token *token, uint64_t *timestamp)
{
	struct leader_record leader;
	int rv;

	rv = disk_paxos_acquire(token, 0, &leader);
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

		if (lease_status[i].stop_thread)
			continue;

		/* this lease has not been acquired */
		if (!lease_status[i].renewal_good_time)
			continue;

		if (!oldest || (oldest < lease_status[i].renewal_good_time))
			oldest = lease_status[i].renewal_good_time;

		if (time(NULL) - lease_status[i].renewal_good_time >=
		    to.lease_renewal_fail_seconds) {
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

void cleanup_lease_threads(void)
{
	struct token *token;
	int i;
	void *ret;

	for (i = 0; i < MAX_LEASES; i++) {
		if (lease_threads[i]) {
			pthread_join(lease_threads[i], &ret);
			lease_threads[i] = NULL;
		}
	}

	for (i = 0; i < MAX_LEASES; i++) {
		token =  tokens[i];
		if (token) {
			free(token->disks);
			free(token);
			tokens[i] = NULL;
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
		log_error(token, "cannot open majority of disks");
		set_lease_status(num, OP_ACQUIRE, -ENODEV, 0);
		goto out_running;
	}

	rv = acquire_lease(token, &timestamp);
	set_lease_status(num, OP_ACQUIRE, rv, timestamp);
	if (rv < 0) {
		log_error(token, "acquire lease failed %d", rv);
		goto out_disks;
	}

	while (1) {
#if 0
		sleep(to.lease_renewal_seconds);
		pthread_mutex_lock(&lease_status_mutex);
		stop = lease_status[num].stop_thread;
		pthread_mutex_unlock(&lease_status_mutex);
		if (stop)
			break;
#endif

		pthread_mutex_lock(&lease_status_mutex);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += to.lease_renewal_seconds;
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
		if (rv < 0)
			log_error(token, "renew lease failed %d", rv);
	}

	rv = release_lease(token, &timestamp);
	set_lease_status(num, OP_RELEASE, rv, timestamp);

 out_disks:
	close_disks(token);
 out_running:
	set_thread_running(num, 0);
	return NULL;
}

/* the disk_paxos structs in global tmp_disks */

int add_lease_thread(char *name, int num_disks, int *num_ret)
{
	struct token *token;
	struct paxos_disk *disks;
	pthread_attr_t attr
	int i, rv, num, found = 0;

	token = malloc(sizeof(struct token));
	if (!token)
		return -ENOMEM;
	memset(token, 0, sizeof(struct token));

	disks = malloc(num_disks * sizeof(struct paxos_disk));
	if (!disks) {
		free(token);
		return -ENOMEM;
	}

	memcpy(disks, &tmp_disks, num_disks * sizeof(struct paxos_disk));
	token->disks = disks;
	token->num_disks = num_disks;
	strncpy(token->name, name, NAME_ID_SIZE);

	disks = NULL;
	memset(&tmp_disks, 0, num_disks * sizeof(struct paxos_disk));

	/* find an unused lease num, only main loop accesses lease_threads[],
	   no locking needed */

	for (i = 0; i < MAX_LEASES; i++) {
		if (!lease_threads[i]) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error(token, "add lease failed, max leases in use");
		rv = -ENOSPC;
		goto out;
	}

	num = i;
	token->num = i;

	/* verify that the tokens slot is unused, only main loop accesses
	   tokens[], no locking needed */

	if (tokens[num]) {
		log_error(token, "add lease failed, num %d is used", num);
		rv = -EINVAL;
		goto out;
	}

	/* verify that this lease_status slot is unused in lease_status[],
	   and that that the token_name is not already used */

	pthread_mutex_lock(&lease_status_mutex);
	for (i = 0; i < MAX_LEASES; i++) {
		if (!lease_status[i].thread_running)
			continue;
		if (strcmp(lease_status[i].token_name, name))
			continue;
		pthread_mutex_unlock(&lease_status_mutex);
		rv = -EINVAL;
		goto out;
	}
	if (lease_status[num].thread_running) {
		pthread_mutex_unlock(&lease_status_mutex);
		log_error(token, "add lease failed, thread %d running", num);
		rv = -EINVAL;
		goto out;
	}
	strncpy(lease_status[num].token_name, name, NAME_ID_SIZE);
	pthread_mutex_unlock(&lease_status_mutex);

	pthread_attr_init(&attr);
	rv = pthread_create(&lease_threads[num], &attr, lease_thread, token);
	pthread_attr_destroy(&attr);
 out:
	if (rv < 0) {
		log_error(token, "add lease failed, thread create %d", rv);
		free(token->disks);
		free(token);
	} else {
		tokens[num] = token;
		*num_ret = num;
	}
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
	int poll_timeout = to.unstable_check_ms;
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

				if (command[0]) {
					rv = run_command(command);
					if (rv < 0) {
						stopping_lease_threads = 1;
						stop_lease_threads();
						unlink_watchdog();
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
		 * has stopped.  pthread_join lease threads and free tokens */
		 */

		if (stopping_lease_threads) {
			cleanup_lease_threads();
			/* error may be set from initial lease acquire
			   or run_command */
			if (!error)
				error = supervise_pid_exit_status;
			break;
		}

		/*
		 * someone has asked sync_manager to shut down
		 */

		if (external_shutdown) {
			kill_supervise_pid();
		}

		/*
		 * if watchdog is supposed to be updated (we haven't
		 * called notouch), check that it's working.
		 */

		wd_status = check_watchdog_thread();
		if (wd_status < 0)
			kill_supervise_pid();

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
			unlink_watchdog();

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
				kill_supervise_pid();
				notouch_watchdog();
			}
		}

		/* Don't check on pid and leases as often when things are in
		   a stable state: pid running and leases being updated in
		   timely fashion. */

		if ((pid_status > 0) && !killing_supervise_pid &&
		    !stopping_lease_threads && !starting_lease_threads &&
		    (time(NULL) - oldest_renewal_time < to.lease_renewal_seconds))
			poll_timeout = to.stable_check_ms;
		else
			poll_timeout = to.unstable_check_ms;
	}

	return error;
}


struct sm_header {
	uint32_t magic;
	uint32_t version;
	uint32_t cmd;
	uint32_t length;
	uint32_t info_len;
	uint32_t seq;
	uint32_t data;
	uint32_t unused;
	char resource_id[NAME_ID_SIZE];
};

struct sm_info {
	char command[COMMAND_MAX];
	char killscript[COMMAND_MAX];
	uint64_t our_host_id;
	uint64_t num_hosts;

	int supervise_pid;
	int supervise_pid_exit_status;
	int starting_lease_thread;
	int stopping_lease_threads;
	int killing_supervise_pid;
	int external_shutdown;

	/* TODO: include wd info */

	uint64_t current_time;
	uint64_t oldest_renewal_time;
	int oldest_renewal_num;

	uint32_t lease_info_len;
	uint32_t lease_info_count;
};

struct sm_lease_info {
	char token_name[NAME_ID_SIZE];
	uint32_t token_type;
	int num;
	int stop_thread;
	int thread_running;

	int acquire_last_result;
	int renewal_last_result;
	int release_last_result;
	uint64_t acquire_last_time;
	uint64_t acquire_good_time;
	uint64_t renewal_last_time;
	uint64_t renewal_good_time;
	uint64_t release_last_time;
	uint64_t release_good_time;

	uint32_t disk_info_len;
	uint32_t disk_info_count;
};

struct sm_disk_info {
	uint64_t offset;
	char path[DISK_PATH_LEN];
};

void cmd_status(int fd, struct sm_header *h_recv)
{
	/* no more to recv */

	/* reply:
	   struct sm_header +
	   struct sm_info +
	   N * (struct sm_lease_info + (M * struct sm_disk_info)) */
}

void process_listener(int ci)
{
	struct sm_header h;
	int fd, rv;

	fd = accept(client[ci].fd, NULL, NULL);
	if (fd < 0)
		return;

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h)) {
	}

	if (h.magic != SM_MAGIC) {
	}

	if (strcmp(resource_id, h.resource_id)) {
	}

	switch (h.cmd) {
	case SM_CMD_GET_TIMEOUTS:
		/* memcpy(sdata, &to, sizeof(to)); */
		break;
	case SM_CMD_SET_TIMEOUTS:
		/* memcpy(&to, rdata, sizeof(to)); */
		break;
	case SM_CMD_SHUTDOWN:
		external_shutdown = 1;
		send_reply_ok(fd, &h);
		break;
	case SM_CMD_SUPERVISE_PID:
		if (!supervise_pid)
			supervise_pid = atoi(h.data);
		send_reply_ok(fd, &h);
		break;
	case SM_CMD_NUM_HOSTS:
		/* just rewrite leader block in leases? */
		break;
	case SM_CMD_ADD_LEASE:
		/* add_lease_thread(), get_lease_status(OP_ACQUIRE) loop */
		break;
	case SM_CMD_DEL_LEASE:
		/* del_lease_thread() */
		break;
	case SM_CMD_STATUS:
		cmd_status(fd, &h);
		break;
	case SM_CMD_DUMP_DEBUG:
		/* send back debug buffer */
		break;
	default:
	};

	close(fd);
}

int setup_listener(void)
{
	char path[PATH_MAX];
	struct sockaddr_un addr;
	socklen_t addrlen;
	int rv, s;

	/* we listen for new client connections on socket s */

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0) {
		log_error("socket error %d %d", s, errno);
		return s;
	}

	snprintf(path, PATH_MAX,
		 "/var/run/sync_manager/sockets/%s", resource_id);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strncpy(&addr.sun_path[1], sock_path, PATH_MAX - 1);
	addrlen = sizeof(sa_family_t) + strlen(addr.sun_path+1) + 1;

	rv = bind(s, (struct sockaddr *) &addr, addrlen);
	if (rv < 0) {
		log_error("bind error %d %d", rv, errno);
		close(s);
		return rv;
	}

	rv = listen(s, 5);
	if (rv < 0) {
		log_error("listen error %d %d", rv, errno);
		close(s);
		return rv;
	}

	client_add(s, process_listener, NULL);
	return 0;
}

int lockfile(void)
{
	char buf[16];
	struct flock lock;
	int fd, error;

	snprintf(lockfile_path, PATH_MAX,
		 "/var/run/sync_manager/lockfiles/%s", resource_id);

	fd = open(lockfile_path, O_CREAT|O_WRONLY|O_CLOEXEC, 0666);
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

void print_usage(void)
{
	printf("Usage:\n");
	printf("sync_manager [options] [-c <path> <args>]\n\n");
	printf("Options:\n");
	printf("  -D			print all logging to stderr\n");
	printf("  -L <level>		write logging at level and up to logfile (-1 none)\n");
	printf("  -S <level>		write logging at level and up to syslog (-1 none)\n");
	printf("  -r <name>		resource id\n");
	printf("  -i <num>		local host id\n");
	printf("  -n <num>		number of hosts\n");
	printf("  -t <name>		token (lease) name\n");
	printf("  -d <path>:<offset>	disk path and offset\n");
	printf("  -k <path>		command to stop supervised process\n");
	printf("  -w <num>		enable (1) or disable (0) using watchdog\n");
	printf("  -c <path> <args>	run command with args, -c must be final option\n");
}

int add_tmp_disk(int d, char *arg)
{
	char *p;
	int rv;

	if (d > MAX_DISKS) {
		fprintf(stderr, "disk option (-d) limit is %d\n", MAX_DISKS);
		return -EINVAL;
	}

	p = strstr(arg, ":");
	if (!p) {
		fprintf(stderr, "disk option (-d) missing :offset\n");
		return -EINVAL;
	}

	*p = '\0';
	p++;

	strncpy(tmp_disks[d].path, arg, DISK_PATH_LEN - 1);

	rv = sscanf(p, "%llu", &tmp_disks[d].offset);
	if (rv != 1) {
		fprintf(stderr, "disk option (-d) invalid offset\n");
		return -EINVAL;
	}
}

/* TODO: option to start up as the receiving side of a transfer
   from another host.  Watch the other host's lease renewals until
   the other host writes our hostid is written in the leader block,
   at which point the lease is ours and we start doing the renewals.
 
   TODO: option to transfer the ownership of all leases to a specified
   hostid, then watch for pid to exit? */

#define RELEASE_VERSION "0.0"

int read_args(int argc, char *argv[], char *token_name, int *num_disks_out)
{
	char optchar;
	char *optarg;
	char *p;
	char *arg1 = argv[1];
	int optarg_used;
	int num_disks = 0;
	int i, j, len;
	int begin_command = 0;

	if (argc < 2 || !strcmp(arg1, "--help") || !strcmp(arg1, "-h")) {
		print_usage();
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "--version") || !strcmp(arg1, "-V")) {
		printf("%s %s (built %s %s)\n",
		       argv[0], RELEASE_VERSION, __DATE__, __TIME__);
		exit(EXIT_SUCCESS);
	}

	if (argc < 2)
		return;

	for (i = 1; i < argc; ) {
		p = argv[i];

		if ((p[0] != '-') || (strlen(p) != 2)) {
			fprintf(stderr, "unknown option %s\n", p);
			print_usage();
			exit(EXIT_FAILURE);
		}

		optchar = p[1];
		i++;

		optarg = argv[i];
		optarg_used = 1;

		switch (optchar) {
		case 'D':
			log_stderr_priority = LOG_DEBUG;
			optarg_used = 0;
			break;
		case 'L':
			log_logfile_priority = atoi(optarg);
			break;
		case 'S':
			log_syslog_priority = atoi(optarg);
			break;
		case 'r':
			strncpy(resource_id, optarg, NAME_ID_SIZE);
			break;
		case 'i':
			our_host_id = atoi(optarg);
			break;
		case 'n':
			num_hosts = atoi(optarg);
			break;
		case 't':
			strncpy(token_name, optarg, NAME_ID_SIZE);
			break;
		case 'd':
			num_disks++;
			rv = add_tmp_disk(num_disks - 1, optarg);
			if (rv < 0)
				return rv;
			break;
		case 'k':
			strncpy(killscript, optarg, COMMAND_MAX - 1);
			break;
		case 'w':
			opt_watchdog = atoi(optarg);
			break;
		case 'c':
			begin_command = 1;
			optarg_used = 0;
			break;
		default:
			fprintf(stderr, "unknown option: %c", optchar);
			break;
		};

		if (optarg_used)
			i++;

		if (begin_command)
			break;
	}

	/* 
	 * the remaining args are for the command
	 * 
	 * sync_manager -r foo -n 2 -d bar:0 -c /bin/cmd -X -Y -Z
	 * argc = 12
	 * loop above breaks with i = 7, argv[7] = "-c"
	 *
	 * cmd_argc = 4 = argc (12) - i (7) - 1
	 * cmd_argv[0] = "/bin/cmd"
	 * cmd_argv[1] = "-X"
	 * cmd_argv[2] = "-Y"
	 * cmd_argv[3] = "-Z"
	 * cmd_argv[4] = NULL (required by execv)
	 */

	if (begin_command) {
		cmd_argc = argc - i - 1;

		if (cmd_argc < 1) {
			fprintf("command option (-c) requires an arg\n");
			exit(EXIT_FAILURE);
		}

		len = (cmd_argc + 1) * sizeof(char *); /* +1 for final NULL */
		cmd_argv = malloc(len);
		if (!cmd_argv)
			return -ENOMEM;
		memset(cmd_argv, 0, len);

		/* place i at arg following "-c", e.g. argv[8] "/bin/cmd" */
		i++;
		j = 0;

		for (j = 0; j < cmd_argc; j++) {
			cmd_argv[j] = strdup(argv[i++]);
			if (!cmd_argv[j])
				return -ENOMEM;
		}

		strncpy(command, cmd_argv[0], COMMAND_MAX - 1);
	}

	*num_disks_out = num_disks;
	return 0;
}

void sigterm_handler(int sig)
{
	external_shutdown = 1;
}

int main(int argc, char *argv[])
{
	char token_name[NAME_ID_SIZE + 1];
	int num_disks = 0;
	int rv, num;

	/* default logging: LOG_ERR and up to stderr, logfile and syslog */

	log_stderr_priority = LOG_ERR;
	log_logfile_priority = LOG_ERR;
	log_syslog_priority = LOG_ERR;

	to.lease_timeout_seconds = 60;
	to.lease_renewal_fail_seconds = 40;
	to.lease_renewal_seconds = 10;
	to.wd_touch_seconds = 4;
	to.wd_reboot_seconds = 15;
	to.wd_touch_fail_seconds = 10;
	to.script_shutdown_seconds = 10;
	to.sigterm_shutdown_seconds = 10;
	to.stable_poll_ms = 2000;
	to.unstable_poll_ms = 500;

	rv = read_args(argc, argv, token_name, &num_disks);
	if (rv < 0)
		goto out;

	signal(SIGTERM, sigterm_handler);

	rv = lockfile();
	if (rv < 0)
		goto out;

	rv = setup_listener();
	if (rv < 0)
		goto out_lockfile;

	if (num_disks) {
		rv = touch_watchdog();
		if (rv < 0)
			goto out_lockfile;

		rv = add_lease_thread(token_name, num_disks, disks, &num);
		if (rv < 0)
			goto out_watchdog;

		starting_lease_thread = 1;

		/* once the lease is acquired, the main loop will run
		   command if there is one */
	}

	/* there was no initial lease, just a command (a lease may be
	   added later) */

	if (!starting_lease_thread && command[0]) {
		rv = run_command(command);
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

