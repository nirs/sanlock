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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "sm.h"
#include "sm_msg.h"
#include "disk_paxos.h"
#include "log.h"

#define CLIENT_NALLOC 2

struct client {
	int fd;
	void *workfn;
	void *deadfn;
};

static int client_maxi;
static int client_size = 0;
static struct client *client = NULL;
static struct pollfd *pollfd = NULL;

/* priorities are LOG_* from syslog.h */
int log_logfile_priority;
int log_syslog_priority;
int log_stderr_priority;

char command[COMMAND_MAX];
char killscript[COMMAND_MAX];
char sm_id[NAME_ID_SIZE + 1];
int our_host_id;
int cmd_argc;
char **cmd_argv;

int opt_watchdog = 1;
int supervise_pid;
int killscript_pid;
int supervise_pid_exit_status;
int starting_lease_thread;
int stopping_lease_threads;
int killing_supervise_pid;
int external_shutdown;
struct sm_timeouts to;

#define OP_ACQUIRE 1
#define OP_RENEWAL 2
#define OP_RELEASE 3

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

	char resource_id[NAME_ID_SIZE + 1];
};

pthread_t lease_threads[MAX_LEASES];
pthread_mutex_t lease_status_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t lease_status_cond = PTHREAD_COND_INITIALIZER;
struct lease_status lease_status[MAX_LEASES];
struct token *tokens[MAX_LEASES];
time_t oldest_renewal_time; /* timestamp of oldest lease renewal */

pthread_t wd_thread;
pthread_mutex_t wd_mutex = PTHREAD_MUTEX_INITIALIZER;
int wd_thread_running;
int wd_touch;
int wd_unlink;
int wd_fd;
char wd_path[PATH_MAX];
int wd_create_result;
int wd_touch_last_result;
time_t wd_create_time;
time_t wd_touch_last_time;
time_t wd_touch_good_time;

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
			log_error(NULL, "can't alloc for pollfd");
	}
	if (!client || !pollfd)
		log_error(NULL, "can't alloc for client array");

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

int lockfile(struct token *token, char *dir, char *name)
{
	char path[PATH_MAX];
	char buf[16];
	struct flock lock;
	int fd, rv;

	snprintf(path, PATH_MAX, "%s/%s", dir, name);

	fd = open(path, O_CREAT|O_WRONLY|O_CLOEXEC, 0666);
	if (fd < 0) {
		log_error(token, "lockfile open error %d", errno);
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	rv = fcntl(fd, F_SETLK, &lock);
	if (rv < 0) {
		log_error(token, "lockfile setlk error %d", errno);
		goto fail;
	}

	rv = ftruncate(fd, 0);
	if (rv < 0) {
		log_error(token, "lockfile truncate error %d", errno);
		goto fail;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d\n", getpid());

	rv = write(fd, buf, strlen(buf));
	if (rv <= 0) {
		log_error(token, "lockfile write error %d", errno);
		goto fail;
	}

	return fd;
 fail:
	close(fd);
	return -1;
}

void unlink_lockfile(int fd, char *dir, char *name)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", dir, name);
	unlink(path);
	close(fd);
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
			log_error(NULL, "open error %d %s", fd, disk->path);
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

	return 0;
}

/*
 * return values:
 * 1 if pid is running (or pid has not been set yet)
 * 0 is pid is not running (or no pid was started and main loop is killing)
 * < 0 on a waitpid error, don't know what these conditions are
 */

int check_supervise_pid(void)
{
	int rv, status;

	if (!supervise_pid && killing_supervise_pid)
		return 0;

	if (!supervise_pid)
		return 1;

	rv = waitpid(supervise_pid, &status, WNOHANG);
	if (!rv)
		return 1;
	if (rv < 0) {
		log_error(NULL, "waitpid errno %d supervise_pid %d",
			  errno, supervise_pid);
		return rv;
	}

	if (WIFEXITED(status)) {
		supervise_pid_exit_status = WEXITSTATUS(status);
		log_debug(NULL, "supervise_pid %d exit status %d",
			  supervise_pid, supervise_pid_exit_status);
		check_killscript_pid();
		supervise_pid = 0;
		return 0;
	}

	return 1;
}

int run_killscript(void)
{
	int pid;
	char *av[2];

	pid = fork();
	if (pid < 0)
		return pid;

	if (pid) {
		killscript_pid = pid;
		return 0;
	} else {
		av[0] = strdup(killscript);
		av[1] = NULL;
		execv(killscript, NULL);
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
		log_debug(NULL, "supervise_pid %d", pid);
		return 0;
	} else {
		execv(command, cmd_argv);
		log_error(NULL, "execv failed errno %d command %s",
			  errno, command);
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
		return;

	expire_time = oldest_renewal_time + to.lease_timeout_seconds;

	if (time(NULL) >= expire_time)
		goto do_kill;

	remaining_seconds = expire_time - time(NULL);

	if (!killscript[0])
		goto do_term;

	/* While we have more than script_shutdown_seconds until our
	   lease expires, we can try using killscript. */

	if (killing_supervise_pid > 2)
		goto do_term;

	if (remaining_seconds >= to.script_shutdown_seconds) {
		if (killing_supervise_pid < 2)
			log_error(NULL, "kill %d killscript", supervise_pid);
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
		if (killing_supervise_pid < 3)
			log_error(NULL, "kill %d sigterm", supervise_pid);
		killing_supervise_pid = 3;
		kill(supervise_pid, SIGTERM);
		return;
	}

	/* No time left for any kind of friendly shutdown. */
 do_kill:
	if (killing_supervise_pid < 4)
		log_error(NULL, "kill %d sigkill", supervise_pid);
	killing_supervise_pid = 4;
	kill(supervise_pid, SIGKILL);
}

void *watchdog_thread(void *arg)
{
	int rv, fd, do_touch, do_unlink, do_create;
	time_t t;

	while (1) {
		do_create = 0;

		pthread_mutex_lock(&wd_mutex);
		do_touch = wd_touch; 
		do_unlink = wd_unlink;
		pthread_mutex_unlock(&wd_mutex);

		if (do_unlink) {
			unlink(wd_path);
			log_debug(NULL, "unlinked watchdog file");
			break;
		}

		if (!do_touch)
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
			do_create = 1;
		} else {
			rv = futimes(wd_fd, NULL);
		}
		t = time(NULL);

		pthread_mutex_lock(&wd_mutex);
		if (do_create) {
			wd_create_result = fd;
			wd_create_time = t;
		}
		wd_touch_last_result = rv;
		wd_touch_last_time = t;
		if (!rv)
			wd_touch_good_time = t;
		pthread_mutex_unlock(&wd_mutex);

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
		return;

	pthread_mutex_lock(&wd_mutex);
	wd_unlink = 1;
	pthread_mutex_unlock(&wd_mutex);

	if (!wd_thread_running)
		return;

	pthread_join(wd_thread, &ret);
	wd_thread_running = 0;
}

int touch_watchdog(void)
{
	pthread_attr_t attr;
	time_t t, start;
	int rv;

	if (!opt_watchdog)
		return 0;

	if (wd_thread_running)
		return 0;

	wd_touch = 1;
	wd_fd = 0;
	wd_unlink = 0;
	wd_create_result = 0;
	wd_create_time = 0;
	wd_touch_last_result = 0;
	wd_touch_last_time = 0;

	snprintf(wd_path, PATH_MAX, "%s/%s", DAEMON_WATCHDOG_DIR, sm_id);

	pthread_attr_init(&attr);
	rv = pthread_create(&wd_thread, &attr, watchdog_thread, NULL);
	pthread_attr_destroy(&attr);
	if (rv < 0) {
		log_error(NULL, "create wd_thread failed %d", rv);
		return rv;
	}
	wd_thread_running = 1;

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

	if (rv < 0) {
		log_error(NULL, "create watchdog file failed %d", rv);
		unlink_watchdog();
	} else {
		log_debug(NULL, "create watchdog file at %llu",
			  (unsigned long long)wd_create_time);
		rv = 0;
	}

	return rv;
}

void notouch_watchdog(void)
{
	time_t log_t = 0;

	pthread_mutex_lock(&wd_mutex);
	if (wd_touch)
		log_t = wd_touch_good_time;
	wd_touch = 0;
	pthread_mutex_unlock(&wd_mutex);

	if (log_t)
		log_error(NULL, "touch watchdog file stopped last %llu",
			  (unsigned long long)log_t);
}

int check_watchdog_thread(void)
{
	int touch;
	time_t t;

	if (!opt_watchdog)
		return 0;

	if (!wd_thread_running)
		return 0;

	pthread_mutex_lock(&wd_mutex);
	touch = wd_touch;
	t = wd_touch_good_time;
	pthread_mutex_unlock(&wd_mutex);

	if (!touch)
		return 0;

	if (time(NULL) - t > to.wd_touch_fail_seconds) {
		log_error(NULL, "touch watchdog file last %llu timeout %d",
			  (unsigned long long)t, to.wd_touch_fail_seconds);
		return -1;
	}
	return 0;
}

/* return < 0 on error, 1 on success */

int acquire_lease(struct token *token, struct leader_record *leader)
{
	struct leader_record leader_ret;
	int rv;

	rv = disk_paxos_acquire(token, 0, &leader_ret);
	if (rv < 0)
		return rv;

	memcpy(leader, &leader_ret, sizeof(struct leader_record));
	return 1;
}

/* return < 0 on error, 1 on success */

int renew_lease(struct token *token, struct leader_record *leader)
{
	struct leader_record leader_ret;
	int rv;

	rv = disk_paxos_renew(token, leader, &leader_ret);
	if (rv < 0)
		return rv;

	memcpy(leader, &leader_ret, sizeof(struct leader_record));
	return 1;
}

/* return < 0 on error, 1 on success */

int release_lease(struct token *token, struct leader_record *leader)
{
	struct leader_record leader_ret;
	int rv;

	rv = disk_paxos_release(token, leader, &leader_ret);
	if (rv < 0)
		return rv;

	memcpy(leader, &leader_ret, sizeof(struct leader_record));
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
		log_error(NULL, "invalid op %d", op);
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
	uint64_t sec, oldest = 0;
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

		sec = time(NULL) - lease_status[i].renewal_good_time;

		if (sec >= to.lease_renewal_fail_seconds) {
			fail_count++;
			log_error(tokens[i], "renewal fail last result %d "
				  "at %llu good %llu",
				  lease_status[i].renewal_last_result,
				  (unsigned long long)lease_status[i].renewal_last_time,
				  (unsigned long long)lease_status[i].renewal_good_time);
		} else if (sec >= to.lease_renewal_warn_seconds) {
			log_error(tokens[i], "renewal delay last result %d "
				  "at %llu good %llu",
				  lease_status[i].renewal_last_result,
				  (unsigned long long)lease_status[i].renewal_last_time,
				  (unsigned long long)lease_status[i].renewal_good_time);
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
		token =  tokens[i];
		if (token) {
			pthread_join(lease_threads[i], &ret);
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
	struct leader_record leader;
	struct timespec ts;
	int num = token->num;
	int fd, rv, stop, num_opened;

	set_thread_running(num, 1);

	fd = lockfile(token, RESOURCE_LOCKFILE_DIR, token->resource_id);
	if (fd < 0) {
		set_lease_status(num, OP_ACQUIRE, -EBADF, 0);
		goto out_run;
	}

	num_opened = open_disks(token);
	if (!majority_disks(token, num_opened)) {
		log_error(token, "cannot open majority of disks");
		set_lease_status(num, OP_ACQUIRE, -ENODEV, 0);
		goto out_lockfile;
	}

	rv = acquire_lease(token, &leader);
	set_lease_status(num, OP_ACQUIRE, rv, leader.timestamp);
	if (rv < 0) {
		log_error(token, "acquire failed %d", rv);
		goto out_disks;
	}
	log_debug(token, "acquire at %llu",
		  (unsigned long long)leader.timestamp);

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

		rv = renew_lease(token, &leader);
		set_lease_status(num, OP_RENEWAL, rv, leader.timestamp);
		if (rv < 0)
			log_error(token, "renewal failed %d", rv);
		else
			log_debug(token, "renewal");
	}

	rv = release_lease(token, &leader);
	set_lease_status(num, OP_RELEASE, rv, leader.timestamp);
	log_debug(token, "release rv %d", rv);

 out_disks:
	close_disks(token);
 out_lockfile:
	unlink_lockfile(fd, RESOURCE_LOCKFILE_DIR, token->resource_id);
 out_run:
	set_thread_running(num, 0);
	return NULL;
}

int create_token(int num_disks, struct token **token_out)
{
	struct token *token;
	struct paxos_disk *disks;

	token = malloc(sizeof(struct token));
	if (!token)
		return -ENOMEM;
	memset(token, 0, sizeof(struct token));

	disks = malloc(num_disks * sizeof(struct paxos_disk));
	if (!disks) {
		free(token);
		return -ENOMEM;
	}

	token->disks = disks;
	token->num_disks = num_disks;
	*token_out = token;
	return 0;
}

int add_lease_thread(struct token *token, int *num_ret)
{
	pthread_attr_t attr;
	int i, rv, num, found = 0;

	/* find an unused lease num, only main loop accesses
	   tokens[] and lease_threads[], no locking needed */

	for (i = 0; i < MAX_LEASES; i++) {
		if (!tokens[i]) {
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

	/* verify that the token num slot is unused in lease_status[],
	   and that that the resource_id is not already used */

	pthread_mutex_lock(&lease_status_mutex);
	for (i = 0; i < MAX_LEASES; i++) {
		if (!lease_status[i].thread_running)
			continue;
		if (strcmp(lease_status[i].resource_id, token->resource_id))
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
	strncpy(lease_status[num].resource_id, token->resource_id, NAME_ID_SIZE);
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
	void (*workfn) (int ci);
	void (*deadfn) (int ci);
	int i, r, rv, pid_status, wd_status;
	int poll_timeout = to.unstable_poll_ms;
	int error = 0;

	while (1) {
		/*
		 * Use this main thread to write log entries to logfile
		 * and/or syslog.  There's some risk that writing could
		 * block for longer than we want.. could dedicate a new
		 * thread to writing log files if needed.
		 */

		write_log_ents();

		/*
		 * Poll events arrive from external tool(s) querying
		 * status, adding/deleting leases, etc.
		 */

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
				unlink_watchdog();
				starting_lease_thread = 0;
				stopping_lease_threads = 1;
				error = r;

			} else if (r > 0) {
				/* lease_thread 0 has acquired lease */
				starting_lease_thread = 0;

				if (command[0]) {
					rv = run_command(command);
					if (rv < 0) {
						unlink_watchdog();
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
		 * has stopped.  pthread_join lease threads and free tokens
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
			unlink_watchdog();
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
		    !stopping_lease_threads && !starting_lease_thread &&
		    (time(NULL) - oldest_renewal_time < to.lease_renewal_seconds))
			poll_timeout = to.stable_poll_ms;
		else
			poll_timeout = to.unstable_poll_ms;
	}

	return error;
}

void cmd_status(int fd, struct sm_header *h_recv)
{
	/* no more to recv */

	/* reply:
	   struct sm_header +
	   struct sm_info +
	   N * (struct sm_lease_info + (M * struct sm_disk_info)) */
}

void cmd_log_dump(int fd, struct sm_header *h_recv)
{
	struct sm_header h;

	memcpy(&h, h_recv, sizeof(struct sm_header));

	/* can't send header until taking log_mutex to find the length */

	write_log_dump(fd, &h);
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

	if (strcmp(sm_id, h.sm_id)) {
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
		break;
	case SM_CMD_SUPERVISE_PID:
		if (!supervise_pid)
			supervise_pid = h.data;
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
	case SM_CMD_LOG_DUMP:
		cmd_log_dump(fd, &h);
		break;
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
		log_error(NULL, "socket error %d %d", s, errno);
		return s;
	}

	snprintf(path, PATH_MAX, "%s/%s", DAEMON_SOCKET_DIR, sm_id);

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_LOCAL;
	strncpy(&addr.sun_path[1], path, PATH_MAX - 1);
	addrlen = sizeof(sa_family_t) + strlen(addr.sun_path+1) + 1;

	rv = bind(s, (struct sockaddr *) &addr, addrlen);
	if (rv < 0) {
		log_error(NULL, "bind error %d %d", rv, errno);
		close(s);
		return rv;
	}

	rv = listen(s, 5);
	if (rv < 0) {
		log_error(NULL, "listen error %d %d", rv, errno);
		close(s);
		return rv;
	}

	client_add(s, process_listener, NULL);
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
	printf("  -n <name>		name of this sync_manager instance\n");
	printf("  -i <num>		local host id\n");
	printf("  -l LEASE		lease description, see below\n");
	printf("  -k <path>		command to stop supervised process\n");
	printf("  -w <num>		enable (1) or disable (0) using watchdog\n");
	printf("  -c <path> <args>	run command with args, -c must be final option\n");
	printf("\nInitialize a lease disk area:\n");
	printf("sync_manager -I -h <num_hosts> [-H <max_hosts>] -l LEASE\n");
	printf("  -h <num_hosts>	max host id that will be able to acquire the lease\n");
	printf("  -H <max_hosts>	max number of hosts the disk area will support\n");
	printf("                        (default %d)\n", DEFAULT_MAX_HOSTS);
	printf("  -l LEASE		lease description, see below\n");
	printf("\nLEASE = <resource_id>:<path>:<offset>[:<path>:<offset>...]\n");
	printf("  <resource_id>		name of resource being leased\n");
	printf("  <path>		disk path\n");
	printf("  <offset>		offset on disk\n");
	printf("  [:<path>:<offset>...] other disks in a multi-disk lease\n");
	printf("\n");
}

/* arg = <resource_id>:<path>:<offset>[:<path>:<offset>...] */

int add_token_arg(char *arg, int *token_count, struct token *token_args[])
{
	struct token *token;
	char sub[DISK_PATH_LEN + 1];
	int sub_count;
	int colons;
	int num_disks;
	int rv, i, j, d;
	int len = strlen(arg);

	if (*token_count >= MAX_LEASE_ARGS) {
		log_error(NULL, "lease args over max %d", MAX_LEASE_ARGS);
		return -1;
	}

	colons = 0;
	for (i = 0; i < strlen(arg); i++) {
		if (arg[i] == ':')
			colons++;
	}
	if (!colons || (colons % 2)) {
		log_error(NULL, "invalid lease arg");
		return -1;
	}
	num_disks = colons / 2;

	if (num_disks > MAX_DISKS) {
		log_error(NULL, "invalid lease arg num_disks %d", num_disks);
		return -1;
	}

	rv = create_token(num_disks, &token);
	if (rv < 0) {
		log_error(NULL, "lease arg create num_disks %d", num_disks);
		return rv;
	}

	token_args[*token_count] = token;
	(*token_count)++;

	d = 0;
	sub_count = 0;
	j = 0;
	memset(sub, 0, sizeof(sub));

	for (i = 0; i < len + 1; i++) {
		if (i < len && arg[i] != ':') {
			if (j >= DISK_PATH_LEN) {
				log_error(NULL, "lease arg length error");
				goto fail;
			}
			sub[j++] = arg[i];
			continue;
		}

		/* do something with sub when we hit ':' or end of arg,
		   first sub is id, odd sub is path, even sub is offset */

		if (!sub_count) {
			if (strlen(sub) > NAME_ID_SIZE) {
				log_error(NULL, "lease arg id length error");
				goto fail;
			}
			strncpy(token->resource_id, sub, NAME_ID_SIZE);
		} else if (sub_count % 2) {
			if (strlen(sub) > DISK_PATH_LEN - 1) {
				log_error(NULL, "lease arg path length error");
				goto fail;
			}
			strncpy(token->disks[d].path, sub, DISK_PATH_LEN - 1);
		} else {
			rv = sscanf(sub, "%llu", (unsigned long long *)&token->disks[d].offset);
			if (rv != 1) {
				log_error(NULL, "lease arg offset error");
				goto fail;
			}
			d++;
		}

		sub_count++;
		j = 0;
		memset(sub, 0, sizeof(sub));
	}

	return 0;

 fail:
	free(token->disks);
	free(token);
	return -1;
}

/* TODO: option to start up as the receiving side of a transfer
   from another host.  Watch the other host's lease renewals until
   the other host writes our hostid is written in the leader block,
   at which point the lease is ours and we start doing the renewals.
 
   TODO: option to transfer the ownership of all leases to a specified
   hostid, then watch for pid to exit? */

/* TODO: option to set timeouts, e.g. -m name1=num,name2=num,name3=num */

#define RELEASE_VERSION "0.0"

int read_args(int argc, char *argv[],
	      int *token_count, struct token *token_args[],
	      int *init, int *init_num_hosts, int *init_max_hosts)
{
	char optchar;
	char *optarg;
	char *p;
	char *arg1 = argv[1];
	int optarg_used;
	int i, j, len, rv;
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

	for (i = 1; i < argc; ) {
		p = argv[i];

		if ((p[0] != '-') || (strlen(p) != 2)) {
			fprintf(stderr, "unknown option %s\n", p);
			fprintf(stderr, "space required before option value\n");
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

		case 'I':
			*init = 1;
			optarg_used = 0;
			break;
		case 'h':
			*init_num_hosts = atoi(optarg);
			break;
		case 'H':
			*init_max_hosts = atoi(optarg);
			break;

		case 'n':
			strncpy(sm_id, optarg, NAME_ID_SIZE);
			break;
		case 'i':
			our_host_id = atoi(optarg);
			break;
		case 'l':
			rv = add_token_arg(optarg, token_count, token_args);
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
			fprintf(stderr, "unknown option: %c\n", optchar);
			exit(EXIT_FAILURE);
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
			log_error(NULL, "command option (-c) requires an arg");
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

	if (!*init && !our_host_id) {
		log_error(NULL, "local host id required");
		return -EINVAL;
	}

	if (!*init && !sm_id[0]) {
		log_error(NULL, "name option (-n) required");
		return -EINVAL;
	}

	return 0;
}

int make_dirs(void)
{
	mode_t old_umask;
	int rv;

	old_umask = umask(0022);
	rv = mkdir(SM_RUN_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	rv = mkdir(DAEMON_LOCKFILE_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	rv = mkdir(RESOURCE_LOCKFILE_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	rv = mkdir(DAEMON_SOCKET_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	rv = mkdir(DAEMON_WATCHDOG_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	rv = mkdir(SM_LOG_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	rv = 0;
 out:
	umask(old_umask);
	if (rv < 0)
		log_error(NULL, "mkdir errno %d", errno);
	return rv;
}

void sigterm_handler(int sig)
{
	external_shutdown = 1;
}

int do_init(int token_count, struct token *token_args[],
	    int init_num_hosts, int init_max_hosts)
{
	struct token *token;
	int num_opened;
	int i, rv = 0;

	for (i = 0; i < token_count; i++) {
		token = token_args[i];

		num_opened = open_disks(token);
		if (!majority_disks(token, num_opened)) {
			log_error(token, "cannot open majority of disks");
			rv = -1;
			continue;
		}

		rv = disk_paxos_init(token, init_num_hosts, init_max_hosts);
		if (rv < 0) {
			log_error(token, "cannot initialize disks");
			rv = -1;
		}
	}

	return rv;
}

int main(int argc, char *argv[])
{
	struct token *token_args[MAX_LEASE_ARGS];
	int token_count = 0;
	int init = 0, init_num_hosts = 0, init_max_hosts = DEFAULT_MAX_HOSTS;
	int fd, rv, num;

	/* default logging: LOG_ERR and up to stderr, logfile and syslog */

	log_stderr_priority = LOG_ERR;
	log_logfile_priority = LOG_ERR;
	log_syslog_priority = LOG_ERR;

	setup_logging();

	rv = make_dirs();
	if (rv < 0)
		goto out;

	to.lease_timeout_seconds = 60;
	to.lease_renewal_warn_seconds = 30;
	to.lease_renewal_fail_seconds = 40;
	to.lease_renewal_seconds = 10;
	to.wd_touch_seconds = 4;
	to.wd_reboot_seconds = 15;
	to.wd_touch_fail_seconds = 10;
	to.script_shutdown_seconds = 10;
	to.sigterm_shutdown_seconds = 10;
	to.stable_poll_ms = 2000;
	to.unstable_poll_ms = 500;

	rv = read_args(argc, argv, &token_count, token_args,
		       &init, &init_num_hosts, &init_max_hosts);
	if (rv < 0)
		goto out;

	if (init) {
		rv = do_init(token_count, token_args,
			     init_num_hosts, init_max_hosts);
		goto out;
	}

	signal(SIGTERM, sigterm_handler);

	fd = lockfile(NULL, DAEMON_LOCKFILE_DIR, sm_id);
	if (fd < 0)
		goto out;

	rv = setup_listener();
	if (rv < 0)
		goto out_lockfile;

	if (token_count) {
		rv = touch_watchdog();
		if (rv < 0)
			goto out_lockfile;

		/* TODO: support more than one initial lease */

		rv = add_lease_thread(token_args[0], &num);
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
	unlink_lockfile(fd, DAEMON_LOCKFILE_DIR, sm_id);
 out:
	return rv;
}

