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
#include "sm_options.h"
#include "token_manager.h"
#include "lockfile.h"
#include "log.h"
#include "diskio.h"

struct client {
	int fd;
	void *workfn;
	void *deadfn;
};

#define CLIENT_NALLOC 32 /* TODO: set lower to test more expanding */
static int client_maxi;
static int client_size = 0;
static struct client *client = NULL;
static struct pollfd *pollfd = NULL;

/* priorities are LOG_* from syslog.h */
int log_logfile_priority = LOG_ERR;
int log_syslog_priority = LOG_ERR;
int log_stderr_priority = LOG_ERR;

/* sync_manager <action>'s */
#define ACT_INIT	1
#define ACT_DAEMON	2
#define ACT_ACQUIRE	3
#define ACT_RELEASE	4
#define ACT_SHUTDOWN	5
#define ACT_SUPERVISE	6
#define ACT_STATUS	7
#define ACT_LOG_DUMP	8
#define ACT_SET_HOST_ID	9

char command[COMMAND_MAX];
char killscript[COMMAND_MAX];
int cluster_mode;
int cmd_argc;
char **cmd_argv;

int listener_socket;
int supervise_pid;
int killscript_pid;
int killing_supervise_pid;
int external_shutdown;

struct cmd_acquire_args {
	int sock;
	int token_count;
	int token_ids[MAX_LEASE_ARGS];
	struct sm_header h_recv;
};

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

static void client_dead(int ci)
{
	close(client[ci].fd);
	client[ci].workfn = NULL;
	client[ci].fd = -1;
	pollfd[ci].fd = -1;
}

static int client_add(int fd, void (*workfn)(int ci), void (*deadfn)(int ci))
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

static int check_killscript_pid(void)
{
	int rv, status;

	if (!killscript_pid)
		return 0;

	rv = waitpid(killscript_pid, &status, WNOHANG);

	/* still running */
	/* TODO: call again before sync_manager exit? */
	if (!rv)
		return 0;

	killscript_pid = 0;
	return 0;
}

/*
 * return values:
 * 1 if pid is running (or pid has not been set yet)
 * 0 is pid is not running (or no pid was started and main loop is killing)
 * < 0 on a waitpid error, don't know what these conditions are
 */

static int check_supervise_pid(void)
{
	int rv, status;
	int waitpid_errno;

	if (!supervise_pid && killing_supervise_pid)
		return 0;

	if (!supervise_pid)
		return 1;

	rv = waitpid(supervise_pid, &status, WNOHANG);

	if (!rv) {
		/* pid exists, no state change */
		return 1;
	} else if (rv < 0) {
		waitpid_errno = errno;

		/* PID is not responding to singal 0. It is down */
		rv = kill(supervise_pid, 0);
		if (rv)
			return 0;

		log_error(NULL, "check_supervise_pid %d failed waitpid %d "
			  "kill %d", supervise_pid, waitpid_errno, errno);
		return -1;
	} else {
		/* pid has terminated */
		log_debug(NULL, "waitpid success %d exited %d signaled %d",
			  rv, WIFEXITED(status), WIFSIGNALED(status));
		check_killscript_pid();
		supervise_pid = 0;
		return 0;
	}
}

static int run_killscript(void)
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
		execv(killscript, av);
		return -1;
	}
}

static int run_command(void)
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

static void kill_supervise_pid(void)
{
	uint64_t expire_time, remaining_seconds;

	if (!killing_supervise_pid)
		killing_supervise_pid = 1;

	if (!supervise_pid)
		return;

	expire_time = get_oldest_renewal_time() + to.lease_timeout_seconds;

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

/* This is called from both the main thread and from the cmd_acquire_thread.
   Each lease_thread we're waiting on here should normally time out on its own
   unless there's some problem causing the thread to get stuck.  If we want
   to use a timeout to address that condition, it should probably be
   some value a little over lease_timeout_seconds, which is the longest
   that each lease_thread to should take to acquire the lease or fail. */

static int wait_acquire_results(int token_count, int *token_ids)
{
	int i, rv, result;

	for (i = 0; i < token_count; i++) {
		rv = wait_acquire_result(token_ids[i], &result);

		if (rv < 0)
			return rv;
		if (result < 0)
			return result;

		/* this shouldn't happen */
		if (!result)
			return -1;
	}

	return 0;
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
 * failure to release disk leases shouldn't jeopardize any vm corruption,
 * so it should be safe to unlink the watchdog files.
 */

static int main_loop(void)
{
	int poll_timeout = to.unstable_poll_ms;
	int i, rv, pid_status;
	void (*workfn) (int ci);
	void (*deadfn) (int ci);

	while (1) {
		/*
		 * Poll events arrive from external tool(s) querying
		 * status, adding/deleting leases, etc.
		 */

		rv = poll(pollfd, client_maxi + 1, poll_timeout);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0) {
			/* errors here unlikely, do we want to shut down,
			   i.e. kill pid / release leases, or continue
			   running with no poll? */
		}
		for (i = 0; i <= client_maxi; i++) {
			if (client[i].fd < 0)
				continue;
			if (pollfd[i].revents & POLLIN) {
				workfn = client[i].workfn;
				workfn(i);
			}
			if (pollfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				deadfn = client[i].deadfn;
				if (deadfn)
					deadfn(i);
				client_dead(i);
			}
		}

		/*
		 * someone has asked sync_manager to shut down
		 */

		if (external_shutdown)
			kill_supervise_pid();

		/*
		 * sync_manager release stops threads that need cleanup
		 */

		cleanup_stopped_lease();

		/*
		 * The main running case (not stopping or starting).
		 * We also continue to run through here after killing the pid,
		 * until the pid has exited at which point we break.
		 *
		 * Watch the pid and renew its associated leases while it
		 * continues to run.  The watchdog is one way to deal with
		 * the error case where the pid continues running but we fail
		 * to renew the leases.
		 */

		pid_status = check_supervise_pid();

		if (!pid_status) {
			break;

		} else if (pid_status < 0) {
			/*
			 * can't get status, don't know if pid is running
			 * use a secondary method to check process
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
			}

		} else if (pid_status > 0) {
			/*
			 * pid is running (or no pid has been set yet)
			 */
			rv = check_leases_renewed();
			if (rv < 0) {
				kill_supervise_pid();
			}
		}

		/* Don't check on pid and leases as often when things are in
		   a stable state: pid running and leases being updated in
		   timely fashion. */

		if ((pid_status > 0) && !killing_supervise_pid &&
		    (time(NULL) - get_oldest_renewal_time() < to.lease_renewal_seconds))
			poll_timeout = to.stable_poll_ms;
		else
			poll_timeout = to.unstable_poll_ms;
	}

	return 0;
}

static void *cmd_acquire_thread(void *args_in)
{
	struct cmd_acquire_args *args = args_in;
	int i, sock, token_count, rv;
	int *token_ids;
	struct sm_header h;

	token_count = args->token_count;
	token_ids = args->token_ids;
	sock = args->sock;

	memcpy(&h, &args->h_recv, sizeof(struct sm_header));

	rv = wait_acquire_results(token_count, token_ids);
	if (rv < 0)
		goto fail;

	h.length = sizeof(h) + (sizeof(int) * token_count);
	h.data = token_count;
	send(sock, &h, sizeof(struct sm_header), MSG_WAITALL);
	send(sock, token_ids, sizeof(int) * token_count, MSG_WAITALL);

	close(sock);
	free(args);
	return NULL;

 fail:
	for (i = 0; i < token_count; i++)
		stop_token(token_ids[i]);

	h.length = sizeof(h);
	h.data = 0;
	send(sock, &h, sizeof(struct sm_header), MSG_WAITALL);

	close(sock);
	free(args);
	return NULL;
}

static void cmd_acquire(int fd, struct sm_header *h_recv)
{
	pthread_t wait_thread;
	pthread_attr_t attr;
	struct sm_header h;
	struct token *token = NULL;
	struct sync_disk *disks = NULL;
	int token_ids[MAX_LEASE_ARGS];
	int token_count = h_recv->data;
	int added_count;
	int rv, i, disks_len, num_disks;
	struct cmd_acquire_args *args;

	memset(token_ids, 0, sizeof(token_ids));
	added_count = 0;

	if (token_count > MAX_LEASE_ARGS) {
		log_error(NULL, "client asked for %d leases maximum is %d",
			  token_count, MAX_LEASE_ARGS);
		rv = -1;
		goto fail;
	}

	for (i = 0; i < token_count; i++) {
		token = NULL;
		disks = NULL;

		token = malloc(sizeof(struct token));
		if (!token) {
			rv = -ENOMEM;
			goto fail;
		}

		rv = recv(fd, token, sizeof(struct token), MSG_WAITALL);
		if (rv != sizeof(struct token)) {
			log_error(NULL, "connection closed unexpectedly %d", rv);
			rv = -1;
			goto fail;
		}

		num_disks = token->num_disks;

		disks = malloc(num_disks * sizeof(struct sync_disk));
		if (!disks) {
			rv = -ENOMEM;
			goto fail;
		}

		disks_len = num_disks * sizeof(struct sync_disk);
		memset(disks, 0, disks_len);

		rv = recv(fd, disks, disks_len, MSG_WAITALL);
		if (rv != disks_len) {
			log_error(NULL, "connection closed unexpectedly %d", rv);
			rv = -1;
			goto fail;
		}
		token->disks = disks;
		log_debug(token, "received request to acquire lease");

		rv = add_lease_thread(token, &token_ids[i]);

		/* add_lease_thread frees token and disks on error */
		token = NULL;
		disks = NULL;

		if (rv < 0)
			goto fail;

		added_count++;
	}

	/* lease_thread created for each token, new thread will wait for
	   the results of the threads and send back a reply */

	args = malloc(sizeof(struct cmd_acquire_args));
	if (!args)
		goto fail;

	memset(args, 0, sizeof(struct cmd_acquire_args));
	args->sock = fd;
	args->token_count = added_count;
	memcpy(args->token_ids, token_ids, sizeof(int) * added_count);
	memcpy(&args->h_recv, h_recv, sizeof(struct sm_header));

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rv = pthread_create(&wait_thread, &attr, cmd_acquire_thread, args);
	pthread_attr_destroy(&attr);
	if (rv < 0) {
		log_error(NULL, "could not start monitor lease for request");
		free(args);
		goto fail;
	}

	return;

 fail:
	if (token)
		free(token);
	if (disks)
		free(disks);

	for (i = 0; i < added_count && i < token_count; i++)
		stop_token(token_ids[i]);

	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = -1;
	send(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
	close(fd);
}

static void cmd_release(int fd, struct sm_header *h_recv)
{
	struct sm_header h;
	char resource_name[NAME_ID_SIZE];
	int results[MAX_LEASE_ARGS];
	int lease_count = h_recv->data;
	int stopped_count;
	int rv, i;

	memset(results, 0, sizeof(results));
	stopped_count = 0;

	for (i = 0; i < lease_count; i++) {
		rv = recv(fd, resource_name, NAME_ID_SIZE, MSG_WAITALL);
		if (rv != NAME_ID_SIZE) {
			log_error(NULL, "connection closed unexpectedly %d", rv);
			results[i] = -1;
			break;
		}

		rv = stop_lease(resource_name);
		if (rv < 0) {
			results[i] = rv;
		} else {
			results[i] = 1;
			stopped_count++;
		}
	}

	/*
	 * one result for each resource_name received:
	 * 1 = stopped the lease thread, make status query to check result
	 * < 0 = error, no lease thread stopped for this resource_name
	 * 0 = no attempt made to stop this resource_name's lease thread
	 *
	 * h.data is the number of results that are "1"
	 */

	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h) + sizeof(int) * lease_count;
	h.data = stopped_count;

	send(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
	send(fd, &results, sizeof(int) * lease_count, MSG_WAITALL);
}

/* reply:
   struct sm_header +
   struct sm_info +
   N * (struct sm_lease_info + (M * struct sm_disk_info)) */

static void cmd_status(int fd, struct sm_header *h_recv)
{
	struct lease_status ls;
	struct token *t;
	struct sm_header *hd;
	struct sm_info *in;
	struct sm_lease_info *li;
	struct sm_disk_info *di;
	char *buf, *li_begin;
	int rv, i, d, len, token_count, disk_count, tokens_copied, disks_copied;

	token_count = 0;
	disk_count = 0;

	for (i = 0; i < MAX_LEASES; i++) {
		if (!tokens[i])
			continue;
		token_count++;
		disk_count += tokens[i]->num_disks;
	}

	len = sizeof(struct sm_header) + sizeof(struct sm_info) +
	      (token_count * sizeof(struct sm_lease_info)) +
	      (disk_count * sizeof(struct sm_disk_info));

	buf = malloc(len);
	if (!buf)
		return;
	memset(buf, 0, len);

	hd = (struct sm_header *)buf;
	in = (struct sm_info *)(buf + sizeof(struct sm_header));
	li_begin = buf + sizeof(struct sm_header) + sizeof(struct sm_info);

	memcpy(hd, h_recv, sizeof(struct sm_header));
	hd->length = len;

	strncpy(in->command, command, COMMAND_MAX - 1);
	strncpy(in->killscript, killscript, COMMAND_MAX - 1);
	in->our_host_id = options.our_host_id;
	in->supervise_pid = supervise_pid;
	in->killing_supervise_pid = killing_supervise_pid;
	in->external_shutdown = external_shutdown;

	in->current_time = time(NULL);
	in->oldest_renewal_time = get_oldest_renewal_time();
	in->lease_info_len = sizeof(struct sm_lease_info);
	in->lease_info_count = token_count;

	tokens_copied = 0;
	disks_copied = 0;

	for (i = 0; i < MAX_LEASES; i++) {
		if (!tokens[i])
			continue;

		t = tokens[i];
		get_lease_status(t->token_id, &ls);

		li = (struct sm_lease_info *)(li_begin +
		     (tokens_copied * sizeof(struct sm_lease_info)) +
		     (disks_copied * sizeof(struct sm_disk_info)));

		strncpy(li->resource_name, t->resource_name, NAME_ID_SIZE);
		li->token_id = t->token_id;
		li->disk_info_len = sizeof(struct sm_disk_info);
		li->disk_info_count = t->num_disks;
		li->stop_thread = ls.stop_thread;
		li->thread_running = ls.thread_running;

		li->acquire_last_result = ls.acquire_last_result;
		li->renewal_last_result = ls.renewal_last_result;
		li->release_last_result = ls.release_last_result;
		li->acquire_last_time = ls.acquire_last_time;
		li->acquire_good_time = ls.acquire_good_time;
		li->renewal_last_time = ls.renewal_last_time;
		li->renewal_good_time = ls.renewal_good_time;
		li->release_last_time = ls.release_last_time;

		for (d = 0; d < t->num_disks; d++) {
			di = (struct sm_disk_info *)((char *)li +
			     sizeof(struct sm_lease_info) +
			     (d * sizeof(struct sm_disk_info)));

			di->offset = t->disks[d].offset;
			strncpy(di->path, t->disks[d].path, DISK_PATH_LEN - 1);
		}

		tokens_copied++;
		disks_copied += t->num_disks;
	}

	rv = send(fd, buf, len, MSG_WAITALL);

	free(buf);
}

static void cmd_log_dump(int fd, struct sm_header *h_recv)
{
	struct sm_header h;

	memcpy(&h, h_recv, sizeof(struct sm_header));

	/* can't send header until taking log_mutex to find the length */

	write_log_dump(fd, &h);
}

static void cmd_set_host_id(int fd, struct sm_header *h_recv)
{
	struct sm_header h;
	int rv;

	if (options.our_host_id < 0) {
		options.our_host_id = h_recv->data;
		rv = 0;
		log_debug(NULL, "host ID set to %d", options.our_host_id);
	} else if (options.our_host_id == h_recv->data) {
		rv = 0;
	} else {
		rv = 1;
		log_error(NULL, "client tried to reset host ID");
	}
	memcpy(&h, h_recv, sizeof(struct sm_header));
	h.length = sizeof(h);
	h.data = rv;
	send(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
}

static void process_listener(int ci GNUC_UNUSED)
{
	struct sm_header h;
	int fd, rv, auto_close = 1;

	fd = accept(listener_socket, NULL, NULL);
	if (fd < 0)
		return;

	rv = recv_header(fd, &h);
	if (rv < 0) {
		return;
	}

	switch (h.cmd) {
	case SM_CMD_ACQUIRE:
		cmd_acquire(fd, &h);
		auto_close = 0;
		break;
	case SM_CMD_RELEASE:
		cmd_release(fd, &h);
		break;
	case SM_CMD_SHUTDOWN:
		external_shutdown = 1;
		break;
	case SM_CMD_SUPERVISE:
		if (!supervise_pid)
			supervise_pid = h.data;
		break;
	case SM_CMD_STATUS:
		cmd_status(fd, &h);
		break;
	case SM_CMD_LOG_DUMP:
		cmd_log_dump(fd, &h);
		break;
	case SM_CMD_SET_HOST_ID:
		cmd_set_host_id(fd, &h);
		break;
#if 0
	case SM_CMD_GET_TIMEOUTS:
		/* memcpy(sdata, &to, sizeof(to)); */
		break;
	case SM_CMD_SET_TIMEOUTS:
		/* memcpy(&to, rdata, sizeof(to)); */
		break;
	case SM_CMD_NUM_HOSTS:
		/* just rewrite leader block in leases? */
		break;
#endif
	default:
		log_error(NULL, "cmd %d not supported", h.cmd);
	};

	if (auto_close)
		close(fd);
}

static int setup_listener(void)
{
	return setup_listener_socket(MAIN_SOCKET_NAME,
                                sizeof(MAIN_SOCKET_NAME), &listener_socket);
}

static void sigterm_handler(int sig GNUC_UNUSED)
{
	external_shutdown = 1;
}

static void sigchld_handler(int sig GNUC_UNUSED)
{
}

static int make_dirs(void)
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
	return rv;
}

/* FIXME: temp func to let everything still work while I move
 *        all the commands to the lib and create a cli util */

static int send_command(int cmd, uint32_t data) {
	int rv, sock;
	rv = connect_socket(MAIN_SOCKET_NAME, sizeof(MAIN_SOCKET_NAME),
	                    &sock);
	if (rv < 0) {
		return -1;
	}

	rv = send_header(sock, cmd, data);
	if (rv < 0) {
		goto clean;
	}

	return sock;

 clean:
	close(sock);
	return rv;
}

static int do_daemon(int token_count, struct token *token_args[])
{
	int token_ids[MAX_LEASE_ARGS];
	struct sigaction act;
	int fd, rv, i;

	/*
	 * after creating dirs and setting up logging the daemon can
	 * use log_error/log_debug
	 */

	rv = make_dirs();
	if (rv < 0) {
		log_tool("cannot create logging dirs\n");
		return -1;
	}

	setup_logging();

	to.lease_timeout_seconds = 60;
	to.lease_renewal_warn_seconds = 30;
	to.lease_renewal_fail_seconds = 40;
	to.lease_renewal_seconds = 10;
	to.script_shutdown_seconds = 10;
	to.sigterm_shutdown_seconds = 10;
	to.stable_poll_ms = 2000;
	to.unstable_poll_ms = 500;
	to.io_timeout_seconds = DEFAULT_IO_TIMEOUT_SECONDS;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigterm_handler;
	rv = sigaction(SIGTERM, &act, NULL);
	if (rv < 0)
		return -rv;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigchld_handler;
	act.sa_flags = SA_NOCLDSTOP;
	rv = sigaction(SIGCHLD, &act, NULL);
	if (rv < 0)
		return -rv;

	fd = lockfile(NULL, DAEMON_LOCKFILE_DIR, options.sm_id);
	if (fd < 0)
		goto out;

	rv = setup_listener();
	if (rv < 0)
		goto out_lockfile;
	client_add(listener_socket, process_listener, NULL);

	for (i = 0; i < token_count; i++) {
		rv = add_lease_thread(token_args[i], &token_ids[i]);
		if (rv < 0)
			goto out_leases;
	}

	rv = wait_acquire_results(token_count, token_ids);
	if (rv < 0)
		goto out_leases;

	if (command[0]) {
		rv = run_command();
		if (rv < 0)
			goto out_leases;
	}

	memset(&token_ids, 0, sizeof(token_ids));

	rv = main_loop();

 out_leases:
	stop_all_leases();
	cleanup_all_leases();
 out_lockfile:
	unlink_lockfile(fd, DAEMON_LOCKFILE_DIR, options.sm_id);
 out:
	close_logging();
	return rv;
}


static int do_init(int token_count, struct token *token_args[],
		   int init_num_hosts, int init_max_hosts)
{
	struct token *token;
	int num_opened;
	int i, rv = 0;

	for (i = 0; i < token_count; i++) {
		token = token_args[i];

		num_opened = open_disks(token->disks, token->num_disks);
		if (!majority_disks(token, num_opened)) {
			log_tool("cannot open majority of disks");
			rv = -1;
			continue;
		}

		rv = disk_paxos_init(token, init_num_hosts, init_max_hosts);
		if (rv < 0) {
			log_tool("cannot initialize disks");
			rv = -1;
		}
	}

	return rv;
}

static int do_set_host_id(void)
{
	struct sm_header h;
	int sock, rv;

	sock = send_command(SM_CMD_SET_HOST_ID, options.our_host_id);
	if (sock < 0)
		return sock;

	rv = recv(sock, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		log_tool("connection closed unexpectedly %d", rv);
		return -1;
	}

	if (!h.data)
		log_tool("host ID set to %d", options.our_host_id);
	else
		log_tool("could not set host ID, it was already set");
	return h.data;
}

static int do_acquire(int token_count, struct token *token_args[])
{
	struct token *t;
	struct sm_header h;
	int token_ids[MAX_LEASE_ARGS];
	int sock, rv, i;

	sock = send_command(SM_CMD_ACQUIRE, token_count);
	if (sock < 0)
		return sock;

	for (i = 0; i < token_count; i++) {
		t = token_args[i];
		rv = send(sock, t, sizeof(struct token), 0);
		if (rv < 0) {
			log_tool("send error %d %d", rv, errno);
			goto out;
		}

		rv = send(sock, t->disks, sizeof(struct sync_disk) * t->num_disks, 0);
		if (rv < 0) {
			log_tool("send error %d %d", rv, errno);
			goto out;
		}
	}

	memset(&h, 0, sizeof(h));
	memset(&token_ids, 0, sizeof(token_ids));

	rv = recv(sock, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		log_tool("connection closed unexpectedly %d", rv);
		goto out;
	}

	if (h.data == 0 || h.data == -1) {
		log_tool("acquire failed");
		rv = -1;
		goto out;
	}

	rv = recv(sock, &token_ids, sizeof(int) * token_count, MSG_WAITALL);
	if (rv != sizeof(int) * token_count) {
		log_tool("connection closed unexpectedly %d", rv);
		goto out;
	}


	for (i = 0; i < token_count; i++) {
		t = token_args[i];
		printf("%s - %d\n", token_args[i]->resource_name, token_ids[i]);
	}
	rv = 0;
 out:
	close(sock);
	return rv;
}

static int do_release(int token_count, struct token *token_args[])
{
	struct sm_header h;
	int results[MAX_LEASE_ARGS];
	int sock, rv, i;

	sock = send_command(SM_CMD_RELEASE, token_count);
	if (sock < 0)
		return sock;

	for (i = 0; i < token_count; i++) {
		rv = send(sock, token_args[i]->resource_name, NAME_ID_SIZE, 0);
		if (rv < 0) {
			log_tool("send error %d %d", rv, errno);
			goto out;
		}
	}

	memset(&h, 0, sizeof(h));
	memset(&results, 0, sizeof(results));

	rv = recv(sock, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		log_tool("connection closed unexpectedly %d", rv);
		goto out;
	}

	rv = recv(sock, &results, sizeof(int) * token_count, MSG_WAITALL);
	if (rv != sizeof(int) * token_count) {
		log_tool("connection closed unexpectedly %d", rv);
		goto out;
	}

	rv = 0;
	for (i = 0; i < token_count; i++) {
		if (results[i] != 1) {
			rv = -1;
		}
		printf("%s - %d\n", token_args[i]->resource_name, results[i]);
	}
 out:
	close(sock);
	return rv;
}

static int do_shutdown(void)
{
	struct sm_header h;
	int fd, rv;
	fd = send_command(SM_CMD_SHUTDOWN, 0);
	if (fd < 0)
		return fd;

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h))
		log_tool("connection closed unexpectedly %d", rv);

	close(fd);
	return 0;
}

static int do_supervise(uint32_t pid)
{
	struct sm_header h;
	int fd, rv;

	fd = send_command(SM_CMD_SUPERVISE, pid);
	if (fd < 0)
		return fd;

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h))
		log_tool("connection closed unexpectedly %d", rv);

	close(fd);
	return 0;
}

static int do_status(void)
{
	struct sm_header h;
	char *buf, *li_begin;
	struct sm_info *in;
	struct sm_lease_info *li;
	struct sm_disk_info *di;
	int i, fd, rv, len, d;
	int tokens_copied = 0, disks_copied = 0;

	fd = send_command(SM_CMD_STATUS, 0);
	if (fd < 0)
		return fd;

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h)) {
		log_tool("connection closed unexpectedly %d", rv);
		goto out;
	}

	len = h.length - sizeof(h);

	buf = malloc(len);
	if (!buf) {
		log_tool("cannot malloc %d", len);
		goto out;
	}
	memset(buf, 0, len);

	rv = recv(fd, buf, len, MSG_WAITALL);
	if (rv != len) {
		log_tool("connection closed unexpectedly %d", rv);
		free(buf);
		goto out;
	}

	in = (struct sm_info *)buf;

	printf("command               %s\n", in->command);
	printf("killscript            %s\n", in->killscript);
	printf("our_host_id           %llu\n", (unsigned long long)in->our_host_id);
	printf("current_time          %llu\n", (unsigned long long)in->current_time);
	printf("supervise_pid         %u\n", in->supervise_pid);
	printf("killing_supervise_pid %u\n", in->killing_supervise_pid);
	printf("external_shutdown     %u\n", in->external_shutdown);
	printf("oldest_renewal_time   %llu\n", (unsigned long long)in->oldest_renewal_time);
	printf("lease count           %d\n", in->lease_info_count);

	li_begin = buf + sizeof(struct sm_info);

	for (i = 0; i < in->lease_info_count; i++) {
		li = (struct sm_lease_info *)(li_begin +
			(tokens_copied * sizeof(struct sm_lease_info)) +
			(disks_copied * sizeof(struct sm_disk_info)));

		printf("\n");
		printf("lease                 %s:", li->resource_name);
		for (d = 0; d < li->disk_info_count; d++) {
			di = (struct sm_disk_info *)((char *)li +
				sizeof(struct sm_lease_info) +
				(d * sizeof(struct sm_disk_info)));

			if (d)
				printf(":");

			printf("%s:%llu\n", di->path,
			       (unsigned long long)di->offset);
		}
		tokens_copied++;
		disks_copied += li->disk_info_count;

		printf("token_id              %x\n", li->token_id);
		printf("stop_thread           %d\n", li->stop_thread);
		printf("thread_running        %d\n", li->thread_running);
		printf("acquire_last_result   %d\n", li->acquire_last_result);
		printf("renewal_last_result   %d\n", li->renewal_last_result);
		printf("release_last_result   %d\n", li->release_last_result);
		printf("acquire_last_time     %llu\n", (unsigned long long)li->acquire_last_time);
		printf("acquire_good_time     %llu\n", (unsigned long long)li->acquire_good_time);
		printf("renewal_last_time     %llu\n", (unsigned long long)li->renewal_last_time);
		printf("renewal_good_time     %llu\n", (unsigned long long)li->renewal_good_time);
		printf("release_last_time     %llu\n", (unsigned long long)li->release_last_time);
		printf("release_good_time     %llu\n", (unsigned long long)li->release_good_time);
	}

 out:
	close(fd);
	return 0;
}

static int do_log_dump(void)
{
	struct sm_header h;
	char *buf;
	int fd, rv, len;

	fd = send_command(SM_CMD_LOG_DUMP, 0);
	if (fd < 0)
		return fd;

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h)) {
		log_tool("connection closed unexpectedly %d", rv);
		goto out;
	}

	len = h.length - sizeof(h);

	buf = malloc(len);
	if (!buf) {
		log_tool("cannot malloc %d", len);
		goto out;
	}
	memset(buf, 0, len);

	rv = recv(fd, buf, len, MSG_WAITALL);
	if (rv != len)
		log_tool("connection closed unexpectedly %d", rv);

	printf("%s\n", buf);
 out:
	close(fd);
	return 0;
}

static void print_usage(void)
{
	printf("Usage:\n");
	printf("sync_manager <action> [options]\n\n");
	printf("actions:\n");
	printf("  help			print usage\n");
	printf("  init			initialize a lease disk area\n");
	printf("  daemon		update leases and monitor pid\n");
	printf("  acquire		acquire leases for a running pid\n");
	printf("  release		release leases for a running pid\n");
	printf("  status		print internal daemon state\n");
	printf("  log_dump		print internal daemon debug buffer\n");
	printf("  shutdown		kill pid, release leases and exit\n");

	printf("\ninit [options] -h <num_hosts> -l LEASE\n");
	printf("  -h <num_hosts>	max host id that will be able to acquire the lease\n");
	printf("  -H <max_hosts>	max number of hosts the disk area will support\n");
	printf("                        (default %d)\n", DEFAULT_MAX_HOSTS);
	printf("  -m <num>		cluster mode of hosts (default 0)\n");
	printf("  -l LEASE		lease description, see below\n");

	printf("\ndaemon [options] -n <name> [-l LEASE] [-c <path> <args>]\n");
	printf("  -D			print all logging to stderr\n");
	printf("  -L <level>		write logging at level and up to logfile (-1 none)\n");
	printf("  -S <level>		write logging at level and up to syslog (-1 none)\n");
	printf("  -n <name>		name for the new sync_manager instance\n");
	printf("  -m <num>		cluster mode of hosts (default 0)\n");
	printf("  -i <num>		local host id\n");
	printf("  -l LEASE		lease description, see below\n");
	printf("  -k <path>		command to stop supervised process\n");
	printf("  -w <num>		enable (1) or disable (0) writing watchdog files\n");
	printf("  -c <path> <args>	run command with args, -c must be final option\n");

	printf("\nacquire -n <name> -l LEASE\n");
	printf("  -n <name>		name of a running sync_manager instance\n");
	printf("  -l LEASE		lease description, see below\n");

	printf("\nrelease -n <name> -r <resource_name>\n");
	printf("  -n <name>		name of a running sync_manager instance\n");
	printf("  -r <resource_name>	resource name of a previously acquired lease\n");

	printf("\nstatus -n <name>\n");
	printf("  -n <name>		name of a running sync_manager instance\n");

	printf("\nlog_dump -n <name>\n");
	printf("  -n <name>		name of a running sync_manager instance\n");

	printf("\nshutdown -n <name>\n");
	printf("  -n <name>		name of a running sync_manager instance\n");

	printf("\nLEASE = <resource_name>:<path>:<offset>[:<path>:<offset>...]\n");
	printf("  <resource_name>	name of resource being leased\n");
	printf("  <path>		disk path\n");
	printf("  <offset>		offset on disk\n");
	printf("  [:<path>:<offset>...] other disks in a multi-disk lease\n");
	printf("\n");
}

static int add_resource_arg(char *arg, int *token_count, struct token *token_args[])
{
	struct token *token;
	int rv;

	if (*token_count >= MAX_LEASE_ARGS) {
		log_tool("lease args over max %d", MAX_LEASE_ARGS);
		return -1;
	}

	rv = create_token(0, &token);
	if (rv < 0) {
		log_tool("resource arg create");
		return rv;
	}

	strncpy(token->resource_name, arg, NAME_ID_SIZE);
	token_args[*token_count] = token;
	(*token_count)++;
	return rv;
}

/* arg = <resource_name>:<path>:<offset>[:<path>:<offset>...] */

static int add_token_arg(char *arg, int *token_count, struct token *token_args[])
{
	struct token *token;
	char sub[DISK_PATH_LEN + 1];
	int sub_count;
	int colons;
	int num_disks;
	int rv, i, j, d;
	int len = strlen(arg);

	if (*token_count >= MAX_LEASE_ARGS) {
		log_tool("lease args over max %d", MAX_LEASE_ARGS);
		return -1;
	}

	colons = 0;
	for (i = 0; i < strlen(arg); i++) {
		if (arg[i] == '\\') {
			i++;
			continue;
		}

		if (arg[i] == ':')
			colons++;
	}
	if (!colons || (colons % 2)) {
		log_tool("invalid lease arg");
		return -1;
	}
	num_disks = colons / 2;

	if (num_disks > MAX_DISKS) {
		log_tool("invalid lease arg num_disks %d", num_disks);
		return -1;
	}

	rv = create_token(num_disks, &token);
	if (rv < 0) {
		log_tool("lease arg create num_disks %d", num_disks);
		return rv;
	}

	token_args[*token_count] = token;
	(*token_count)++;

	d = 0;
	sub_count = 0;
	j = 0;
	memset(sub, 0, sizeof(sub));

	for (i = 0; i < len + 1; i++) {
		if (arg[i] == '\\') {
			if (i == (len - 1)) {
				log_tool("Invalid lease string");
				goto fail;
			}

			i++;
			sub[j++] = arg[i];
			continue;
		}
		if (i < len && arg[i] != ':') {
			if (j >= DISK_PATH_LEN) {
				log_tool("lease arg length error");
				goto fail;
			}
			sub[j++] = arg[i];
			continue;
		}

		/* do something with sub when we hit ':' or end of arg,
		   first sub is id, odd sub is path, even sub is offset */

		if (!sub_count) {
			if (strlen(sub) > NAME_ID_SIZE) {
				log_tool("lease arg id length error");
				goto fail;
			}
			strncpy(token->resource_name, sub, NAME_ID_SIZE);
		} else if (sub_count % 2) {
			if (strlen(sub) > DISK_PATH_LEN-1 || strlen(sub) < 1) {
				log_tool("lease arg path length error");
				goto fail;
			}
			strncpy(token->disks[d].path, sub, DISK_PATH_LEN - 1);
		} else {
			rv = sscanf(sub, "%llu", (unsigned long long *)&token->disks[d].offset);
			if (rv != 1) {
				log_tool("lease arg offset error");
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

static int read_args(int argc, char *argv[],
		     int *token_count, struct token *token_args[],
		     int *action, int *init_num_hosts, int *init_max_hosts)
{
	char optchar;
	char *optionarg;
	char *p;
	char *arg1 = argv[1];
	int optionarg_used;
	int i, j, len, rv;
	int begin_command = 0;

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

	if (!strcmp(arg1, "init"))
		*action = ACT_INIT;
	else if (!strcmp(arg1, "daemon"))
		*action = ACT_DAEMON;
	else if (!strcmp(arg1, "acquire"))
		*action = ACT_ACQUIRE;
	else if (!strcmp(arg1, "release"))
		*action = ACT_RELEASE;
	else if (!strcmp(arg1, "shutdown"))
		*action = ACT_SHUTDOWN;
	else if (!strcmp(arg1, "supervise"))
		*action = ACT_SUPERVISE;
	else if (!strcmp(arg1, "status"))
		*action = ACT_STATUS;
	else if (!strcmp(arg1, "log_dump"))
		*action = ACT_LOG_DUMP;
	else if (!strcmp(arg1, "set_host_id"))
		*action = ACT_SET_HOST_ID;
	else {
		log_tool("first arg is unknown action");
		print_usage();
		exit(EXIT_FAILURE);
	}

	for (i = 2; i < argc; ) {
		p = argv[i];

		if ((p[0] != '-') || (strlen(p) != 2)) {
			log_tool("unknown option %s", p);
			log_tool("space required before option value");
			print_usage();
			exit(EXIT_FAILURE);
		}

		optchar = p[1];
		i++;

		optionarg = argv[i];
		optionarg_used = 1;

		switch (optchar) {
		case 'D':
			log_stderr_priority = LOG_DEBUG;
			optionarg_used = 0;
			break;
		case 'L':
			log_logfile_priority = atoi(optionarg);
			break;
		case 'S':
			log_syslog_priority = atoi(optionarg);
			break;

		case 'h':
			*init_num_hosts = atoi(optionarg);
			break;
		case 'H':
			*init_max_hosts = atoi(optionarg);
			break;
		case 'm':
			cluster_mode = atoi(optionarg);
			break;
		case 'n':
			strncpy(options.sm_id, optionarg, NAME_ID_SIZE);
			break;
		case 'i':
			options.our_host_id = atoi(optionarg);
			break;
		case 'r':
			if ((*action) != ACT_RELEASE)
				return -1;

			rv = add_resource_arg(optionarg, token_count, token_args);
			if (rv < 0)
				return rv;
			break;
		case 'l':
			if ((*action) == ACT_RELEASE)
				return -1;

			rv = add_token_arg(optionarg, token_count, token_args);
			if (rv < 0)
				return rv;
			break;
		case 'k':
			strncpy(killscript, optionarg, COMMAND_MAX - 1);
			break;
		case 'w':
			options.opt_watchdog = atoi(optionarg);
			break;
		case 'c':
			begin_command = 1;
			optionarg_used = 0;
			break;
		default:
			log_tool("unknown option: %c", optchar);
			exit(EXIT_FAILURE);
		};

		if (optionarg_used)
			i++;

		if (begin_command)
			break;
	}

	/*
	 * the remaining args are for the command
	 *
	 * sync_manager -r foo -n 2 -d bar:0 -c /bin/cmd -X -Y -Z
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

	if ((*action == ACT_DAEMON) && (options.our_host_id < 0) && (*token_count > 0)) {
		log_tool("local host id required is you wish to acquire initial leases");
		return -EINVAL;
	}

	if ((*action == ACT_SET_HOST_ID) && (options.our_host_id < 0)) {
		log_tool("local host id parameter not set");
		return -EINVAL;
	}

	if ((*action != ACT_INIT) && !options.sm_id[0]) {
		log_tool("name option (-n) required");
		return -EINVAL;
	}

	if ((*action == ACT_ACQUIRE) && !token_count) {
		log_tool("no leases were asked to be acquired");
		return -EINVAL;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct token *token_args[MAX_LEASE_ARGS];
	int token_count = 0;
	int action = 0;
	int init_num_hosts = 0, init_max_hosts = DEFAULT_MAX_HOSTS;
	int rv;

	rv = read_args(argc, argv, &token_count, token_args,
		       &action, &init_num_hosts, &init_max_hosts);
	if (rv < 0)
		goto out;

	switch (action) {
	case ACT_DAEMON:
		rv = do_daemon(token_count, token_args);
		break;
	case ACT_INIT:
		rv = do_init(token_count, token_args,
			     init_num_hosts, init_max_hosts);
		break;
	case ACT_ACQUIRE:
		rv = do_acquire(token_count, token_args);
		break;
	case ACT_RELEASE:
		rv = do_release(token_count, token_args);
		break;
	case ACT_SHUTDOWN:
		rv = do_shutdown();
		break;
	case ACT_SUPERVISE:
		rv = do_supervise(supervise_pid);
		break;
	case ACT_STATUS:
		rv = do_status();
		break;
	case ACT_LOG_DUMP:
		rv = do_log_dump();
		break;
	case ACT_SET_HOST_ID:
		rv = do_set_host_id();
		break;
	default:
		break;
	}
 out:
	return rv;
}

