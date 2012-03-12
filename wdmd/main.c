/*
 * Copyright 2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <stddef.h>
#include <grp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <poll.h>
#include <syslog.h>
#include <dirent.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <linux/watchdog.h>

#include "wdmd.h"
#include "wdmd_sock.h"

#ifndef GNUC_UNUSED
#define GNUC_UNUSED __attribute__((__unused__))
#endif

#define RELEASE_VERSION "2.1"

#define DEFAULT_TEST_INTERVAL 10
#define DEFAULT_FIRE_TIMEOUT 60
#define DEFAULT_HIGH_PRIORITY 1

#define DEFAULT_SOCKET_GID 0
#define DEFAULT_SOCKET_MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)

static int test_interval = DEFAULT_TEST_INTERVAL;
static int fire_timeout = DEFAULT_FIRE_TIMEOUT;
static int high_priority = DEFAULT_HIGH_PRIORITY;
static int daemon_quit;
static int daemon_debug;
static int socket_gid;
static time_t last_keepalive;
static char lockfile_path[PATH_MAX];
static int dev_fd;

struct script_status {
	int pid;
	char path[PATH_MAX];
};

/* The relationship between SCRIPT_WAIT_SECONDS/MAX_SCRIPTS/test_interval
   is not very sophisticated, but it's simple.  If we wait up to 2 seconds
   for each script to exit, and have 5 scripts, that's up to 10 seconds we
   spend in test_scripts, and it's simplest if the max time in test_scripts
   does not excede the test_interval (10). */

#define SCRIPT_WAIT_SECONDS 2
#define MAX_SCRIPTS 4
struct script_status scripts[MAX_SCRIPTS];

struct client {
	int used;
	int fd;
	int pid;
	int pid_dead;
	int refcount;
	uint64_t renewal;
	uint64_t expire;
	void *workfn;
	void *deadfn;
	char name[WDMD_NAME_SIZE];
};

#define CLIENT_NALLOC 16
static int client_maxi;
static int client_size = 0;
static struct client *client = NULL;
static struct pollfd *pollfd = NULL;
const char *client_built = " client";


#define log_debug(fmt, args...) \
do { \
	if (daemon_debug) \
		fprintf(stderr, "%llu " fmt "\n", (unsigned long long)time(NULL), ##args); \
} while (0)

#define log_error(fmt, args...) \
do { \
	log_debug(fmt, ##args); \
	syslog(LOG_ERR, fmt, ##args); \
} while (0)


static uint64_t monotime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec;
}

/*
 * test clients
 */

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
		memset(&client[i], 0, sizeof(struct client));
		client[i].fd = -1;
		pollfd[i].fd = -1;
		pollfd[i].revents = 0;
	}
	client_size += CLIENT_NALLOC;
}

static int client_add(int fd, void (*workfn)(int ci), void (*deadfn)(int ci))
{
	int i;

	if (!client)
		client_alloc();
 again:
	for (i = 0; i < client_size; i++) {
		if (!client[i].used) {
			client[i].used = 1;
			client[i].workfn = workfn;
			client[i].deadfn = deadfn;
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

static void client_pid_dead(int ci)
{
	if (!client[ci].expire) {
		log_debug("client_pid_dead ci %d", ci);

		close(client[ci].fd);

		client[ci].used = 0;
		memset(&client[ci], 0, sizeof(struct client));

		client[ci].fd = -1;
		pollfd[ci].fd = -1;
		pollfd[ci].events = 0;
	} else {
		/* test_clients() needs to continue watching this ci so
		   it can expire */

		log_debug("client_pid_dead ci %d expire %llu", ci,
			  (unsigned long long)client[ci].expire);

		close(client[ci].fd);

		client[ci].pid_dead = 1;
		client[ci].refcount = 0;

		client[ci].fd = -1;
		pollfd[ci].fd = -1;
		pollfd[ci].events = 0;
	}
}

static int get_peer_pid(int fd, int *pid)
{
	struct ucred cred;
	unsigned int cl = sizeof(cred);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cl) != 0)
		return -1;

	*pid = cred.pid;
	return 0;
}

static void process_connection(int ci)
{
	struct wdmd_header h;
	struct wdmd_header h_ret;
	void (*deadfn)(int ci);
	int rv, pid;

	memset(&h, 0, sizeof(h));

	rv = recv(client[ci].fd, &h, sizeof(h), MSG_WAITALL);
	if (!rv)
		return;
	if (rv < 0) {
		log_error("ci %d recv error %d", ci, errno);
		goto dead;
	}
	if (rv != sizeof(h)) {
		log_error("ci %d recv size %d", ci, rv);
		goto dead;
	}

	switch(h.cmd) {
	case CMD_REGISTER:
		/* TODO: allow client to reconnect, search clients for h.name
		   and copy the renewal and expire times, then clear the
		   old client entry */

		rv = get_peer_pid(client[ci].fd, &pid);
		if (rv < 0)
			goto dead;
		client[ci].pid = pid;
		memcpy(client[ci].name, h.name, WDMD_NAME_SIZE);
		log_debug("register ci %d fd %d pid %d %s", ci, client[ci].fd,
			  pid, client[ci].name);
		break;

	case CMD_REFCOUNT_SET:
		client[ci].refcount = 1;
		break;

	case CMD_REFCOUNT_CLEAR:
		client[ci].refcount = 0;
		break;

	case CMD_TEST_LIVE:
		client[ci].renewal = h.renewal_time;
		client[ci].expire = h.expire_time;
		log_debug("test_live ci %d renewal %llu expire %llu", ci,
			  (unsigned long long)client[ci].renewal,
			  (unsigned long long)client[ci].expire);
		break;

	case CMD_STATUS:
		memcpy(&h_ret, &h, sizeof(h));
		h_ret.test_interval = test_interval;
		h_ret.fire_timeout = fire_timeout;
		h_ret.last_keepalive = last_keepalive;
		send(client[ci].fd, &h_ret, sizeof(h_ret), MSG_NOSIGNAL);
		break;
	};

	return;

 dead:
	deadfn = client[ci].deadfn;
	if (deadfn)
		deadfn(ci);
}

static void process_listener(int ci)
{
	int fd;
	int on = 1;

	fd = accept(client[ci].fd, NULL, NULL);
	if (fd < 0)
		return;

	setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

	client_add(fd, process_connection, client_pid_dead);
}

static void close_clients(void)
{
}

static int setup_listener_socket(int *listener_socket)
{
	int rv, s;
	struct sockaddr_un addr;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0)
		return -errno;

	rv = wdmd_socket_address(&addr);
	if (rv < 0)
		return rv;

	unlink(addr.sun_path);
	rv = bind(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (rv < 0) {
		rv = -errno;
		close(s);
		return rv;
	}

	rv = listen(s, 5);
	if (rv < 0) {
		rv = -errno;
		close(s);
		return rv;
	}

	rv = chmod(addr.sun_path, DEFAULT_SOCKET_MODE);
	if (rv < 0) {
		rv = -errno;
		close(s);
		return rv;
	}

	rv = chown(addr.sun_path, -1, socket_gid);
	if (rv < 0) {
		rv = -errno;
		close(s);
		return rv;
	}

	fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);

	*listener_socket = s;
	return 0;
}

static int setup_clients(void)
{
	int rv, fd = -1, ci;

	rv = setup_listener_socket(&fd);
	if (rv < 0)
		return rv;

	ci = client_add(fd, process_listener, client_pid_dead);
	return 0;
}

static int test_clients(void)
{
	uint64_t t;
	int fail_count = 0;
	int i;

	t = monotime();

	for (i = 0; i < client_size; i++) {
		if (!client[i].used)
		       continue;
		if (!client[i].expire)
			continue;

		if (t >= client[i].expire) {
			log_error("test failed pid %d renewal %llu expire %llu",
				  client[i].pid,
				  (unsigned long long)client[i].renewal,
				  (unsigned long long)client[i].expire);
			fail_count++;
		}
	}

	return fail_count;
}

static int active_clients(void)
{
	int i;

	for (i = 0; i < client_size; i++) {
		if (client[i].refcount)
			return 1;
	}
	return 0;
}


#ifdef TEST_FILES
#define FILES_DIR "/var/run/wdmd/test_files"
const char *files_built = " files";
static DIR *files_dir;

static void close_files(void)
{
	closedir(files_dir);
}

static int setup_files(void)
{
	mode_t old_umask;
	int rv;

	old_umask = umask(0022);
	rv = mkdir(FILES_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	files_dir = opendir(FILES_DIR);
	if (!files_dir)
		rv = -errno;
	else
		rv = 0;
 out:
	umask(old_umask);
	return rv;
}

static int read_file(char *name, uint64_t *renewal, uint64_t *expire)
{
	FILE *file;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX-1, "%s/%s", FILES_DIR, name);

	file = fopen(path, "r");
	if (!file)
		return -1;

	fscanf(file, "renewal %llu expire %llu", renewal, expire);

	fclose(file);
	return 0;
}

static int test_files(void)
{
	struct dirent *de;
	uint64_t t, renewal, expire;
	int fail_count = 0;
	int rv;

	while ((de = readdir(files_dir))) {
		if (de->d_name[0] == '.')
			continue;

		rv = read_file(de->d_name, &renewal, &expire);
		if (rv < 0)
			continue;

		t = monotime();

		if (t >= expire) {
			log_error("test failed file %s renewal %llu expire %llu ",
				  de->d_name,
				  (unsigned long long)renewal,
				  (unsigned long long)expire);
			fail_count++;
		}
	}

	return fail_count;
}

#else

const char *files_built = NULL;
static void close_files(void) { }
static int setup_files(void) { return 0; }
static int test_files(void) { return 0; }

#endif /* TEST_FILES */


#ifdef TEST_SCRIPTS
#define SCRIPTS_DIR "/etc/wdmd/test_scripts"
static DIR *scripts_dir;
const char *scripts_built = " scripts";

static void close_scripts(void)
{
	closedir(scripts_dir);
}

static int setup_scripts(void)
{
	mode_t old_umask;
	int rv;

	old_umask = umask(0022);
	rv = mkdir(SCRIPTS_DIR, 0777);
	if (rv < 0 && errno != EEXIST)
		goto out;

	scripts_dir = opendir(SCRIPTS_DIR);
	if (!scripts_dir)
		rv = -errno;
	else
		rv = 0;
 out:
	umask(old_umask);
	return rv;
}

static int run_script(char *name, int i)
{
	int pid;

	if (i >= MAX_SCRIPTS) {
		log_error("max scripts %d, ignore %s", MAX_SCRIPTS, name);
		return -1;
	}

	snprintf(scripts[i].path, PATH_MAX-1, "%s/%s", SCRIPTS_DIR, name);

	pid = fork();
	if (pid < 0)
		return -errno;

	if (pid) {
		log_debug("run_script %d %s", pid, name);
		scripts[i].pid = pid;
		return 0;
	} else {
		execlp(scripts[i].path, scripts[i].path, NULL);
		exit(EXIT_FAILURE);
	}
}

static int check_script(int i)
{
	time_t begin;
	int status;
	int rv;

	if (!scripts[i].pid)
		return 0;

	begin = monotime();

	while (1) {
		rv = waitpid(scripts[i].pid, &status, WNOHANG);

		if (rv < 0) {
			goto out;

		} else if (!rv) {
			/* pid still running */
			if (monotime() - begin >= SCRIPT_WAIT_SECONDS) {
				rv = -ETIMEDOUT;
				goto out;
			}
			sleep(1);

		} else if (WIFEXITED(status)) {
			/* pid exited */
			if (!WEXITSTATUS(status))
				rv = 0;
			else
				rv = -1;
			goto out;

		} else {
			/* pid state changed but still running */
			if (monotime() - begin >= 2) {
				rv = -ETIMEDOUT;
				goto out;
			}
			sleep(1);
		}
	}
 out:
	log_debug("check_script %d rv %d begin %llu",
		  scripts[i].pid, rv, (unsigned long long)begin);

	scripts[i].pid = 0;
	return rv;
}

static int test_scripts(void)
{
	struct dirent *de;
	int fail_count = 0;
	int run_count = 0;
	int i, rv;

	memset(scripts, 0, sizeof(scripts));

	rewinddir(scripts_dir);

	while ((de = readdir(scripts_dir))) {
		if (de->d_name[0] == '.')
			continue;

		rv = run_script(de->d_name, run_count);
		if (!rv)
			run_count++;
	}

	for (i = 0; i < run_count; i++) {
		rv = check_script(i);
		if (rv < 0) {
			log_error("test failed script %s", scripts[i].path);
			fail_count++;
		}
	}

	return fail_count;
}

#else

const char *scripts_built = NULL;
static void close_scripts(void) { }
static int setup_scripts(void) { return 0; }
static int test_scripts(void) { return 0; }

#endif /* TEST_SCRIPTS */


static void close_watchdog(void)
{
	int rv;

	rv = write(dev_fd, "V", 1);
	if (rv < 0)
		log_error("/dev/watchdog disarm write error %d", errno);
	else
		log_error("/dev/watchdog disarmed");

	close(dev_fd);
}

static int setup_watchdog(void)
{
	int rv, timeout;

	dev_fd = open("/dev/watchdog", O_WRONLY | O_CLOEXEC);
	if (dev_fd < 0) {
		log_error("no /dev/watchdog, load a watchdog driver");
		return dev_fd;
	}

	timeout = 0;

	rv = ioctl(dev_fd, WDIOC_GETTIMEOUT, &timeout);
	if (rv < 0) {
		log_error("/dev/watchdog failed to report timeout");
		close_watchdog();
		return -1;
	}

	if (timeout == fire_timeout)
		goto out;

	timeout = fire_timeout;

	rv = ioctl(dev_fd, WDIOC_SETTIMEOUT, &timeout);
	if (rv < 0) {
		log_error("/dev/watchdog failed to set timeout");
		close_watchdog();
		return -1;
	}

	if (timeout != fire_timeout) {
		log_error("/dev/watchdog failed to set new timeout");
		close_watchdog();
		return -1;
	}
 out:
	log_error("/dev/watchdog armed with fire_timeout %d", fire_timeout);

	return 0;
}

static void pet_watchdog(void)
{
	int rv, unused;

	rv = ioctl(dev_fd, WDIOC_KEEPALIVE, &unused);

	last_keepalive = monotime();
	log_debug("keepalive %d", rv);
}

static void process_signals(int ci)
{
	struct signalfd_siginfo fdsi;
	ssize_t rv;
	int fd = client[ci].fd;

	rv = read(fd, &fdsi, sizeof(struct signalfd_siginfo));
	if (rv != sizeof(struct signalfd_siginfo)) {
		return;
	}

	if (fdsi.ssi_signo == SIGTERM) {
		if (!active_clients())
			daemon_quit = 1;
	}
}

static int setup_signals(void)
{
	sigset_t mask;
	int fd, rv;

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);

	rv = sigprocmask(SIG_BLOCK, &mask, NULL);
	if (rv < 0)
		return rv;

	fd = signalfd(-1, &mask, 0);
	if (fd < 0)
		return -errno;

	client_add(fd, process_signals, client_pid_dead);
	return 0;
}

static int test_loop(void)
{
	void (*workfn) (int ci);
	void (*deadfn) (int ci);
	uint64_t test_time;
	int poll_timeout;
	int sleep_seconds;
	int fail_count;
	int rv, i;

	pet_watchdog();

	test_time = 0;
	poll_timeout = test_interval * 1000;

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

		if (daemon_quit && !active_clients())
			break;

		if (monotime() - test_time >= test_interval) {
			test_time = monotime();
			log_debug("test_time %llu",
				  (unsigned long long)test_time);

			fail_count = 0;
			fail_count += test_files();
			fail_count += test_scripts();
			fail_count += test_clients();

			if (!fail_count)
				pet_watchdog();
		}

		sleep_seconds = test_time + test_interval - monotime();
		poll_timeout = (sleep_seconds > 0) ? sleep_seconds * 1000 : 1;
		log_debug("sleep_seconds %d", sleep_seconds);
	}

	return 0;
}

static int lockfile(void)
{
	char buf[16];
	struct flock lock;
	mode_t old_umask;
	int fd, rv;

	old_umask = umask(0022);
	rv = mkdir(WDMD_RUN_DIR, 0777);
	if (rv < 0 && errno != EEXIST) {
		umask(old_umask);
		return rv;
	}
	umask(old_umask);

	sprintf(lockfile_path, "%s/wdmd.pid", WDMD_RUN_DIR);

	fd = open(lockfile_path, O_CREAT|O_WRONLY|O_CLOEXEC, 0666);
	if (fd < 0) {
		log_error("lockfile open error %s: %s",
			  lockfile_path, strerror(errno));
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	rv = fcntl(fd, F_SETLK, &lock);
	if (rv < 0) {
		log_error("lockfile setlk error %s: %s",
			  lockfile_path, strerror(errno));
		goto fail;
	}

	rv = ftruncate(fd, 0);
	if (rv < 0) {
		log_error("lockfile truncate error %s: %s",
			  lockfile_path, strerror(errno));
		goto fail;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d\n", getpid());

	rv = write(fd, buf, strlen(buf));
	if (rv <= 0) {
		log_error("lockfile write error %s: %s",
			  lockfile_path, strerror(errno));
		goto fail;
	}

	return fd;
 fail:
	close(fd);
	return -1;
}

static void setup_priority(void)
{
	struct sched_param sched_param;
	int rv;

	if (!high_priority)
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

static void print_usage_and_exit(int status)
{
	printf("Usage:\n");
	printf("wdmd [options]\n\n");
	printf("--version, -V         print version\n");
	printf("--help, -h            print usage\n");
	printf("-D                    debug: no fork and print all logging to stderr\n");
	printf("-H <num>              use high priority features (1 yes, 0 no, default %d)\n",
				      DEFAULT_HIGH_PRIORITY);
	printf("-G <groupname>        group ownership for the socket\n");
	exit(status);
}

static void print_version_and_exit(void)
{
	printf("wdmd version %s tests_built%s%s%s\n", RELEASE_VERSION,
	       scripts_built ? scripts_built : "",
	       client_built ? client_built : "",
	       files_built ? files_built : "");
	exit(0);
}

/* If wdmd exits abnormally, /dev/watchdog will eventually fire, and clients
   can detect wdmd is gone and begin to shut down cleanly ahead of the reset.
   But what if wdmd is restarted before the wd fires?  It will begin petting
   /dev/watchdog again, leaving the previous clients unprotected.  I don't
   know if this situation is important enough to try to prevent.  One way
   would be for wdmd to fail starting if it found a pid file left over from
   its previous run. */

int main(int argc, char *argv[])
{
	int rv;

	/*
	 * TODO:
	 * -c <num> enable test clients (1 yes, 0 no, default ...)
	 * -s <num> enable test scripts (1 yes, 0 no, default ...)
	 * -f <num> enable test files (1 yes, 0 no, default ...)
	 */

	while (1) {
	    int c;
	    int option_index = 0;

	    static struct option long_options[] = {
	        {"help",    no_argument, 0,  'h' },
	        {"version", no_argument, 0,  'V' },
	        {0,         0,           0,  0 }
	    };

	    c = getopt_long(argc, argv, "hVDH:G:",
	                    long_options, &option_index);
	    if (c == -1)
	         break;

	    switch (c) {
	        case 'h':
                    print_usage_and_exit(0);
	            break;
	        case 'V':
                    print_version_and_exit();
	            break;
	        case 'D':
	            daemon_debug = 1;
	            break;
	        case 'G':
	            socket_gid = group_to_gid(optarg);
	            break;
	        case 'H':
	            high_priority = atoi(optarg);
	            break;
	    }
	}

	if (!daemon_debug) {
		if (daemon(0, 0) < 0) {
			fprintf(stderr, "cannot fork daemon\n");
			exit(EXIT_FAILURE);
		}
		umask(0);
	}

	openlog("wdmd", LOG_CONS | LOG_PID, LOG_DAEMON);

	log_error("wdmd started tests_built%s%s%s\n",
		  scripts_built ? scripts_built : "",
		  client_built ? client_built : "",
		  files_built ? files_built : "");
		  
	setup_priority();

	rv = lockfile();
	if (rv < 0)
		goto out;

	rv = setup_signals();
	if (rv < 0)
		goto out_lockfile;

	rv = setup_scripts();
	if (rv < 0)
		goto out_lockfile;

	rv = setup_files();
	if (rv < 0)
		goto out_scripts;

	rv = setup_clients();
	if (rv < 0)
		goto out_files;

	rv = setup_watchdog();
	if (rv < 0)
		goto out_clients;

	rv = test_loop();

	close_watchdog();
 out_clients:
	close_clients();
 out_files:
	close_files();
 out_scripts:
	close_scripts();
 out_lockfile:
	unlink(lockfile_path);
 out:
	return rv;
}

