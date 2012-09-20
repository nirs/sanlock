/*
 * Copyright 2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signalfd.h>

#include "sanlock.h"
#include "sanlock_admin.h"
#include "sanlock_resource.h"
#include "sanlock_direct.h"
#include "wdmd.h"

/*
 * TODO: shutdown checks
 */

#define MAX_HOSTS 128 /* keep in sync with fence_sanlock definition */

#define LIVE_INTERVAL 5
#define EXPIRE_INTERVAL 20

#define RUN_DIR "/var/run/fence_sanlockd"

static char *prog_name = (char *)"fence_sanlockd";

static int we_are_victim;
static int shutdown;
static int daemon_debug;
static int our_host_id;
static char path[PATH_MAX];
static struct sanlk_lockspace ls;
static struct sanlk_resource *r;
static struct sanlk_disk disk;
static char rdbuf[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
static char lockfile_path[PATH_MAX];
static char fifo_path[PATH_MAX];
static char fifo_line[PATH_MAX];
static char key1[PATH_MAX];
static char key2[PATH_MAX];
static char val1[PATH_MAX];
static char val2[PATH_MAX];


struct client {
	int used;
	int fd;
	void *workfn;
	void *deadfn;
};

#define CLIENT_NALLOC 3
static int client_maxi;
static int client_size = 0;
static struct client *client = NULL;
static struct pollfd *pollfd = NULL;

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

static int lockfile(void)
{
	char buf[16];
	struct flock lock;
	mode_t old_umask;
	int fd, rv;

	old_umask = umask(0022);
	rv = mkdir(RUN_DIR, 0775);
	if (rv < 0 && errno != EEXIST) {
		umask(old_umask);
		return rv;
	}
	umask(old_umask);

	sprintf(lockfile_path, "%s/%s.pid", RUN_DIR, prog_name);

	fd = open(lockfile_path, O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
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
		shutdown = 1;
	}

	if (fdsi.ssi_signo == SIGUSR1) {
		we_are_victim = 1;
	}
}

static int setup_signals(void)
{
	sigset_t mask;
	int fd, rv;

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGUSR1);

	rv = sigprocmask(SIG_BLOCK, &mask, NULL);
	if (rv < 0)
		return rv;

	fd = signalfd(-1, &mask, 0);
	if (fd < 0)
		return -errno;

	client_add(fd, process_signals, NULL);
	return 0;
}

static int wait_options(void)
{
	int fd, rv;

	snprintf(fifo_path, PATH_MAX-1, "%s/%s.fifo", RUN_DIR, prog_name);

	rv = mkfifo(fifo_path, (S_IRUSR | S_IWUSR));
	if (rv && errno != EEXIST) {
		log_error("wait_options mkfifo error %d %s", errno, fifo_path);
		return -1;
	}

	fd = open(fifo_path, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		log_error("wait_options open error %d %s", errno, fifo_path);
		rv = fd;
		goto out_unlink;
	}

	memset(fifo_line, 0, sizeof(fifo_line));

	rv = read(fd, fifo_line, sizeof(fifo_line));
	if (rv < 0) {
		log_error("wait_options read error %d", errno);
		goto out;
	}

	rv = sscanf(fifo_line, "%s %s %s %s", key1, val1, key2, val2);
	if (rv != 4) {
		log_error("wait_options scan error %d", rv);
		rv = -1;
		goto out;
	}

	if (strcmp(key1, "-p") || strcmp(key2, "-i")) {
		log_error("wait_options args error");
		rv = -1;
		goto out;
	}

	strncpy(path, val1, PATH_MAX-1);
	our_host_id = atoi(val2);

	if (!our_host_id || our_host_id > MAX_HOSTS) {
		log_error("wait_options invalid host_id");
		rv = -1;
		goto out;
	}

	if (!path[0]) {
		log_error("wait_options invalid path");
		rv = -1;
		goto out;
	}

	log_debug("wait_options -p %s -i %d", path, our_host_id);
	rv = 0;
 out:
	close(fd);
 out_unlink:
	unlink(fifo_path);
	return rv;
}

static int send_options(void)
{
	int fd, rv;

	snprintf(fifo_path, PATH_MAX-1, "%s/%s.fifo", RUN_DIR, prog_name);

	fd = open(fifo_path, O_WRONLY|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "open error %d %s\n", errno, fifo_path);
		return -1;
	}

	memset(fifo_line, 0, sizeof(fifo_line));

	snprintf(fifo_line, PATH_MAX-1, "-p %s -i %d", path, our_host_id);

	rv = write(fd, fifo_line, sizeof(fifo_line));
	if (rv < 0) {
		fprintf(stderr, "write error %d %s\n", errno, fifo_path);
	} else {
		rv = 0;
	}

	close(fd);
	return rv;
}

static void print_usage(void)
{
	printf("Usage:\n");
	printf("fence_sanlockd [options]\n");
	printf("\n");
	printf("Options:\n");
	printf("  -D            Enable debugging to stderr and don't fork\n");
	printf("  -p <path>     Path to shared storage with sanlock leases\n");
	printf("  -i <host_id>  Local sanlock host_id (1-%d)\n", MAX_HOSTS);
	printf("  -w            Wait for fence_sanlockd -s to send options (p,i)\n");
	printf("  -s            Send options (p,i) to waiting fence_sanlockd -w\n");
	printf("  -h            Print this help, then exit\n");
	printf("  -V            Print program version information, then exit\n");
}

int main(int argc, char *argv[])
{
	void (*workfn) (int ci);
	void (*deadfn) (int ci);
	uint64_t live_time, now;
	int poll_timeout;
	int sleep_seconds;
	int send_opts = 0, wait_opts = 0;
	int cont = 1;
	int optchar;
	int sock, con, rv, i;
	int align;

	while (cont) {
		optchar = getopt(argc, argv, "Dp:i:hVws");

		switch (optchar) {
		case 'D':
			daemon_debug = 1;
			break;
		case 'p':
			strcpy(path, optarg);
			break;
		case 'i':
			our_host_id = atoi(optarg);
			if (our_host_id > MAX_HOSTS) {
				fprintf(stderr, "invalid host_id %d, use 1-%d\n",
					our_host_id, MAX_HOSTS);
				exit(1);
			}
			break;
		case 'w':
			wait_opts = 1;
			break;
		case 's':
			send_opts = 1;
			break;
		case 'h':
			print_usage();
			exit(0);
		case 'V':
			printf("fence_sanlockd %s (built %s %s)\n",
				VERSION, __DATE__, __TIME__);
			exit(0);
		case EOF:
			cont = 0;
			break;
		default:
			fprintf(stderr, "unknown option %c\n", optchar);
			exit(1);
		};
	}

	if (wait_opts && send_opts) {
		fprintf(stderr, "-w and -s options cannot be used together\n");
		exit(1);
	}

	if (!wait_opts && (!our_host_id || !path[0])) {
		fprintf(stderr, "-i and -p options required\n");
		exit(1);
	}

	if (send_opts) {
		rv = send_options();
		return rv;
	}

	if (!daemon_debug) {
		if (daemon(0, 0) < 0) {
			fprintf(stderr, "cannot fork daemon\n");
			exit(EXIT_FAILURE);
		}
	}

	openlog(prog_name, LOG_CONS | LOG_PID, LOG_DAEMON);

	rv = lockfile();
	if (rv < 0)
		goto out;

	rv = setup_signals();
	if (rv < 0)
		goto out_lockfile;

	if (wait_opts) {
		rv = wait_options();
		if (rv < 0)
			goto out_lockfile;
	}

	con = wdmd_connect();
	if (con < 0) {
		log_error("wdmd connect error %d", con);
		goto out_lockfile;
	}

	rv = wdmd_register(con, (char *)"fence_sanlockd");
	if (rv < 0) {
		log_error("wdmd register error %d", rv);
		goto out_lockfile;
	}

	rv = wdmd_refcount_set(con);
	if (rv < 0) {
		log_error("wdmd refcount error %d", rv);
		goto out_lockfile;
	}

	sock = sanlock_register();
	if (sock < 0) {
		log_error("register error %d", sock);
		goto out_refcount;
	}

	rv = sanlock_restrict(sock, SANLK_RESTRICT_SIGKILL);
	if (rv < 0) {
		log_error("restrict error %d", sock);
		goto out_refcount;
	}

	memset(&disk, 0, sizeof(disk));
	sprintf(disk.path, "%s", path);

	align = sanlock_direct_align(&disk);
	if (align < 0) {
		log_error("direct_align error %d", align);
		goto out_refcount;
	}

	memset(&ls, 0, sizeof(ls));
	sprintf(ls.host_id_disk.path, "%s", path);
	strcpy(ls.name, "fence");
	ls.host_id = our_host_id;

	log_debug("add_lockspace begin");

	rv = sanlock_add_lockspace(&ls, 0);
	if (rv < 0) {
		log_error("add_lockspace error %d", rv);
		goto out_refcount;
	}

	log_debug("add_lockspace done %d", rv);

	memset(rdbuf, 0, sizeof(rdbuf));
	r = (struct sanlk_resource *)&rdbuf;
	strcpy(r->lockspace_name, "fence");
	sprintf(r->name, "h%d", our_host_id);
	sprintf(r->disks[0].path, "%s", path);
	r->disks[0].offset = our_host_id * align;
	r->num_disks = 1;

	log_debug("acquire begin");

	rv = sanlock_acquire(sock, -1, 0, 1, &r, NULL);
	if (rv < 0) {
		log_error("acquire error %d", rv);
		goto out_lockspace;
	}

	log_debug("acquire done %d", rv);

	/* at this point we can be fenced by someone */

	now = monotime();
	live_time = now;
	log_debug("test live %llu", (unsigned long long)now);
	rv = wdmd_test_live(con, now, now + EXPIRE_INTERVAL);
	if (rv < 0) {
		log_error("wdmd_test_live first error %d", rv);
		goto out_release;
	}

	sleep_seconds = live_time + LIVE_INTERVAL - monotime();
	poll_timeout = (sleep_seconds > 0) ? sleep_seconds * 1000 : 500;

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

		now = monotime();

		if (shutdown) {
			/*
			 * FIXME: how to be sure that it's safe for us to shut
			 * down?  i.e. nothing is running that needs fencing?
			 *
			 * There are at least two distinct problems:
			 *
			 * 1. stopping when dlm/gfs instances exist in the
			 *    kernel, but no userland cluster processes exist,
			 *    i.e. they have exited uncleanly, and the node
			 *    currently needs fencing.
			 *
			 * 2. stopping when dlm_controld is running, but no
			 *    lockspaces currently exist.  Point 1 would pass,
			 *    but dlm_controld assumes fencing is enabled, and
			 *    would allow a new lockspace to be created, without
			 *    fencing protection if we are not running.
			 *
			 * For now, have the init script check that:
			 * - /sys/kernel/config/dlm/cluster/ is empty
			 *   (dlm_controld is not running)
			 * - /sys/kernel/dlm/ is empty
			 *   (lockspaces do not exist in the kernel)
			 */
			log_error("shutdown");
			rv = wdmd_test_live(con, 0, 0);
			if (rv < 0)
				log_error("wdmd_test_live 0 error %d", rv);
			break;

		} else if (we_are_victim) {
			/*
			 * The sanlock daemon has seen someone request our
			 * lease, which happens when they run fence_sanlock
			 * against us.  In response to the request, our sanlock
			 * daemon has sent us SIGUSR1.
			 *
			 * Do not call wdmd_test_live, so wdmd will see our
			 * connection expire, and will quit petting the
			 * watchdog, which will then fire in 60 sec.  sanlock
			 * continues renewing its host_id until the machine
			 * dies, and the node doing fencing will then be able
			 * to acquire our lease host_dead_seconds after our
			 * last sanlock renewal.
			 *
			 * TODO: we could eventually attempt to kill/unmount/etc
			 * anything using shared storage, and if that all works,
			 * then we could do a clean shutdown afterward.  That would
			 * often not work, because dlm/gfs would be stuck in the
			 * kernel due to failure (cluster partition) that caused
			 * our fencing, and couldn't be forcibly cleaned up.
			 */
			log_error("we are being fenced, our watchdog will fire");

		} else if (now - live_time >= LIVE_INTERVAL) {
			/*
			 * How to pick the expire_time.  From the perspective
			 * of fence_sanlockd the expire_time isn't really
			 * important.  It should be far enough in the future
			 * so that it's:
			 * - after the next time we're going to call test_live,
			 *   because our test_live calls are obviously meant to
			 *   keep it from expiring
			 * - more than 10 seconds in the future because of a
			 *   current quirk in wdmd, where it pre-emptively
			 *   closes the wd 10 seconds before the actual expire
			 *   time (see comments in wdmd for reason).  So we
			 *   want to be sure we renew at least 10 sec before
			 *   the last expire time.
			 *
			 * It shouldn't be too long, because when we see we're
			 * being fenced, we'll quit calling test_live, and we
			 * want our watchdog to reset us in a fairly short amount
			 * time after that (this effects how long the fencing node
			 * has to wait.) The longer the expire_time we provide,
			 * the longer it'll take before wdmd sees it expire, quits
			 * petting the wd, and resets us.
			 *
			 * So, if we have set expire_time to 20 sec in the
			 * future, and we renew once every 5 sec, we have two
			 * chances to renew before a pre-emptive close.
			 */
			live_time = now;
			log_debug("test live %llu", (unsigned long long)now);
			rv = wdmd_test_live(con, now, now + EXPIRE_INTERVAL);
			if (rv < 0)
				log_error("wdmd_test_live error %d", rv);
		}

		if (we_are_victim) {
			poll_timeout = 10000;
		} else {
			sleep_seconds = live_time + LIVE_INTERVAL - monotime();
			poll_timeout = (sleep_seconds > 0) ? sleep_seconds * 1000 : 500;
		}
	}

 out_release:
	sanlock_release(sock, -1, 0, 1, &r);
 out_lockspace:
	sanlock_rem_lockspace(&ls, 0);
 out_refcount:
	wdmd_refcount_clear(con);
 out_lockfile:
	unlink(lockfile_path);
 out:
	return rv;
}

