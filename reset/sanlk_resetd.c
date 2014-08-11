/*
 * Copyright 2014 Red Hat, Inc.
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
#include <dirent.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/signalfd.h>

#include "sanlock.h"
#include "sanlock_admin.h"
#include "sanlock_resource.h"
#include "sanlock_direct.h"
#include "wdmd.h"

static struct sockaddr_un update_addr;
static socklen_t update_addrlen;
#include "sanlk_reset.h"

#define DEFAULT_SYSRQ_DELAY 25

static char *daemon_name = (char *)"sanlk-resetd";
static int daemon_quit;
static int daemon_foreground;
static int daemon_debug;
static int poll_timeout;
static int resource_mode;
static int use_watchdog = 1;
static int use_sysrq_reboot = 0;
static int sysrq_delay = DEFAULT_SYSRQ_DELAY;
static int we_are_resetting;
static int we_are_rebooting;
static int wd_reset_failed;
static uint64_t rebooting_time;

#define MAX_LS        64
#define POLLFD_COUNT  (MAX_LS+2)
#define SIGNAL_INDEX  (MAX_LS)
#define UPDATE_INDEX  (MAX_LS+1)

static char *ls_names[MAX_LS];
static int ls_fd[MAX_LS];
static int ls_count;

static struct pollfd *pollfd;
static int update_fd;
static int signal_fd;
static int wdmd_fd;

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

#define log_warn(fmt, args...) \
do { \
	log_debug(fmt, ##args); \
	syslog(LOG_WARNING, fmt, ##args); \
} while (0)

#define log_notice(fmt, args...) \
do { \
	log_debug(fmt, ##args); \
	syslog(LOG_NOTICE, fmt, ##args); \
} while (0)


static uint64_t monotime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec;
}

/*
 * By default a 25 second delay is used before using sysrq to give sanlock
 * time to write our resetting event in its next lease renewal.
 *
 * It would not be surprising for sysrq reboot to fail or hang, so it's
 * important for the watchdog to also be there to reset us.  This
 * sysrq reboot is used only as a way to speed up the reset since the
 * watchdog requires 60 seconds to fire.
 */

static void sysrq_reboot(void)
{
	int fd, rv;

	log_notice("Rebooting host with sysrq");
	/* give at least a small chance for the log message to be written */
	sleep(1);

	fd = open("/proc/sysrq-trigger", O_WRONLY);

	if (fd < 0) {
		log_error("failed to open sysrq-trigger %d %d", fd, errno);
		return;
	}

	rv = write(fd, "b", 1);
	if (rv < 0) {
		log_error("failed to write sysrq-trigger %d %d", rv, errno);
	}

	close(fd);

	/* If sysrq reboot worked, then I don't think we will get here. */
	/* If sysrq reboot failed, then the watchdog should reset us. */
	log_error("Reboot from sysrq is expected");
}

/*
 * Use the watchdog to reset the machine as soon as possible.
 * Intentionally set the expire time on the connection to
 * the current time so that the watchdog will expire and
 * reset as soon as possible.
 */

static int watchdog_reset_self(void)
{
	uint64_t now;
	int rv;

	if (!use_watchdog)
		return 0;

	now = monotime();

	rv = wdmd_test_live(wdmd_fd, now, now);
	if (rv < 0) {
		log_error("watchdog_reset_self test_live failed %d", rv);
		return rv;
	}

	log_notice("Resetting host with watchdog");
	return 0;
}

static int setup_wdmd(void)
{
	char name[WDMD_NAME_SIZE];
	int con;
	int rv;

	if (!use_watchdog)
		return 0;

	con = wdmd_connect();
	if (con < 0) {
		log_error("setup_wdmd connect failed %d", con);
		return con;
	}

	memset(name, 0, sizeof(name));

	snprintf(name, WDMD_NAME_SIZE - 1, "sanlk-resetd");

	rv = wdmd_register(con, name);
	if (rv < 0) {
		log_error("setup_wdmd register failed %d", rv);
		goto fail_close;
	}

	/* the refcount tells wdmd that it should not cleanly exit */

	rv = wdmd_refcount_set(con);
	if (rv < 0) {
		log_error("setup_wdmd refcount_set failed %d", rv);
		goto fail_close;
	}

	log_debug("setup_wdmd %d", con);

	wdmd_fd = con;
	return 0;

 fail_close:
	close(con);
	return -1;
}

static void close_wdmd(void)
{
	if (!use_watchdog)
		return;

	wdmd_refcount_clear(wdmd_fd);
	close(wdmd_fd);
}

/*
 * This event will be included in the next lease renewal of the lockspace.
 * This should be within the next 20 seconds, unless renewals are
 * experiencing some delays.  We have about 60 seconds to get the renewal,
 * including the event, written before the watchdog fires (or syrq_delay until
 * sysrq reboot if that is configured).
 */

static void set_event_out(char *ls_name, uint64_t event_out, uint64_t from_host, uint64_t from_gen)
{
	struct sanlk_host_event he;
	int rv;

	he.host_id = from_host;
	he.generation = from_gen;
	he.event = event_out;
	he.data = 0;

	log_notice("set reply %s%s(%llx %llx) for host %llu %llu ls %s",
		   (event_out & EVENT_RESETTING) ? "resetting " : "",
		   (event_out & EVENT_REBOOTING) ? "rebooting " : "",
		   (unsigned long long)he.event,
		   (unsigned long long)he.data,
		   (unsigned long long)from_host,
		   (unsigned long long)from_gen,
		   ls_name);

	rv = sanlock_set_event(ls_name, &he, SANLK_SETEV_ALL_HOSTS);
	if (rv < 0)
		log_error("set_event error %d ls %s", rv, ls_name);
}

static int find_ls(char *name)
{
	int i;

	for (i = 0; i < MAX_LS; i++) {
		if (!ls_names[i])
			continue;

		if (!strcmp(name, ls_names[i]))
			return i;
	}

	return -1;
}

static int register_ls(int i)
{
	int fd;

	if (!ls_names[i])
		return -ENOMEM;

	fd = sanlock_reg_event(ls_names[i], NULL, 0);
	if (fd < 0) {
		log_error("reg_event %d error %d ls %s", i, fd, ls_names[i]);
		free(ls_names[i]);
		ls_names[i] = NULL;
		return fd;
	} else {
		log_debug("reg_event %d fd %d ls %s", i, fd, ls_names[i]);
		ls_fd[i] = fd;
		pollfd[i].fd = fd;
		pollfd[i].events = POLLIN;
		ls_count++;
		return 0;
	}
}

static void unregister_ls(int i)
{
	log_debug("end_event %d fd %d ls %s", i, ls_fd[i], ls_names[i]);
	sanlock_end_event(ls_fd[i], ls_names[i], 0);
	free(ls_names[i]);
	ls_names[i] = NULL;
	ls_fd[i] = -1;
	pollfd[i].fd = -1;
	pollfd[i].events = 0;
	ls_count--;
}

static void get_events(int i)
{
	struct sanlk_host_event from_he;
	uint64_t from_host, from_gen;
	uint64_t event, event_out;
	int set_config_failed;
	int rv;

	while (1) {
		rv = sanlock_get_event(ls_fd[i], 0, &from_he, &from_host, &from_gen);
		if (rv == -EAGAIN)
			break;
		if (rv < 0) {
			log_error("unregister %d fd %d get_event error %d ls %s",
				  i, ls_fd[i], rv, ls_names[i]);
			unregister_ls(i);
			break;
		}

		event = from_he.event;
		event_out = 0;
		set_config_failed = 0;

		if (event & (EVENT_RESET | EVENT_REBOOT)) {
			log_notice("request to %s%s(%llx %llx) from host %llu %llu ls %s",
				   (event & EVENT_RESET) ? "reset " : "",
				   (event & EVENT_REBOOT) ? "reboot " : "",
				   (unsigned long long)from_he.event,
				   (unsigned long long)from_he.data,
				   (unsigned long long)from_host,
				   (unsigned long long)from_gen,
				   ls_names[i]);
		}

		if (event & (EVENT_RESETTING | EVENT_REBOOTING)) {
			log_notice("notice of %s%s(%llx %llx) from host %llu %llu ls %s",
				   (event & EVENT_RESETTING) ? "resetting " : "",
				   (event & EVENT_REBOOTING) ? "rebooting " : "",
				   (unsigned long long)from_he.event,
				   (unsigned long long)from_he.data,
				   (unsigned long long)from_host,
				   (unsigned long long)from_gen,
				   ls_names[i]);
		}

		if ((event & EVENT_REBOOT) && !use_sysrq_reboot) {
			event &= ~EVENT_REBOOT;
			log_error("ignore reboot request sysrq_reboot not enabled");
		}

		if ((event & EVENT_RESET) && !resource_mode) {
			/* prevent lockspaces from cleanly exiting from lost storage,
			   if this cannot be done, then do not set_event_out. */

			rv = sanlock_set_config(ls_names[i], 0, SANLK_CONFIG_USED, NULL);
			if (rv < 0) {
				log_error("sanlock_set_config error %d ls %s",
					  rv, ls_names[i]);
				set_config_failed = 1;
			}
		}

		if ((event & EVENT_RESET) && !we_are_resetting) {
			we_are_resetting = 1;
			poll_timeout = 1000;
			wd_reset_failed = watchdog_reset_self();
		}


		if ((event & EVENT_REBOOT) && !we_are_rebooting) {
			we_are_rebooting = 1;
			poll_timeout = 1000;
			rebooting_time = monotime();
		}

		/*
		 * We attempt to reply to reset requests in any lockspace
		 * where we get one, even though we initiate the reset only
		 * the first time we get the request.  The first lockspace
		 * through which we get the request is most likely to get
		 * our reply.  Our reply through subsequent lockspaces are
		 * less likely to have time to be written out before the
		 * reset/reboot actually occur.
		 *
		 * Our resetting reply is addressed to all hosts.  Multiple
		 * hosts could ask us to reset, and all will get the reply
		 * to the first we receive.
		 */

		if (we_are_resetting && !wd_reset_failed)
			event_out |= EVENT_RESETTING;
		if (we_are_rebooting)
			event_out |= EVENT_REBOOTING;

		if (event_out && !set_config_failed) {
			set_event_out(ls_names[i], event_out, from_host, from_gen);

			/* No further events from this lockspace are useful. */
			pollfd[i].fd = -1;
			pollfd[i].events = 0;
			return;
		}
	}
}

static int setup_signals(void)
{
	sigset_t mask;
	int rv;

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGHUP);

	rv = sigprocmask(SIG_BLOCK, &mask, NULL);
	if (rv < 0)
		return rv;

	signal_fd = signalfd(-1, &mask, 0);
	if (signal_fd < 0)
		return -errno;

	return 0;
}

static void process_signal(int fd)
{
	struct signalfd_siginfo fdsi;
	ssize_t rv;

	rv = read(fd, &fdsi, sizeof(struct signalfd_siginfo));
	if (rv != sizeof(struct signalfd_siginfo))
		return;

	if ((fdsi.ssi_signo == SIGTERM) || (fdsi.ssi_signo == SIGINT)) {
		log_debug("daemon_quit signal %d", fdsi.ssi_signo);
		daemon_quit = 1;
	}
}

static int setup_update(void)
{
	int s, rv;

	rv = mkdir(SANLK_RESETD_RUNDIR, 0755);
	if (rv < 0 && errno != EEXIST)
		return rv;

	s = setup_resetd_socket();

	unlink(update_addr.sun_path);
	rv = bind(s, (struct sockaddr *) &update_addr, update_addrlen);
	if (rv < 0)
		goto fail_close;

	rv = chmod(update_addr.sun_path, SANLK_RESETD_SOCKET_MODE);
	if (rv < 0)
		goto fail_close;

	update_fd = s;
	return 0;

fail_close:
	close(s);
	return -1;
}

static void process_update(int fd)
{
	char buf[UPDATE_SIZE];
	char cmd[UPDATE_SIZE];
	char name[UPDATE_SIZE];
	int i, rv;

	memset(buf, 0, sizeof(buf));
	memset(cmd, 0, sizeof(cmd));
	memset(name, 0, sizeof(name));

	rv = recvfrom(fd, buf, UPDATE_SIZE, MSG_DONTWAIT,
		      (struct sockaddr *) &update_addr, &update_addrlen);
	if (!rv || rv < 0 || rv != UPDATE_SIZE) {
		log_debug("process_update recvfrom error %d %d", rv, errno);
		return;
	}

	buf[UPDATE_SIZE-1] = '\0';

	rv = sscanf(buf, "%s %s", cmd, name);
	if (rv != 2) {
		log_debug("process_update ignore message %d", rv);
		return;
	}

	if (!strcmp(cmd, "reg")) {
		log_debug("process_update reg %s", name);

		/* if the name exists, end then reg */
		i = find_ls(name);
		if (i > -1) {
			unregister_ls(i);
			ls_names[i] = strdup(name);
			register_ls(i);
			return;
		}

		for (i = 0; i < MAX_LS; i++) {
			if (ls_names[i])
				continue;

			ls_names[i] = strdup(name);
			register_ls(i);
			return;
		}

	} else if (!strcmp(cmd, "end")) {
		log_debug("process_update end %s", name);

		i = find_ls(name);
		if (i > -1) {
			unregister_ls(i);
			return;
		}

	} else if (!strcmp(cmd, "clear")) {
		log_debug("process_update clear %s", name);

		for (i = 0; i < MAX_LS; i++) {
			if (!ls_names[i])
				continue;
			unregister_ls(i);
		}
	} else {
		log_debug("process_update cmd unknown");
	}
}

static void usage(void)
{
	printf("%s [options] lockspace_name ...\n", daemon_name);
	printf("  --help | -h\n");
	printf("        Show this help information.\n");
	printf("  --version | -V\n");
	printf("        Show version.\n");
	printf("  --foreground | -f\n");
	printf("        Don't fork.\n");
	printf("  --daemon-debug | -D\n");
	printf("        Don't fork and print debugging to stdout.\n");
	printf("  --watchdog | -w 0|1\n");
	printf("        Disable (0) use of wdmd/watchdog for testing.\n");
	printf("  --sysrq-reboot | -b 0|1\n");
	printf("        Enable/Disable (1/0) use of /proc/sysrq-trigger to reboot (default 0).\n");
	printf("  --sysrq-delay | -d <sec>\n");
	printf("        Delay this many seconds before using /proc/sysrq-trigger (default %d).\n", DEFAULT_SYSRQ_DELAY);
	printf("  --resource-mode | -R 0|1\n");
	printf("        Resource leases are used (1) or not used (0) to protect storage.\n");
	printf("\n");
	printf("Get reset events from lockspace_name (max %d).\n", MAX_LS);
}

int main(int argc, char *argv[])
{
	int ls_argc = 0;
	int i, rv;

	static struct option long_options[] = {
		{"help",	  no_argument,	    0, 'h' },
		{"version",       no_argument,	    0, 'V' },
		{"foreground",    no_argument,	    0, 'f' },
		{"daemon-debug",  no_argument,	    0, 'D' },
		{"watchdog",      required_argument, 0, 'w' },
		{"sysrq-reboot",  required_argument, 0, 'b' },
		{"sysrq-delay",   required_argument, 0, 'd' },
		{"resource-mode", required_argument, 0, 'R' },
		{0, 0, 0, 0 }
	};

	while (1) {
		int c;
		int option_index = 0;

		c = getopt_long(argc, argv, "hVfDw:b:d:R:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case '0':
			break;
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'V':
			printf("%s version: " VERSION "\n", daemon_name);
			exit(EXIT_SUCCESS);
		case 'f':
			daemon_foreground = 1;
			break;
		case 'D':
			daemon_foreground = 1;
			daemon_debug = 1;
			break;
		case 'R':
			resource_mode = atoi(optarg);
			break;
		case 'w':
			use_watchdog = atoi(optarg);
			break;
		case 'b':
			use_sysrq_reboot = atoi(optarg);
			break;
		case 'd':
			sysrq_delay = atoi(optarg);
			break;
		case '?':
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	for (i = optind; i < argc; i++) {
		if (ls_argc == MAX_LS) {
			fprintf(stderr, "ignore lockspace_name %s", argv[i]);
			continue;
		}
		ls_names[ls_argc] = strdup(argv[i]);
		ls_argc++;
	}

	if (!daemon_foreground) {
		if (daemon(0, 0) < 0) {
			fprintf(stderr, "cannot fork daemon\n");
			exit(EXIT_FAILURE);
		}
	}

	openlog(daemon_name, LOG_CONS | LOG_PID, LOG_DAEMON);

	log_notice("%s %s started %s", daemon_name, VERSION, use_watchdog ? "" : "use_watchdog=0");

	rv = setup_wdmd();
	if (rv < 0) {
		log_error("failed to set up wdmd");
		return rv;
	}

	rv = setup_signals();
	if (rv < 0) {
		log_error("failed to set up signal fd");
		goto out;
	}

	rv = setup_update();
	if (rv < 0) {
		log_error("failed to set up update fd");
		goto out;
	}

	/*
	 * MAX_LS+2: MAX_LS fd's for lockspace, 1 fd for signal_fd, 1 fd for update_fd.
	 */

	pollfd = malloc(POLLFD_COUNT * sizeof(struct pollfd));
	if (!pollfd)
		return -ENOMEM;
	memset(pollfd, 0, POLLFD_COUNT * sizeof(struct pollfd));

	for (i = 0; i < POLLFD_COUNT; i++)
		pollfd[i].fd = -1;

	pollfd[SIGNAL_INDEX].fd = signal_fd;
	pollfd[SIGNAL_INDEX].events = POLLIN;
	pollfd[UPDATE_INDEX].fd = update_fd;
	pollfd[UPDATE_INDEX].events = POLLIN;

	/*
	 * register with sanlock for each initial lockspace
	 */

	for (i = 0; i < MAX_LS; i++)
		ls_fd[i] = -1;

	for (i = 0; i < ls_argc; i++)
		register_ls(i);

	poll_timeout = -1;

	while (1) {
		rv = poll(pollfd, POLLFD_COUNT, poll_timeout);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0)
			break;

		if (pollfd[SIGNAL_INDEX].revents & POLLIN)
			process_signal(pollfd[SIGNAL_INDEX].fd);

		if (pollfd[UPDATE_INDEX].revents & POLLIN)
			process_update(pollfd[UPDATE_INDEX].fd);

		if (pollfd[UPDATE_INDEX].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			close(update_fd);
			pollfd[UPDATE_INDEX].fd = -1;
			pollfd[UPDATE_INDEX].events = 0;
			pollfd[UPDATE_INDEX].revents = 0;
		}

		if (daemon_quit)
			break;

		if (we_are_rebooting && (monotime() - rebooting_time >= sysrq_delay)) {
			sysrq_reboot();
		}

		for (i = 0; i < MAX_LS; i++) {
			if (pollfd[i].revents & POLLIN)
				get_events(i);

			if (pollfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				log_debug("unregister %d ls_fd %d pollfd %d %x %x ls %s",
					  i, ls_fd[i], pollfd[i].fd,
					  pollfd[i].events, pollfd[i].revents,
					  ls_names[i]);
				unregister_ls(i);
			}
		}
	}

	log_debug("unregister daemon_quit=%d ls_count=%d", daemon_quit, ls_count);

	for (i = 0; i < MAX_LS; i++) {
		if (!ls_names[i])
			continue;
		if (ls_fd[i] == -1)
			continue;
		unregister_ls(i);
	}
out:
	close_wdmd();
	return 0;
}
