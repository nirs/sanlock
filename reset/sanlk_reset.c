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

static struct sockaddr_un update_addr;
static socklen_t update_addrlen;
#include "sanlk_reset.h"

#define MAX_LS 64

static char *prog_name;
static uint64_t begin;
static struct pollfd *pollfd;
static int use_watchdog = 1;
static int use_sysrq_reboot = 0;
static int resource_mode;
static int target_host_id;
static uint64_t target_generation;
static int ls_count;
static char *ls_names[MAX_LS];
static int ls_hostids[MAX_LS];
static int ls_fd[MAX_LS];
static uint64_t ls_timestamp[MAX_LS];
static uint32_t ls_host_flags[MAX_LS];
static int ls_is_resetting[MAX_LS];
static int ls_is_dead[MAX_LS];
static int ls_is_free[MAX_LS];
static int ls_renewals[MAX_LS];

#define log_debug(fmt, args...) \
do { \
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

static void unregister_ls(int i)
{
	sanlock_end_event(ls_fd[i], ls_names[i], 0);
	ls_names[i] = NULL;
	ls_fd[i] = -1;
	pollfd[i].fd = -1;
	pollfd[i].events = 0;
	ls_count--;
}

static const char *host_flag_str(uint32_t flags)
{
	switch(flags) {
	case SANLK_HOST_UNKNOWN:
		return "unknown";
	case SANLK_HOST_FREE:
		return "free";
	case SANLK_HOST_LIVE:
		return "live";
	case SANLK_HOST_FAIL:
		return "fail";
	case SANLK_HOST_DEAD:
		return "dead";
	default:
		return "invalid";
	};
}

/*
 * When should we give up waiting for a host to be dead/done
 * and exit with a failure?
 *
 * If we have not seen a resetting reply from the host
 * and it has renewed its lease a number of times [+],
 * then it probably did not get the reset event or was
 * not able to perform it.
 * If this is true for all lockspaces, then give up.
 *
 * If we have not seen a resetting reply from the host
 * and it is now DEAD in the lockspace, then it probably
 * was reset/rebooted before its reply was written, or
 * it lost access to storage.
 * If this is true for all lockspaces, then give up.
 *
 * (When resource_mode is 1 we can wait until host is DEAD
 * and not require a resetting reply, so in that case we
 * might want an option to skip the early failure when
 * two renewals are received with no reply...
 * or just remove resource_mode 1?)
 *
 * [+] The number of lease renewals that can be
 * seen between set RESET and get RESETTING:
 *
 * host2 sanlock renews its lease
 * . writes TS1
 *
 * host1 sanlock renews its lease
 * . reads TS1
 *
 *                host1 sanlk-reset set_event RESET
 *
 *                host1 sanlk-reset get_hosts
 *                . ls_timestamp = TS1
 *
 * host2 sanlock renews its lease
 * . writes TS2
 *
 * host1 sanlock renews its lease
 * . reads TS2
 * . writes RESET
 *
 *                host1 sanlk-reset get_hosts
 *                . ls_timestamp = TS2
 *                . ls_renewals = 1
 *
 * host2 sanlock renews its lease
 * . writes TS3
 * . reads RESET
 *
 * host1 sanlock renews its lease
 * . reads TS3
 *
 *                host1 sanlk-reset get_hosts
 *                . ls_timestamp = TS3
 *                . ls_renewals = 2
 *
 *                host2 sanlk-resetd get_event RESET
 *                . set watchdog to fire
 *
 *                host2 sanlk-resetd set_event RESETTING
 *
 * host2 sanlock renews its lease
 * . writes TS4
 * . writes RESETTING
 *
 * host1 sanlock renews its lease
 * . reads TS4
 * . reads RESETTING
 *
 *                host1 sanlk-reset get_hosts
 *                . ls_timestamp = TS4
 *                . ls_renewals = 3
 *
 *                host1 sanlk-reset get_event RESETTING
 *
 * So 4 timestamps (3 timestamp changes as counted in ls_renewals)
 * is the typical number seen by sanlk-reset.
 * The code below uses 4 renewals in case there is some unknown timing
 * skew, io delays, scheduling delays, that affect the count.
 */

static int reset_fail(void)
{
	int cmd_fail = 0;
	int cmd_wait = 0;
	int i;

	for (i = 0; i < MAX_LS; i++) {
		if (!ls_names[i])
			continue;

		if (ls_is_resetting[i]) {
			/*
			 * sanlk-resetd on the host has replied that
			 * it has set up its watchdog to reset it, so
			 * in time it should become DEAD and be counted
			 * as done in reset_done().  The time for the host
			 * to be reported as DEAD is not something we can
			 * compute exactly here, (and it depends on things
			 * like io timeout).
			 *
			 * If the watchdog failed to reset the host (or
			 * use_watchdog was turned off in sanlk-reset),
			 * then we'll continue coming through here
			 * indefinately.  We want to eventually fail
			 * in this case, so put a large upper bound
			 * on the time we'll wait for the host state
			 * to become DEAD.
			 */

			if (monotime() - begin > 300) {
				log_error("host watchdog reset failed in %s:%d",
					  ls_names[i], ls_hostids[i]);
				cmd_fail++;
			} else {
				cmd_wait++;
			}
			continue;
		}

		/*
		 * We have not seen a resetting reply from the host:
		 * 1. we haven't waited long enough yet
		 * 2. the host couldn't perform the reset and won't reply
		 * 3. the host reset/rebooted too quickly before its reply could be written
		 * 4. the host lost storage and didn't get the event
		 * 5. the host lost storage and couldn't write a reply
		 * 6. the host is not running sanlk-resetd
		 * 7. the host left the lockspace
		 * 8. the host had not joined any of the lockspaces where the event was set
		 * 9. sanlk-resetd is not watching events in the ls where the event was set
		 */

		if (ls_is_dead[i]) {
			/* case 3, case 4, case 5 */
			log_error("host is dead with no reply in %s:%d",
				  ls_names[i], ls_hostids[i]);
			cmd_fail++;

		} else if (ls_is_free[i]) {
			/* case 7, case 8 */
			log_error("host is free with no reply in %s:%d",
				  ls_names[i], ls_hostids[i]);
			cmd_fail++;

		} else if (ls_renewals[i] >= 4) {
			/* case 2, case 6, case 9 */
			log_error("host renewals %d with no reply in %s:%d",
				  ls_renewals[i], ls_names[i], ls_hostids[i]);
			cmd_fail++;

		} else {
			/* case 1 */
			cmd_wait++;
		}
	}

	if (cmd_fail && !cmd_wait) {
		log_error("reset failed: no replies in %d ls", cmd_fail);
		return 1;
	}

	return 0;
}

static int reset_done(void)
{
	struct sanlk_host *hs;
	uint64_t host_id;
	uint32_t state;
	int hs_count;
	int is_done = 0;
	int i, rv;

	/*
	 * Get the state of the host in each lockspace.
	 */

	for (i = 0; i < MAX_LS; i++) {
		if (!ls_names[i])
			continue;

		hs_count = 0;
		hs = NULL;
		host_id = (uint64_t)ls_hostids[i];

		rv = sanlock_get_hosts(ls_names[i], host_id, &hs, &hs_count, 0);

		if ((rv < 0) || (hs == NULL) || (hs_count != 1) || (hs->host_id != host_id)) {
			log_error("sanlock_get_hosts error %d ls %s:%d",
				  rv, ls_names[i], ls_hostids[i]);
			continue;
		}

		if (ls_timestamp[i] && (ls_timestamp[i] != hs->timestamp))
			ls_renewals[i]++;

		ls_timestamp[i] = hs->timestamp;
		ls_host_flags[i] = hs->flags;

		log_debug("%04u state %s reply %d timestamp %llu ls %s:%d",
			  (uint32_t)(monotime() - begin),
			  host_flag_str(ls_host_flags[i]),
			  ls_is_resetting[i],
			  (unsigned long long)hs->timestamp,
			  ls_names[i], ls_hostids[i]);

		free(hs);
	}

	/*
	 * The lockspace behavior is different when resource leases
	 * are not used to protect storage, so the conditions to check
	 * depend on the --with-resources option.
	 *
	 * With resource leases, a host is safe/done when either it
	 * is DEAD in any one lockspace (its watchdog has fired).
	 *
	 * Without resource leases, the loss of lockspace storage will
	 * cause the lockspace to cleanly exit immediately.  Because of
	 * this, the DEAD state of the delta lease alone is not helpful.
	 *
	 * However, if we get a RESETTING reply, it means sanlk-resetd
	 * on the destination has prevented the lockspace from exiting
	 * due to lost storage.  This means that the DEAD state of the
	 * host will imply that the host's watchdog fired.
	 *
	 * with resource leases: if the host is DEAD in any lockspace,
	 * reset is done because the watchdog fired.
	 *
	 * without resource leases: if the host replied and is DEAD in
	 * any lockspace, reset is done because the watchdog fired.
	 */

	for (i = 0; i < MAX_LS; i++) {
		if (!ls_names[i])
			continue;

		state = ls_host_flags[i] & SANLK_HOST_MASK;

		if (state == SANLK_HOST_DEAD)
			ls_is_dead[i] = 1;

		if (state == SANLK_HOST_FREE)
			ls_is_free[i] = 1;

		if (resource_mode && ls_is_dead[i])
			is_done = 1;

		if (!resource_mode && ls_is_dead[i] && ls_is_resetting[i])
			is_done = 1;

		if (ls_is_dead[i])
			log_notice("host dead in ls %s:%d", ls_names[i], ls_hostids[i]);

		if (is_done)
			log_notice("reset done in ls %s:%d", ls_names[i], ls_hostids[i]);
	}

	return is_done;
}

static void get_events(int i)
{
	struct sanlk_host_event from_he;
	uint64_t from_host, from_gen;
	int rv;

	while (1) {
		rv = sanlock_get_event(ls_fd[i], 0, &from_he, &from_host, &from_gen);
		if (rv == -EAGAIN)
			break;
		if (rv < 0) {
			log_error("unregister fd %d get_event error %d ls %s",
				  ls_fd[i], rv, ls_names[i]);
			unregister_ls(i);
			break;
		}

		if ((from_host == ls_hostids[i]) &&
		    ((from_he.event & EVENT_RESETTING) || (from_he.event & EVENT_REBOOTING))) {
			log_notice("notice of %s%s(%llx %llx) from host %llu %llu ls %s",
				   (from_he.event & EVENT_RESETTING) ? "resetting " : "",
				   (from_he.event & EVENT_REBOOTING) ? "rebooting " : "",
				   (unsigned long long)from_he.event,
				   (unsigned long long)from_he.data,
				   (unsigned long long)from_host,
				   (unsigned long long)from_gen,
				   ls_names[i]);

			if (from_he.event & EVENT_RESETTING)
				ls_is_resetting[i] = 1;
		} else {
			log_notice("event ignored %llx %llx from host %llu %llu ls %s",
				   (unsigned long long)from_he.event,
				   (unsigned long long)from_he.data,
				   (unsigned long long)from_host,
				   (unsigned long long)from_gen,
				   ls_names[i]);
		}
	}
}

static int update_local_daemon(char *cmd)
{
	char buf[UPDATE_SIZE];
	int rv, i, s;

	s = setup_resetd_socket();
	if (s < 0) {
		fprintf(stderr, "Failed to create socket %d\n", s);
		return s;
	}

	for (i = 0; i < ls_count; i++) {
		memset(buf, 0, sizeof(buf));
		snprintf(buf, UPDATE_SIZE, "%s %s", cmd, ls_names[i]);

		rv = sendto(s, buf, UPDATE_SIZE, 0, (struct sockaddr *)&update_addr, update_addrlen);
		if (rv < 0) {
			printf("Failed to update local sanlk-resetd: %s\n", strerror(errno));
			return rv;
		} else {
			printf("Updated %s %s\n", cmd, ls_names[i]);
		}
	}

	return 0;
}

static void usage(void)
{
	printf("%s [options] reg|end|reset lockspaces\n", prog_name);
	printf("  --help | -h\n");
	printf("        Show this help information.\n");
	printf("  --version | -V\n");
	printf("        Show version.\n");
	printf("\n");
	printf("Update the local sanlk-resetd to watch lockspaces for reset events:\n");
	printf("%s reg lockspace_name ...\n", prog_name);
	printf("\n");
	printf("Update the local sanlk-resetd to not watch lockspaces for reset events:\n");
	printf("%s end lockspace_name ...\n", prog_name);
	printf("\n");
	printf("Update the local sanlk-resetd to clear all lockspaces being watched:\n");
	printf("%s clear all\n", prog_name);
	printf("\n");
	printf("Reset another host through a lockspace it is watching:\n");
	printf("%s reset lockspace_name:host_id ...\n", prog_name);
	printf("  --host-id | -i <num>\n");
	printf("        Host id to reset.\n");
	printf("  --generation | -g <num>\n");
	printf("        Generation of host id (default 0 for current generation).\n");
	printf("  --watchdog | -w 0|1\n");
	printf("        Disable (0) use of wdmd/watchdog for testing.\n");
	printf("  --sysrq-reboot | -b 0|1\n");
	printf("        Enable/Disable (1/0) use of /proc/sysrq-trigger to reboot (default 0).\n");
	printf("  --resource-mode | -R 0|1\n");
	printf("        Resource leases are used (1) or not used (0) to protect storage.\n");
	printf("  The event will be set in each lockspace_name (max %d).\n", MAX_LS);
	printf("  The -i and -g options can only be used with a single lockspace_name arg.\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	char *ls_name, *colon, *cmd;
	struct sanlk_host_event he;
	uint32_t flags = 0;
	int i, fd, rv;
	int done = 0;
	int fail = 0;

	prog_name = argv[0];
	begin = monotime();

	memset(&he, 0, sizeof(he));

	if (argc < 2) {
		usage();
		exit(EXIT_FAILURE);
	}

	static struct option long_options[] = {
		{"help",	   no_argument,       0, 'h' },
		{"version",        no_argument,       0, 'V' },
		{"host-id",        required_argument, 0, 'i' },
		{"generation",     required_argument, 0, 'g' },
		{"watchdog",       required_argument, 0, 'w' },
		{"sysrq-reboot",   required_argument, 0, 'b' },
		{"resource-mode",  required_argument, 0, 'R' },
		{0, 0, 0, 0 }
	};

	while (1) {
		int c;
		int option_index = 0;

		c = getopt_long(argc, argv, "hVi:g:w:b:R:",
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
			printf("%s version: " VERSION "\n", prog_name);
			exit(EXIT_SUCCESS);
		case 'i':
			target_host_id = atoi(optarg);
			break;
		case 'g':
			target_generation = strtoull(optarg, NULL, 0);
			break;
		case 'w':
			use_watchdog = atoi(optarg);
			break;
		case 'b':
			use_sysrq_reboot = atoi(optarg);
			break;
		case 'R':
			resource_mode = atoi(optarg);
			break;
		case '?':
		default:
			usage();
			exit(2);
		}
	}

	ls_count = 0;

	for (i = optind; i < argc; i++) {
		if (i == optind) {
			cmd = argv[i];
		} else if (ls_count == MAX_LS) {
			fprintf(stderr, "ignore lockspace_name %s\n", argv[i]);
		} else {
			ls_names[ls_count] = argv[i];
			ls_count++;
		}
	}

	/*
	 * Update local sanlk-resetd.
	 */

	if (!strcmp(cmd, "reg") || !strcmp(cmd, "end") || !strcmp(cmd, "clear")) {
		return update_local_daemon(cmd);
	}

	/*
	 * Reset another host.
	 */

	if (strcmp(cmd, "reset")) {
		fprintf(stderr, "unknown command\n");
		exit(2);
	}

	if (!ls_count) {
		fprintf(stderr, "lockspace_name is required\n");
		exit(2);
	}

	if ((ls_count > 1) && (target_host_id || target_generation)) {
		fprintf(stderr, "-i and -g options are only allowed with a single lockspace_name\n");
		exit(2);
	}

	for (i = 0; i < ls_count; i++) {
		ls_name = ls_names[i];
		colon = strstr(ls_name, ":");
		if (!colon) {
			ls_hostids[i] = target_host_id;
		} else {
			ls_hostids[i] = atoi(colon+1);
			*colon = '\0';
		}

		if (ls_hostids[i] < 1 || ls_hostids[i] > 2000) {
			fprintf(stderr, "invalid host_id %d", ls_hostids[i]);
			exit(2);
		}
	}

	openlog(prog_name, LOG_CONS | LOG_PID, LOG_DAEMON);

	pollfd = malloc(MAX_LS * sizeof(struct pollfd));
	if (!pollfd)
		return -ENOMEM;

	for (i = 0; i < MAX_LS; i++) {
		ls_fd[i] = -1;
		pollfd[i].fd = -1;
		pollfd[i].events = 0;
		pollfd[i].revents = 0;
	}

	ls_count = 0;

	for (i = 0; i < MAX_LS; i++) {
		if (!ls_names[i])
			continue;

		fd = sanlock_reg_event(ls_names[i], NULL, 0);
		if (fd < 0) {
			log_error("reg_event error %d ls %s", fd, ls_names[i]);
			ls_names[i] = NULL;
		} else {
			ls_fd[i] = fd;
			pollfd[i].fd = ls_fd[i];
			pollfd[i].events = POLLIN;
			ls_count++;
		}
	}

	if (!ls_count) {
		log_error("No lockspaces could be registered.");
		exit(EXIT_FAILURE);
	}

	if (use_watchdog)
		he.event |= EVENT_RESET;
	if (use_sysrq_reboot)
		he.event |= EVENT_REBOOT;

	for (i = 0; i < MAX_LS; i++) {
		if (!ls_names[i])
			continue;
		if (ls_fd[i] == -1)
			continue;

		/* a host can have different host_ids in different lockspaces */
		he.host_id = ls_hostids[i];
		he.generation = target_generation;

		flags = target_generation ? SANLK_SETEV_CUR_GENERATION : 0;

		rv = sanlock_set_event(ls_names[i], &he, flags);
		if (rv < 0) {
			log_error("set_event error %d ls %s", rv, ls_names[i]);
			unregister_ls(i);
		} else {
			log_notice("asked host %llu %llu to %s%s(%llx %llx) through ls %s",
				   (unsigned long long)he.host_id,
				   (unsigned long long)he.generation,
				   (he.event & EVENT_RESET) ? "reset " : "",
				   (he.event & EVENT_REBOOT) ? "reboot " : "",
				   (unsigned long long)he.event,
				   (unsigned long long)he.data,
				   ls_names[i]);
		}
	}

	if (!ls_count) {
		log_error("Event could not be set in any lockspace.");
		exit(EXIT_FAILURE);
	}

	while (1) {
		rv = poll(pollfd, MAX_LS, 2000);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0)
			break;

		done = reset_done();
		if (done)
			break;

		fail = reset_fail();
		if (fail)
			break;

		for (i = 0; i < MAX_LS; i++) {
			if (pollfd[i].fd < 0)
				continue;

			if (pollfd[i].revents & POLLIN)
				get_events(i);

			if (pollfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				log_debug("unregister fd %d poll %x ls %s",
					  ls_fd[i], pollfd[i].revents, ls_names[i]);
				unregister_ls(i);
			}
		}
	}

	for (i = 0; i < MAX_LS; i++) {
		if (!ls_names[i])
			continue;
		if (ls_fd[i] == -1)
			continue;
		unregister_ls(i);
	}

	if (done) {
		log_notice("reset done in %u seconds", (uint32_t)(monotime() - begin));
		exit(EXIT_SUCCESS);
	} else {
		log_error("reset failed in %u seconds", (uint32_t)(monotime() - begin));
		exit(EXIT_FAILURE);
	}
}
