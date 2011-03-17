/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "sanlock_internal.h"
#include "log.h"
#include "client_msg.h"
#include "sanlock_admin.h"

int sanlock_shutdown(void)
{
	struct sm_header h;
	int fd;

	fd = send_command(SM_CMD_SHUTDOWN, 0);
	if (fd < 0)
		return fd;

	close(fd);
	return 0;
}

int sanlock_log_dump(void)
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
		rv = -1;
		goto out;
	}

	len = h.length - sizeof(h);

	buf = malloc(len);
	if (!buf) {
		rv = -ENOMEM;
		goto out;
	}
	memset(buf, 0, len);

	rv = recv(fd, buf, len, MSG_WAITALL);
	if (rv != len) {
		rv = -1;
		goto out;
	}

	rv = 0;
	printf("%s\n", buf);
 out:
	close(fd);
	return rv;
}

static void print_debug(char *str, int len)
{
	char *p;
	int i;

	p = &str[0];
	for (i = 0; i < len-1; i++) {
		if (str[i] == ' ') {
			str[i] = '\0';
			printf("    %s\n", p);
			p = &str[i+1];
		}
	}

	if (p)
		printf("    %s\n", p);
}

static void status_daemon(int fd GNUC_UNUSED, struct sanlk_state *st, char *str, int debug)
{
	printf("daemon\n");

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

static void status_lockspace(int fd, struct sanlk_state *st, char *str, int debug)
{
	struct sanlk_lockspace lockspace;
	int rv;

	rv = recv(fd, &lockspace, sizeof(lockspace), MSG_WAITALL);

	printf("lockspace %.48s host_id %llu %s:%llu\n",
	       lockspace.name, (unsigned long long)lockspace.host_id,
	       lockspace.host_id_disk.path,
	       (unsigned long long)lockspace.host_id_disk.offset);

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

static void status_client(int fd GNUC_UNUSED, struct sanlk_state *st, char *str, int debug)
{
	printf("pid %u ", st->data32);
	printf("%.48s\n", st->name);

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

static void status_resource(int fd, struct sanlk_state *st, char *str, int debug)
{
	struct sanlk_resource resource;
	struct sanlk_disk disk;
	int i, rv;

	rv = recv(fd, &resource, sizeof(resource), MSG_WAITALL);

	printf("    %.48s %.48s\n", resource.lockspace_name, resource.name);

	for (i = 0; i < resource.num_disks; i++) {
		rv = recv(fd, &disk, sizeof(disk), MSG_WAITALL);

		printf("    %s:%llu\n",
		       disk.path, (unsigned long long)disk.offset);
	}

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

int sanlock_status(int debug)
{
	struct sm_header h;
	struct sanlk_state st;
	char str[SANLK_STATE_MAXSTR];
	int fd, rv;

	fd = send_command(SM_CMD_STATUS, 0);
	if (fd < 0)
		return fd;

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h))
		return -1;


	while (1) {
		rv = recv(fd, &st, sizeof(st), MSG_WAITALL);
		if (!rv)
			break;
		if (rv != sizeof(st))
			return -1;

		if (st.str_len) {
			rv = recv(fd, str, st.str_len, MSG_WAITALL);
			if (rv != st.str_len)
				return -1;
		}

		switch (st.type) {
		case SANLK_STATE_DAEMON:
			status_daemon(fd, &st, str, debug);
			break;
		case SANLK_STATE_LOCKSPACE:
			status_lockspace(fd, &st, str, debug);
			break;
		case SANLK_STATE_CLIENT:
			status_client(fd, &st, str, debug);
			break;
		case SANLK_STATE_RESOURCE:
			status_resource(fd, &st, str, debug);
			break;
		}
	}

	return 0;
}

static int cmd_lockspace(int cmd, struct sanlk_lockspace *ls, uint32_t flags)
{
	struct sm_header h;
	int rv, fd;

	rv = connect_socket(&fd);
	if (rv < 0)
		return rv;

	rv = send_header(fd, cmd, flags, sizeof(struct sanlk_lockspace), 0, 0);
	if (rv < 0)
		return rv;

	rv = send(fd, (void *)ls, sizeof(struct sanlk_lockspace), 0);
	if (rv < 0) {
		rv = -1;
		goto out;
	}

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -1;
		goto out;
	}

	if (h.data) {
		rv = (int)h.data;
		goto out;
	}

	rv = 0;
 out:
	close(fd);
	return rv;
}

int sanlock_add_lockspace(struct sanlk_lockspace *ls, uint32_t flags)
{
	return cmd_lockspace(SM_CMD_ADD_LOCKSPACE, ls, flags);
}

int sanlock_rem_lockspace(struct sanlk_lockspace *ls, uint32_t flags)
{
	return cmd_lockspace(SM_CMD_REM_LOCKSPACE, ls, flags);
}

