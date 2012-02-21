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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "sanlock.h"
#include "sanlock_sock.h"

#include "client_cmd.h"

#ifndef GNUC_UNUSED
#define GNUC_UNUSED __attribute__((__unused__))
#endif

extern int send_command(int cmd, uint32_t data);

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

static void status_daemon(struct sanlk_state *st, char *str, int debug)
{
	printf("daemon %.48s\n", st->name);

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

static void status_client(struct sanlk_state *st, char *str, int debug)
{
	printf("p %d ", st->data32);
	printf("%.48s\n", st->name);

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

static void status_lockspace(struct sanlk_state *st, char *str, char *bin, int debug)
{
	struct sanlk_lockspace *ls = (struct sanlk_lockspace *)bin;

	printf("s %.48s:%llu:%s:%llu\n",
	       ls->name,
	       (unsigned long long)ls->host_id,
	       ls->host_id_disk.path,
	       (unsigned long long)ls->host_id_disk.offset);

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

static void status_resource(struct sanlk_state *st, char *str, char *bin, int debug)
{
	struct sanlk_resource *res = (struct sanlk_resource *)bin;
	struct sanlk_disk *disk;
	int i;

	printf("r %.48s:%.48s", res->lockspace_name, res->name);

	for (i = 0; i < res->num_disks; i++) {
		disk = (struct sanlk_disk *)(bin + sizeof(struct sanlk_resource) + i * sizeof(struct sanlk_disk));

		printf(":%s:%llu",
		       disk->path, (unsigned long long)disk->offset);
	}

	if (res->flags & SANLK_RES_SHARED)
		printf(":SH p %u\n", st->data32);
	else
		printf(":%llu p %u\n", (unsigned long long)st->data64, st->data32);

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

static void status_host(struct sanlk_state *st, char *str, int debug)
{
	printf("%u timestamp %llu\n", st->data32,
	       (unsigned long long)st->data64);

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

static void print_st(struct sanlk_state *st, char *str, char *bin, int debug)
{
	switch (st->type) {
	case SANLK_STATE_DAEMON:
		status_daemon(st, str, debug);
		break;
	case SANLK_STATE_CLIENT:
		status_client(st, str, debug);
		break;
	case SANLK_STATE_LOCKSPACE:
		status_lockspace(st, str, bin, debug);
		break;
	case SANLK_STATE_RESOURCE:
		status_resource(st, str, bin, debug);
		break;
	}
}

#define MAX_SORT_ENTRIES 1024
static char *sort_bufs[MAX_SORT_ENTRIES];
static int sort_count;
static int sort_done;

static void print_type(int type, int debug)
{
	struct sanlk_state *st;
	char *buf, *str, *bin;
	int i;

	for (i = 0; i < sort_count; i++) {
		buf = sort_bufs[i];
		if (!buf)
			continue;
		st = (struct sanlk_state *)buf;
		str = buf + sizeof(struct sanlk_state);
		bin = buf + sizeof(struct sanlk_state) + SANLK_STATE_MAXSTR;

		if (!type || st->type == type) {
			print_st(st, str, bin, debug);
			free(buf);
			sort_bufs[i] = NULL;
			sort_done++;
		}
	}
}

static void print_p(int p, int debug)
{
	struct sanlk_state *st;
	char *buf, *str, *bin;
	int i;

	for (i = 0; i < sort_count; i++) {
		buf = sort_bufs[i];
		if (!buf)
			continue;
		st = (struct sanlk_state *)buf;
		str = buf + sizeof(struct sanlk_state);
		bin = buf + sizeof(struct sanlk_state) + SANLK_STATE_MAXSTR;

		if (st->type != SANLK_STATE_CLIENT)
			continue;

		if (st->data32 == p) {
			print_st(st, str, bin, debug);
			free(buf);
			sort_bufs[i] = NULL;
			sort_done++;
		}
	}
}

static int find_type(int type, int *sort_index)
{
	struct sanlk_state *st;
	char *buf;
	int i;

	for (i = 0; i < sort_count; i++) {
		buf = sort_bufs[i];
		if (!buf)
			continue;
		st = (struct sanlk_state *)buf;

		if (st->type == type) {
			*sort_index = i;
			return 0;
		}
	}
	return -1;
}

static void print_r(int p, char *s, int debug)
{
	struct sanlk_resource *res;
	struct sanlk_state *st;
	char *buf, *str, *bin;
	int i;

	for (i = 0; i < sort_count; i++) {
		buf = sort_bufs[i];
		if (!buf)
			continue;
		st = (struct sanlk_state *)buf;
		str = buf + sizeof(struct sanlk_state);
		bin = buf + sizeof(struct sanlk_state) + SANLK_STATE_MAXSTR;

		if (st->type != SANLK_STATE_RESOURCE)
			continue;

		res = (struct sanlk_resource *)bin;

		if ((p && st->data32 == p) ||
		    (s && !strncmp(s, res->lockspace_name, SANLK_NAME_LEN))) {
			print_st(st, str, bin, debug);
			free(buf);
			sort_bufs[i] = NULL;
			sort_done++;
		}
	}
}

static void print_r_by_p(int debug)
{
	struct sanlk_state *st;
	char *buf, *str, *bin;
	int rv, i;

	while (1) {
		rv = find_type(SANLK_STATE_CLIENT, &i);
		if (rv < 0)
			return;

		buf = sort_bufs[i];
		st = (struct sanlk_state *)buf;
		str = buf + sizeof(struct sanlk_state);
		bin = buf + sizeof(struct sanlk_state) + SANLK_STATE_MAXSTR;

		print_st(st, str, bin, debug);

		print_r(st->data32, NULL, debug);

		free(buf);
		sort_bufs[i] = NULL;
		sort_done++;
	}
}

static void print_r_by_s(int debug)
{
	struct sanlk_state *st;
	char *buf, *str, *bin;
	int rv, i;

	while (1) {
		rv = find_type(SANLK_STATE_LOCKSPACE, &i);
		if (rv < 0)
			return;

		buf = sort_bufs[i];
		st = (struct sanlk_state *)buf;
		str = buf + sizeof(struct sanlk_state);
		bin = buf + sizeof(struct sanlk_state) + SANLK_STATE_MAXSTR;

		print_st(st, str, bin, debug);

		print_r(0, st->name, debug);

		free(buf);
		sort_bufs[i] = NULL;
		sort_done++;
	}
}

static void recv_bin(int fd, struct sanlk_state *st, char *bin)
{
	struct sanlk_resource *res;

	if (st->type == SANLK_STATE_LOCKSPACE) {
		recv(fd, bin, sizeof(struct sanlk_lockspace), MSG_WAITALL);

	} else if (st->type == SANLK_STATE_RESOURCE) {
		recv(fd, bin, sizeof(struct sanlk_resource), MSG_WAITALL);

		res = (struct sanlk_resource *)bin;

		recv(fd, bin+sizeof(struct sanlk_resource),
		     res->num_disks * sizeof(struct sanlk_disk),
		     MSG_WAITALL);
	}
}

int sanlock_status(int debug, char sort_arg)
{
	struct sm_header h;
	struct sanlk_state state;
	char maxstr[SANLK_STATE_MAXSTR];
	char maxbin[SANLK_STATE_MAXSTR];
	struct sanlk_state *st;
	char *buf, *str, *bin;
	int fd, rv, len;
	int sort_p = 0, sort_s = 0;

	if (sort_arg == 'p')
		sort_p = 1;
	else if (sort_arg == 's')
		sort_s = 1;

	fd = send_command(SM_CMD_STATUS, 0);
	if (fd < 0)
		return fd;

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}
	if (rv != sizeof(h)) {
		rv = -1;
		goto out;
	}

	st = &state;
	str = maxstr;
	bin = maxbin;

	while (1) {
		if (sort_p || sort_s) {
			len = sizeof(struct sanlk_state) + SANLK_STATE_MAXSTR*4;
			buf = malloc(len);
			if (!buf)
				return -ENOMEM;
			memset(buf, 0, len);
			st = (struct sanlk_state *)buf;
			str = buf + sizeof(struct sanlk_state);
			bin = buf + sizeof(struct sanlk_state) + SANLK_STATE_MAXSTR;
		} else {
			memset(&state, 0, sizeof(state));
			memset(maxstr, 0, sizeof(maxstr));
			memset(maxbin, 0, sizeof(maxbin));
		}

		rv = recv(fd, st, sizeof(struct sanlk_state), MSG_WAITALL);
		if (!rv)
			break;
		if (rv != sizeof(struct sanlk_state))
			break;

		if (st->str_len) {
			rv = recv(fd, str, st->str_len, MSG_WAITALL);
			if (rv != st->str_len)
				break;
		}

		recv_bin(fd, st, bin);

		if (sort_p || sort_s) {
			if (sort_count == MAX_SORT_ENTRIES) {
				printf("cannot sort over %d\n", MAX_SORT_ENTRIES);
				goto out;
			}
			sort_bufs[sort_count++] = buf;
			continue;
		}

		/* no sorting, print as received */

		print_st(st, str, bin, debug);
	}

	if (sort_p) {
		print_type(SANLK_STATE_DAEMON, debug);
		print_p(-1, debug);
		print_type(SANLK_STATE_LOCKSPACE, debug);
		print_r_by_p(debug);
		if (sort_done < sort_count) {
			printf("-\n");
			print_type(0, debug);
		}
	} else if (sort_s) {
		print_type(SANLK_STATE_DAEMON, debug);
		print_p(-1, debug);
		print_type(SANLK_STATE_CLIENT, debug);
		print_r_by_s(debug);
		if (sort_done < sort_count) {
			printf("-\n");
			print_type(0, debug);
		}
	}

	rv = 0;
 out:
	close(fd);
	return rv;
}

int sanlock_host_status(int debug, char *lockspace_name)
{
	struct sm_header h;
	struct sanlk_state st;
	struct sanlk_lockspace lockspace;
	char str[SANLK_STATE_MAXSTR];
	int fd, rv;

	if (!lockspace_name || !lockspace_name[0])
		return -1;

	fd = send_command(SM_CMD_HOST_STATUS, 0);
	if (fd < 0)
		return fd;

	memset(&lockspace, 0, sizeof(lockspace));
	snprintf(lockspace.name, SANLK_NAME_LEN, "%s", lockspace_name);

	rv = send(fd, &lockspace, sizeof(lockspace), 0);
	if (rv < 0)
		goto out;

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}
	if (rv != sizeof(h)) {
		rv = -1;
		goto out;
	}

	while (1) {
		rv = recv(fd, &st, sizeof(st), MSG_WAITALL);
		if (!rv)
			break;
		if (rv != sizeof(st))
			break;

		if (st.str_len) {
			rv = recv(fd, str, st.str_len, MSG_WAITALL);
			if (rv != st.str_len)
				break;
		}

		switch (st.type) {
		case SANLK_STATE_HOST:
			status_host(&st, str, debug);
			break;
		}
	}

	rv = h.data;
 out:
	close(fd);
	return rv;
}

int sanlock_log_dump(int max_size)
{
	struct sm_header h;
	char *buf;
	int fd, rv;

	buf = malloc(max_size);
	if (!buf)
		return -ENOMEM;
	memset(buf, 0, max_size);

	fd = send_command(SM_CMD_LOG_DUMP, 0);
	if (fd < 0) {
		free(buf);
		return fd;
	}

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}
	if (rv != sizeof(h)) {
		rv = -1;
		goto out;
	}

	if (h.data <= 0 || h.data > max_size)
		goto out;

	rv = recv(fd, buf, h.data, MSG_WAITALL);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}
	if (!rv) {
		rv = -1;
		goto out;
	}

	printf("%s", buf);
	printf("\n");

	if (rv != h.data)
		printf("partial dump %d of %d\n", rv, h.data);
 out:
	close(fd);
	free(buf);
	return rv;
}

int sanlock_shutdown(uint32_t force)
{
	int fd;

	fd = send_command(SM_CMD_SHUTDOWN, force);
	if (fd < 0)
		return fd;

	close(fd);
	return 0;
}

