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

static const char *add_rem_str(struct sanlk_state *st, char *str)
{
	if (!st->str_len)
		return NULL;

	if (strstr(str, "list=add"))
		return "ADD";
	if (strstr(str, "list=rem"))
		return "REM";
	if (strstr(str, "list=orphan"))
		return "ORPHAN";

	return NULL;
}

/* TODO: when path strings are exported, through status or inquire, we
   should export into a malloced buffer the size of the standard chars
   plus extra esc chars. */

static void status_lockspace(struct sanlk_state *st, char *str, char *bin, int debug)
{
	struct sanlk_lockspace *ls = (struct sanlk_lockspace *)bin;
	char path[SANLK_PATH_LEN + 1];
	const char *add_rem;

	memset(path, 0, sizeof(path));
	sanlock_path_export(path, ls->host_id_disk.path, sizeof(path));

	printf("s %.48s:%llu:%s:%llu",
	       ls->name,
	       (unsigned long long)ls->host_id,
	       path,
	       (unsigned long long)ls->host_id_disk.offset);

	add_rem = add_rem_str(st, str);
	if (add_rem)
		printf(" %s\n", add_rem);
	else
		printf("\n");

	if (st->str_len && debug)
		print_debug(str, st->str_len);
}

static void status_resource(struct sanlk_state *st, char *str, char *bin, int debug)
{
	struct sanlk_resource *res = (struct sanlk_resource *)bin;
	struct sanlk_disk *disk;
	char path[SANLK_PATH_LEN + 1];
	const char *add_rem;
	int i;

	printf("r %.48s:%.48s", res->lockspace_name, res->name);

	for (i = 0; i < res->num_disks; i++) {
		disk = (struct sanlk_disk *)(bin + sizeof(struct sanlk_resource) + i * sizeof(struct sanlk_disk));

		memset(path, 0, sizeof(path));
		sanlock_path_export(path, disk->path, sizeof(path));

		printf(":%s:%llu", path, (unsigned long long)disk->offset);
	}

	if (res->flags & SANLK_RES_SHARED)
		printf(":SH p %u", st->data32);
	else
		printf(":%llu p %u", (unsigned long long)st->data64, st->data32);

	add_rem = add_rem_str(st, str);
	if (add_rem)
		printf(" %s\n", add_rem);
	else
		printf("\n");

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
	char *buf = NULL, *str, *bin;
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
		if (sort_s || sort_p) {
			len = sizeof(struct sanlk_state) + SANLK_STATE_MAXSTR*4;
			buf = calloc(len, sizeof(char));
			if (!buf)
				return -ENOMEM;

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

		if (sort_s || sort_p) {
			if ((sort_count == MAX_SORT_ENTRIES) || (!buf)) {
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

static int lockspace_host_status(int debug, char *lockspace_name)
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

int sanlock_host_status(int debug, char *lockspace_name)
{
	struct sm_header h;
	struct sanlk_state state;
	char maxstr[SANLK_STATE_MAXSTR];
	char maxbin[SANLK_STATE_MAXSTR];
	struct sanlk_state *st;
	char *str, *bin;
	struct sanlk_lockspace *ls;
	int fd, rv, i;

	if (lockspace_name && lockspace_name[0])
		return lockspace_host_status(debug, lockspace_name);

	fd = send_command(SM_CMD_STATUS, SANLK_STATE_LOCKSPACE);
	if (fd < 0)
		return fd;

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv < 0) {
		rv = -errno;
		close(fd);
		return rv;
	}
	if (rv != sizeof(h)) {
		close(fd);
		return -1;
	}

	st = &state;
	str = maxstr;
	bin = maxbin;

	while (1) {
		memset(&state, 0, sizeof(state));
		memset(maxstr, 0, sizeof(maxstr));
		memset(maxbin, 0, sizeof(maxbin));

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

		if (st->type != SANLK_STATE_LOCKSPACE)
			continue;

		ls = (struct sanlk_lockspace *)bin;

		sort_bufs[sort_count++] = strdup(ls->name);
	}

	close(fd);

	for (i = 0; i < sort_count; i++) {
		printf("lockspace %s\n", sort_bufs[i]);
		lockspace_host_status(debug, sort_bufs[i]);
		free(sort_bufs[i]);
	}

	return 0;
}

int sanlock_renewal(char *lockspace_name)
{
	struct sm_header h;
	struct sanlk_state st;
	struct sanlk_lockspace lockspace;
	char str[SANLK_STATE_MAXSTR];
	int fd, rv;

	if (!lockspace_name || !lockspace_name[0])
		return -1;

	fd = send_command(SM_CMD_RENEWAL, 0);
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

		printf("%s\n", str);
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

int sanlock_shutdown(uint32_t force, int wait_result)
{
	struct sm_header h;
	int cmd;
	int fd;
	int rv = 0;

	if (wait_result)
		cmd = SM_CMD_SHUTDOWN_WAIT;
	else
		cmd = SM_CMD_SHUTDOWN;

	fd = send_command(cmd, force);
	if (fd < 0)
		return fd;

	if (cmd != SM_CMD_SHUTDOWN_WAIT)
		goto out;

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

	rv = h.data;
 out:
	close(fd);
	return rv;
}

