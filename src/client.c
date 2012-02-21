/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include "sanlock_resource.h"
#include "sanlock_admin.h"
#include "sanlock_sock.h"

#ifndef GNUC_UNUSED
#define GNUC_UNUSED __attribute__((__unused__))
#endif

static int connect_socket(int *sock_fd)
{
	int rv, s;
	struct sockaddr_un addr;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0)
		return -errno;

	rv = sanlock_socket_address(&addr);
	if (rv < 0)
		return rv;

	rv = connect(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (rv < 0) {
		rv = -errno;
		close(s);
		return rv;
	}
	*sock_fd = s;
	return 0;
}

static int send_header(int sock, int cmd, uint32_t cmd_flags, int datalen,
		       uint32_t data, uint32_t data2)
{
	struct sm_header header;
	int rv;

	memset(&header, 0, sizeof(struct sm_header));
	header.magic = SM_MAGIC;
	header.cmd = cmd;
	header.cmd_flags = cmd_flags;
	header.length = sizeof(header) + datalen;
	header.data = data;
	header.data2 = data2;

	rv = send(sock, (void *) &header, sizeof(struct sm_header), 0);
	if (rv < 0)
		return -errno;

	return 0;
}

int send_command(int cmd, uint32_t data);

int send_command(int cmd, uint32_t data)
{
	int rv, sock;

	rv = connect_socket(&sock);
	if (rv < 0)
		return rv;

	rv = send_header(sock, cmd, 0, 0, data, 0);
	if (rv < 0) {
		close(sock);
		return rv;
	}

	return sock;
}

static int recv_result(int fd)
{
	struct sm_header h;
	int rv;

	memset(&h, 0, sizeof(struct sm_header));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv < 0)
		return -errno;
	if (rv != sizeof(h))
		return -1;

	return (int)h.data;
}

static int cmd_lockspace(int cmd, struct sanlk_lockspace *ls, uint32_t flags)
{
	int rv, fd;

	rv = connect_socket(&fd);
	if (rv < 0)
		return rv;

	rv = send_header(fd, cmd, flags, sizeof(struct sanlk_lockspace), 0, 0);
	if (rv < 0)
		goto out;

	rv = send(fd, (void *)ls, sizeof(struct sanlk_lockspace), 0);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}

	rv = recv_result(fd);
 out:
	close(fd);
	return rv;
}

int sanlock_add_lockspace(struct sanlk_lockspace *ls, uint32_t flags)
{
	return cmd_lockspace(SM_CMD_ADD_LOCKSPACE, ls, flags);
}

int sanlock_inq_lockspace(struct sanlk_lockspace *ls, uint32_t flags)
{
	return cmd_lockspace(SM_CMD_INQ_LOCKSPACE, ls, flags);
}

int sanlock_rem_lockspace(struct sanlk_lockspace *ls, uint32_t flags)
{
	return cmd_lockspace(SM_CMD_REM_LOCKSPACE, ls, flags);
}

int sanlock_align(struct sanlk_disk *disk)
{
	int rv, fd;

	rv = connect_socket(&fd);
	if (rv < 0)
		return rv;

	rv = send_header(fd, SM_CMD_ALIGN, 0, sizeof(struct sanlk_disk), 0, 0);
	if (rv < 0)
		goto out;

	rv = send(fd, (void *)disk, sizeof(struct sanlk_disk), 0);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}

	rv = recv_result(fd);
 out:
	close(fd);
	return rv;
}

int sanlock_init(struct sanlk_lockspace *ls,
		 struct sanlk_resource *res,
		 int max_hosts, int num_hosts)
{
	int rv, fd, cmd, datalen;

	if (!ls && !res)
		return -EINVAL;

	rv = connect_socket(&fd);
	if (rv < 0)
		return rv;

	if (ls && ls->host_id_disk.path[0]) {
		cmd = SM_CMD_INIT_LOCKSPACE;
		datalen = sizeof(struct sanlk_lockspace);
	} else {
		cmd = SM_CMD_INIT_RESOURCE;
		datalen = sizeof(struct sanlk_resource) +
			  sizeof(struct sanlk_disk) * res->num_disks;
	}

	rv = send_header(fd, cmd, 0, datalen, max_hosts, num_hosts);
	if (rv < 0)
		goto out;

	if (ls) {
		rv = send(fd, ls, sizeof(struct sanlk_lockspace), 0);
		if (rv < 0) {
			rv = -errno;
			goto out;
		}
	} else {
		rv = send(fd, res, sizeof(struct sanlk_resource), 0);
		if (rv < 0) {
			rv = -errno;
			goto out;
		}

		rv = send(fd, res->disks, sizeof(struct sanlk_disk) * res->num_disks, 0);
		if (rv < 0) {
			rv = -errno;
			goto out;
		}
	}

	rv = recv_result(fd);
 out:
	close(fd);
	return rv;
}

/* src has colons unescaped, dst should have them escaped with backslash */

static void copy_path_out(char *dst, char *src)
{
	int i, j = 0;

	for (i = 0; i < strlen(src); i++) {
		if (src[i] == ':')
			dst[j++] = '\\';
		dst[j++] = src[i];
	}
}

/* src has colons escaped with backslash, dst should have backslash removed */ 

static void copy_path_in(char *dst, char *src)
{
	int i, j = 0;

	for (i = 0; i < strlen(src); i++) {
		if (src[i] == '\\')
			continue;
		dst[j++] = src[i];
	}
}

int sanlock_register(void)
{
	int sock, rv;

	rv = connect_socket(&sock);
	if (rv < 0)
		return rv;

	rv = send_header(sock, SM_CMD_REGISTER, 0, 0, 0, 0);
	if (rv < 0) {
		close(sock);
		return rv;
	}

	return sock;
}

int sanlock_restrict(int sock, uint32_t flags)
{
	int rv;

	rv = send_header(sock, SM_CMD_RESTRICT, flags, 0, 0, -1);
	if (rv < 0)
		return rv;

	rv = recv_result(sock);
	return rv;
}

int sanlock_acquire(int sock, int pid, uint32_t flags, int res_count,
		    struct sanlk_resource *res_args[],
		    struct sanlk_options *opt_in)
{
	struct sanlk_resource *res;
	struct sanlk_options opt;
	int rv, i, fd, data2;
	int datalen = 0;

	if (res_count > SANLK_MAX_RESOURCES)
		return -EINVAL;

	for (i = 0; i < res_count; i++) {
		res = res_args[i];
		datalen += sizeof(struct sanlk_resource);

		if (res->num_disks > SANLK_MAX_DISKS)
			return -EINVAL;

		datalen += (res->num_disks * sizeof(struct sanlk_disk));
	}

	datalen += sizeof(struct sanlk_options);
	if (opt_in) {
		memcpy(&opt, opt_in, sizeof(struct sanlk_options));
		datalen += opt_in->len;
	} else {
		memset(&opt, 0, sizeof(opt));
	}

	if (sock == -1) {
		/* connect to daemon and ask it to acquire a lease for
		   another registered pid */

		data2 = pid;

		rv = connect_socket(&fd);
		if (rv < 0)
			return rv;
	} else {
		/* use our own existing registered connection and ask daemon
		   to acquire a lease for self */

		data2 = -1;
		fd = sock;
	}

	rv = send_header(fd, SM_CMD_ACQUIRE, flags, datalen, res_count, data2);
	if (rv < 0)
		return rv;

	for (i = 0; i < res_count; i++) {
		res = res_args[i];
		rv = send(fd, res, sizeof(struct sanlk_resource), 0);
		if (rv < 0) {
			rv = -1;
			goto out;
		}

		rv = send(fd, res->disks, sizeof(struct sanlk_disk) * res->num_disks, 0);
		if (rv < 0) {
			rv = -1;
			goto out;
		}
	}

	rv = send(fd, &opt, sizeof(struct sanlk_options), 0);
	if (rv < 0) {
		rv = -1;
		goto out;
	}

	if (opt.len) {
		rv = send(fd, opt_in->str, opt.len, 0);
		if (rv < 0) {
			rv = -1;
			goto out;
		}
	}

	rv = recv_result(fd);
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

int sanlock_inquire(int sock, int pid, uint32_t flags, int *res_count,
		    char **res_state)
{
	struct sm_header h;
	char *reply_data = NULL;
	int rv, fd, data2, len;

	*res_count = 0;

	if (res_state)
		*res_state = NULL;

	if (sock == -1) {
		/* connect to daemon and ask it to acquire a lease for
		   another registered pid */

		data2 = pid;

		rv = connect_socket(&fd);
		if (rv < 0)
			return rv;
	} else {
		/* use our own existing registered connection and ask daemon
		   to acquire a lease for self */

		data2 = -1;
		fd = sock;
	}

	rv = send_header(fd, SM_CMD_INQUIRE, flags, 0, 0, data2);
	if (rv < 0)
		return rv;

	/* get result */

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -1;
		goto out;
	}

	len = h.length - sizeof(h);
	if (!len) {
		rv = (int)h.data;
		goto out;
	}

	reply_data = malloc(len);
	if (!reply_data) {
		rv = -ENOMEM;
		goto out;
	}

	rv = recv(fd, reply_data, len, MSG_WAITALL);
	if (rv != len) {
		free(reply_data);
		rv = -1;
		goto out;
	}

	if (res_state)
		*res_state = reply_data;
	else
		free(reply_data);

	*res_count = (int)h.data2;
	rv = (int)h.data;
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

/* tell daemon to release lease(s) for given pid.
   I don't think the pid itself will usually tell sm to release leases,
   but it will be requested by a manager overseeing the pid */

int sanlock_release(int sock, int pid, uint32_t flags, int res_count,
		    struct sanlk_resource *res_args[])
{
	int fd, rv, i, data2, datalen;

	if (sock == -1) {
		/* connect to daemon and ask it to acquire a lease for
		   another registered pid */

		data2 = pid;

		rv = connect_socket(&fd);
		if (rv < 0)
			return rv;
	} else {
		/* use our own existing registered connection and ask daemon
		   to acquire a lease for self */

		data2 = -1;
		fd = sock;
	}

	datalen = res_count * sizeof(struct sanlk_resource);

	rv = send_header(fd, SM_CMD_RELEASE, flags, datalen, res_count, data2);
	if (rv < 0)
		goto out;

	for (i = 0; i < res_count; i++) {
		rv = send(fd, res_args[i], sizeof(struct sanlk_resource), 0);
		if (rv < 0) {
			rv = -1;
			goto out;
		}
	}

	rv = recv_result(fd);
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

int sanlock_request(uint32_t flags, uint32_t force_mode,
		    struct sanlk_resource *res)
{
	int fd, rv, datalen;

	datalen = sizeof(struct sanlk_resource) +
		  sizeof(struct sanlk_disk) * res->num_disks;

	rv = connect_socket(&fd);
	if (rv < 0)
		return rv;

	rv = send_header(fd, SM_CMD_REQUEST, flags, datalen, force_mode, 0);
	if (rv < 0)
		goto out;

	rv = send(fd, res, sizeof(struct sanlk_resource), 0);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}

	rv = send(fd, res->disks, sizeof(struct sanlk_disk) * res->num_disks, 0);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}

	rv = recv_result(fd);
 out:
	close(fd);
	return rv;
}

int sanlock_examine(uint32_t flags, struct sanlk_lockspace *ls,
		    struct sanlk_resource *res)
{
	char *data;
	int rv, fd, cmd, datalen;

	if (!ls && !res)
		return -EINVAL;

	rv = connect_socket(&fd);
	if (rv < 0)
		return rv;

	if (ls && ls->host_id_disk.path[0]) {
		cmd = SM_CMD_EXAMINE_LOCKSPACE;
		datalen = sizeof(struct sanlk_lockspace);
		data = (char *)ls;
	} else {
		cmd = SM_CMD_EXAMINE_RESOURCE;
		datalen = sizeof(struct sanlk_resource);
		data = (char *)res;
	}

	rv = send_header(fd, cmd, flags, datalen, 0, 0);
	if (rv < 0)
		goto out;

	rv = send(fd, data, datalen, 0);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}

	rv = recv_result(fd);
 out:
	close(fd);
	return rv;
}

/*
 * convert from struct sanlk_resource to string with format:
 * <lockspace_name>:<resource_name>:<path>:<offset>[:<path>:<offset>...]:<lver>
 */

int sanlock_res_to_str(struct sanlk_resource *res, char **str_ret)
{
	char path[SANLK_PATH_LEN + 1];
	char *str;
	int ret, len, pos, d;

	str = malloc(SANLK_MAX_RES_STR + 1);
	if (!str)
		return -ENOMEM;
	memset(str, 0, SANLK_MAX_RES_STR + 1);

	len = SANLK_MAX_RES_STR;
	pos = 0;

	ret = snprintf(str + pos, len - pos, "%s:%s",
		       res->lockspace_name, res->name);

	if (ret >= len - pos)
		goto fail;
	pos += ret;

	for (d = 0; d < res->num_disks; d++) {
		memset(path, 0, sizeof(path));
		copy_path_out(path, res->disks[d].path);

		ret = snprintf(str + pos, len - pos, ":%s:%llu", path,
			       (unsigned long long)res->disks[d].offset);

		if (ret >= len - pos)
			goto fail;
		pos += ret;
	}

	if (res->flags & SANLK_RES_SHARED)
		ret = snprintf(str + pos, len - pos, ":SH");
	else
		ret = snprintf(str + pos, len - pos, ":%llu",
			       (unsigned long long)res->lver);

	if (ret > len - pos)
		goto fail;
	pos += ret;

	if (pos > len)
		goto fail;

	*str_ret = str;
	return 0;

 fail:
	free(str);
	return -EINVAL;
}

/*
 * convert to struct sanlk_resource from string with format:
 * <lockspace_name>:<resource_name>:<path>:<offset>[:<path>:<offset>...][:<lver>]
 */

int sanlock_str_to_res(char *str, struct sanlk_resource **res_ret)
{
	struct sanlk_resource *res;
	char sub[SANLK_PATH_LEN + 1];
	int i, j, d, rv, len, sub_count, colons, num_disks, have_lver;

	if (strlen(str) < 3)
		return -ENXIO;

	colons = 0;
	for (i = 0; i < strlen(str); i++) {
		if (str[i] == '\\') {
			i++;
			continue;
		}

		if (str[i] == ':')
			colons++;
	}
	if (!colons || (colons == 2)) {
		return -1;
	}

	num_disks = (colons - 1) / 2;
	have_lver = (colons - 1) % 2;

	if (num_disks > SANLK_MAX_DISKS)
		return -2;

	len = sizeof(struct sanlk_resource) + num_disks * sizeof(struct sanlk_disk);

	res = malloc(len);
	if (!res)
		return -ENOMEM;
	memset(res, 0, len);

	res->num_disks = num_disks;

	d = 0;
	sub_count = 0;
	j = 0;
	memset(sub, 0, sizeof(sub));

	len = strlen(str);

	for (i = 0; i < len + 1; i++) {
		if (str[i] == '\\') {
			if (i == (len - 1))
				goto fail;

			i++;
			sub[j++] = str[i];
			continue;
		}
		if (i < len && str[i] != ':') {
			if (j >= SANLK_PATH_LEN)
				goto fail;
			sub[j++] = str[i];
			continue;
		}

		/* do something with sub when we hit ':' or end of str,
		   first and second subs are lockspace and resource names,
		   then even sub is path, odd sub is offset */

		if (sub_count < 2 && strlen(sub) > SANLK_NAME_LEN)
			goto fail;
		if (sub_count >= 2 && (strlen(sub) > SANLK_PATH_LEN-1 || strlen(sub) < 1))
			goto fail;

		if (sub_count == 0) {
			strncpy(res->lockspace_name, sub, SANLK_NAME_LEN);

		} else if (sub_count == 1) {
			strncpy(res->name, sub, SANLK_NAME_LEN);

		} else if (!(sub_count % 2)) {
			if (have_lver && (d == num_disks)) {
				if (!strncmp(sub, "SH", 2)) {
					res->flags |= SANLK_RES_SHARED;
				} else {
					res->flags |= SANLK_RES_LVER;
					res->lver = strtoull(sub, NULL, 0);
				}
			} else {
				strncpy(res->disks[d].path, sub, SANLK_PATH_LEN - 1);
			}
		} else {
			rv = sscanf(sub, "%llu", (unsigned long long *)&res->disks[d].offset);
			if (rv != 1)
				goto fail;
			d++;
		}

		sub_count++;
		j = 0;
		memset(sub, 0, sizeof(sub));
	}

	*res_ret = res;
	return 0;

 fail:
	free(res);
	return -1;
}

/*
 * convert from array of struct sanlk_resource * to state string with format:
 * "RESOURCE1 RESOURCE2 RESOURCE3 ..."
 * RESOURCE format in sanlock_res_to_str() comment
 */

int sanlock_args_to_state(int res_count,
			  struct sanlk_resource *res_args[],
			  char **res_state)
{
	char *str, *state;
	int i, rv;

	state = malloc(res_count * (SANLK_MAX_RES_STR + 1));
	if (!state)
		return -ENOMEM;
	memset(state, 0, res_count * (SANLK_MAX_RES_STR + 1));

	for (i = 0; i < res_count; i++) {
		str = NULL;

		rv = sanlock_res_to_str(res_args[i], &str);
		if (rv < 0 || !str) {
			free(state);
			return rv;
		}

		if (strlen(str) > SANLK_MAX_RES_STR - 1) {
			free(str);
			free(state);
			return -EINVAL;
		}

		/* space is str separator, so it's invalid within each str */

		if (strstr(str, " ")) {
			free(str);
			free(state);
			return -EINVAL;
		}

		if (i)
			strcat(state, " ");
		strcat(state, str);
		free(str);
	}

	/* caller to free state */
	*res_state = state;
	return 0;
}

/*
 * convert to array of struct sanlk_resource * from state string with format:
 * "RESOURCE1 RESOURCE2 RESOURCE3 ..."
 * RESOURCE format in sanlock_str_to_res() comment
 */

int sanlock_state_to_args(char *res_state,
			  int *res_count,
			  struct sanlk_resource ***res_args)
{
	struct sanlk_resource **args;
	struct sanlk_resource *res;
	char str[SANLK_MAX_RES_STR + 1];
	int count = 1, arg_count = 0;
	int i, j, len, rv;

	for (i = 0; i < strlen(res_state); i++) {
		if (res_state[i] == ' ')
			count++;
	}

	*res_count = count;

	args = malloc(count * sizeof(*args));
	if (!args)
		return -ENOMEM;
	memset(args, 0, count * sizeof(*args));

	j = 0;
	memset(str, 0, sizeof(str));

	len = strlen(res_state);

	for (i = 0; i < len + 1; i++) {
		if (i < len && res_state[i] != ' ') {
			str[j++] = res_state[i];
			continue;
		}

		rv = sanlock_str_to_res(str, &res);
		if (rv < 0 || !res)
			goto fail_free;

		if (arg_count == count)
			goto fail_free;

		args[arg_count++] = res;

		j = 0;
		memset(str, 0, sizeof(str));
	}

	/* caller to free res_count res and args */
	*res_count = arg_count;
	*res_args = args;
	return 0;

 fail_free:
	for (i = 0; i < count; i++) {
		if (args[i])
			free(args[i]);
	}
	free(args);
	return rv;
}

/*
 * convert to struct sanlk_lockspace from string with format:
 * <lockspace_name>:<host_id>:<path>:<offset>
 */

int sanlock_str_to_lockspace(char *str, struct sanlk_lockspace *ls)
{
	char *host_id = NULL;
	char *path = NULL;
	char *offset = NULL;
	int i;

	if (!str)
		return -EINVAL;

	for (i = 0; i < strlen(str); i++) {
		if (str[i] == '\\') {
			i++;
			continue;
		}

		if (str[i] == ':') {
			if (!host_id)
				host_id = &str[i];
			else if (!path)
				path = &str[i];
			else if (!offset)
				offset = &str[i];
		}
	}

	if (host_id) {
		*host_id = '\0';
		host_id++;
	}
	if (path) {
		*path = '\0';
		path++;
	}
	if (offset) {
		*offset= '\0';
		offset++;
	}

	strncpy(ls->name, str, SANLK_NAME_LEN);

	if (host_id)
		ls->host_id = atoll(host_id);
	if (path)
		copy_path_in(ls->host_id_disk.path, path);
	if (offset)
		ls->host_id_disk.offset = atoll(offset);

	return 0;
}

