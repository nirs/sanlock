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
#include "client_msg.h"
#include "sanlock_resource.h"

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

int sanlock_acquire(int sock, int pid, uint32_t flags, int res_count,
		    struct sanlk_resource *res_args[],
		    struct sanlk_options *opt_in)
{
	struct sanlk_resource *res;
	struct sanlk_options opt;
	struct sm_header h;
	int rv, i, fd, data2;
	int datalen = 0;

	if (res_count > SANLK_MAX_RESOURCES)
		return -EINVAL;

	for (i = 0; i < res_count; i++) {
		res = res_args[i];
		datalen += sizeof(struct sanlk_resource);

		if (res->num_disks > MAX_DISKS)
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

	/* get result */

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -1;
		goto out;
	}
	rv = (int)h.data;
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
	struct sm_header h;
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

	/* get result */

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -1;
		goto out;
	}
	rv = (int)h.data;
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

/*
 * convert from struct sanlk_resource to string with format:
 * <lockspace_name>:<resource_name>:<path>:<offset>[:<path>:<offset>...]:<lver>
 */

int sanlock_res_to_str(struct sanlk_resource *res, char **str_ret)
{
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
		ret = snprintf(str + pos, len - pos, ":%s:%llu",
			       res->disks[d].path,
			       (unsigned long long)res->disks[d].offset);

		if (ret >= len - pos)
			goto fail;
		pos += ret;
	}

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

	if (num_disks > MAX_DISKS)
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

		if (sub_count < 2 && strlen(sub) > NAME_ID_SIZE)
			goto fail;
		if (sub_count >= 2 && (strlen(sub) > SANLK_PATH_LEN-1 || strlen(sub) < 1))
			goto fail;

		if (sub_count == 0) {
			strncpy(res->lockspace_name, sub, NAME_ID_SIZE);

		} else if (sub_count == 1) {
			strncpy(res->name, sub, NAME_ID_SIZE);

		} else if (!(sub_count % 2)) {
			if (have_lver && (d == num_disks)) {
				res->flags |= SANLK_RES_LVER;
				res->lver = strtoull(sub, NULL, 0);
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

		if (strlen(str) > SANLK_MAX_RES_STR) {
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

	*res_count = arg_count;
	*res_args = args;
	return 0;

 fail_free:
	for (i = 0; i < count; i++) {
		if (args[i])
			free(args[i]);
	}
	free(args);
 fail:
	return rv;
}

