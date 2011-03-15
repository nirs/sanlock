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

	rv = send_header(sock, SM_CMD_REGISTER, 0, 0, 0);
	if (rv < 0) {
		close(sock);
		return rv;
	}

	return sock;
}

int sanlock_acquire(int sock, int pid, int res_count,
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

	rv = send_header(fd, SM_CMD_ACQUIRE, datalen, res_count, data2);
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

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -1;
		goto out;
	}

	if (h.data != res_count) {
		rv = -1;
		goto out;
	}
	rv = 0;
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

int sanlock_migrate(int sock, int pid, uint64_t target_host_id, char **state)
{
	struct sm_header h;
	char *reply_str = NULL;
	int rv, fd, data2, len;

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

	rv = send_header(fd, SM_CMD_MIGRATE, sizeof(uint64_t), 0, data2);
	if (rv < 0)
		return rv;

	rv = send(fd, &target_host_id, sizeof(uint64_t), 0);
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

	len = h.length - sizeof(h);
	reply_str = malloc(len);
	if (!reply_str) {
		rv = -ENOMEM;
		goto out;
	}

	rv = recv(fd, reply_str, len, MSG_WAITALL);
	if (rv != len) {
		free(reply_str);
		rv = -1;
		goto out;
	}

	if (h.data) {
		free(reply_str);
		rv = (int)h.data;
		goto out;
	}

	if (state)
		*state = reply_str;
	rv = 0;
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

/* tell daemon to release lease(s) for given pid.
   I don't think the pid itself will usually tell sm to release leases,
   but it will be requested by a manager overseeing the pid */

int sanlock_release(int sock, int pid, int res_count,
		    struct sanlk_resource *res_args[])
{
	struct sm_header h;
	int results[SANLK_MAX_RESOURCES];
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

	rv = send_header(fd, SM_CMD_RELEASE, datalen, res_count, data2);
	if (rv < 0)
		goto out;

	for (i = 0; i < res_count; i++) {
		rv = send(fd, res_args[i], sizeof(struct sanlk_resource), 0);
		if (rv < 0) {
			rv = -1;
			goto out;
		}
	}

	memset(&h, 0, sizeof(h));
	memset(&results, 0, sizeof(results));

	rv = recv(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -1;
		goto out;
	}

	rv = recv(fd, &results, sizeof(int) * res_count, MSG_WAITALL);
	if (rv != sizeof(int) * res_count) {
		rv = -1;
		goto out;
	}

	rv = 0;
	for (i = 0; i < res_count; i++) {
		if (results[i] != 1) {
			rv = -1;
		}
	}
 out:
	if (sock == -1)
		close(fd);
	return rv;
}

int sanlock_setowner(int sock, int pid)
{
	struct sm_header h;
	int rv, fd, data2;

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

	rv = send_header(fd, SM_CMD_SETOWNER, 0, 0, data2);
	if (rv < 0)
		return rv;

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
	if (sock == -1)
		close(fd);
	return rv;
}
