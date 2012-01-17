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
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "wdmd.h"
#include "wdmd_sock.h"

int wdmd_connect(void)
{
	int rv, s;
	struct sockaddr_un addr;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0)
		return -errno;

	rv = wdmd_socket_address(&addr);
	if (rv < 0)
		return rv;

	rv = connect(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (rv < 0) {
		rv = -errno;
		close(s);
		return rv;
	}
	return s;
}

int wdmd_register(int con, char *name)
{
	struct wdmd_header h;
	int rv;

	if (strlen(name) > WDMD_NAME_SIZE)
		return -ENAMETOOLONG;

	memset(&h, 0, sizeof(h));
	h.cmd = CMD_REGISTER;
	strncpy(h.name, name, WDMD_NAME_SIZE);

	rv = send(con, (void *)&h, sizeof(struct wdmd_header), 0);
	if (rv < 0)
		return -errno;
	return 0;
}

static int send_header(int con, int cmd)
{
	struct wdmd_header h;
	int rv;

	memset(&h, 0, sizeof(h));
	h.cmd = cmd;

	rv = send(con, (void *)&h, sizeof(struct wdmd_header), 0);
	if (rv < 0)
		return -errno;
	return 0;
}

int wdmd_refcount_set(int con)
{
	return send_header(con, CMD_REFCOUNT_SET);
}

int wdmd_refcount_clear(int con)
{
	return send_header(con, CMD_REFCOUNT_CLEAR);
}

int wdmd_test_live(int con, uint64_t renewal_time, uint64_t expire_time)
{
	struct wdmd_header h;
	int rv;

	memset(&h, 0, sizeof(h));
	h.cmd = CMD_TEST_LIVE;
	h.renewal_time = renewal_time;
	h.expire_time = expire_time;

	rv = send(con, (void *)&h, sizeof(struct wdmd_header), 0);
	if (rv < 0)
		return -errno;
	return 0;
}

int wdmd_status(int con, int *test_interval, int *fire_timeout,
	       uint64_t *last_keepalive)
{
	struct wdmd_header h;
	int rv;

	rv = send_header(con, CMD_STATUS);
	if (rv < 0)
		return rv;

	rv = recv(con, &h, sizeof(h), MSG_WAITALL);
	if (rv < 0)
		return -errno;

	*test_interval = h.test_interval;
	*fire_timeout = h.fire_timeout;
	*last_keepalive = h.last_keepalive;
	return 0;
}

