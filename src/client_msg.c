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

static int get_socket_address(struct sockaddr_un *addr)
{
	memset(addr, 0, sizeof(struct sockaddr_un));
	addr->sun_family = AF_LOCAL;
	snprintf(addr->sun_path, sizeof(addr->sun_path) - 1, "%s/%s",
		 SANLK_RUN_DIR, SANLK_SOCKET_NAME);
	return 0;
}

int setup_listener_socket(int *listener_socket,
                          uid_t owner, gid_t group, mode_t mode)
{
	int rv, s;
	struct sockaddr_un addr;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0)
		return -1;

	rv = get_socket_address(&addr);
	if (rv < 0)
		return rv;

	unlink(addr.sun_path);
	rv = bind(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (rv < 0)
		goto exit_fail;

	rv = chmod(addr.sun_path, mode);
	if (rv < 0)
		goto exit_fail;

	rv = chown(addr.sun_path, owner, group);
	if (rv < 0)
		goto exit_fail;

	rv = listen(s, 5);
	if (rv < 0)
		goto exit_fail;

	*listener_socket = s;
	return 0;

 exit_fail:
	close(s);
	return -1;
}

int connect_socket(int *sock_fd)
{
	int rv, s;
	struct sockaddr_un addr;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0)
		return -1;

	rv = get_socket_address(&addr);
	if (rv < 0)
		return rv;

	rv = connect(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (rv < 0) {
		rv = -1;
		close(s);
		return rv;
	}
	*sock_fd = s;
	return 0;
}

int send_header(int sock, int cmd, uint32_t cmd_flags, int datalen,
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
		return -1;

	return 0;
}

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

