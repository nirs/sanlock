/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WDMD_SOCK_H__
#define __WDMD_SOCK_H__

#define WDMD_RUN_DIR "/var/run/wdmd"
#define WDMD_SOCKET_NAME "wdmd.sock"

enum {
	CMD_REGISTER = 1,
	CMD_REFCOUNT_SET,
	CMD_REFCOUNT_CLEAR,
	CMD_TEST_LIVE,
	CMD_STATUS,
};

struct wdmd_header {
	uint32_t magic;
	uint32_t cmd;
	uint32_t len;
	uint32_t flags;
	uint32_t test_interval;
	uint32_t fire_timeout;
	uint64_t last_keepalive;
	uint64_t renewal_time;
	uint64_t expire_time;
	char name[WDMD_NAME_SIZE];
};

int wdmd_socket_address(struct sockaddr_un *addr);

#endif
