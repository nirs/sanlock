/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __SANLOCK_SOCK_H__
#define __SANLOCK_SOCK_H__

#define MAX_CLIENT_MSG (1024 * 1024) /* TODO: this is random */

enum {
	SM_CMD_REGISTER		= 1,
	SM_CMD_ADD_LOCKSPACE	= 2,
	SM_CMD_REM_LOCKSPACE	= 3,
	SM_CMD_SHUTDOWN		= 4,
	SM_CMD_STATUS		= 5,
	SM_CMD_LOG_DUMP		= 6,
	SM_CMD_ACQUIRE		= 7,
	SM_CMD_RELEASE		= 8,
	SM_CMD_INQUIRE		= 9,
	SM_CMD_RESTRICT		= 10,
	SM_CMD_REQUEST		= 11,
};

struct sm_header {
	uint32_t magic;
	uint32_t version;
	uint32_t cmd; /* SM_CMD_ */
	uint32_t cmd_flags;
	uint32_t length;
	uint32_t seq;
	uint32_t data;
	uint32_t data2;
};

#define SANLK_STATE_MAXSTR	4096

#define SANLK_STATE_DAEMON      1
#define SANLK_STATE_LOCKSPACE   2
#define SANLK_STATE_CLIENT      3
#define SANLK_STATE_RESOURCE    4

struct sanlk_state {
	uint32_t type; /* SANLK_STATE_ */
	uint32_t flags;
	uint32_t data32; /* pid (for client) */
	uint64_t data64;
	char name[SANLK_NAME_LEN]; /* client name or resource name */
	uint32_t str_len;
	char str[0]; /* string of internal state */
};

int sanlock_socket_address(struct sockaddr_un *addr);

#endif
