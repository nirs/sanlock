/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __CLIENT_MSG_H__
#define __CLIENT_MSG_H__

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

int setup_listener_socket(int *listener_socket,
                          uid_t owner, gid_t group, mode_t mode);
int connect_socket(int *sock_fd);
int send_header(int sock, int cmd, uint32_t cmd_flags, int datalen,
		uint32_t data, uint32_t data2);
int send_command(int cmd, uint32_t data);

#endif
