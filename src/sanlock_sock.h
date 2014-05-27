/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __SANLOCK_SOCK_H__
#define __SANLOCK_SOCK_H__

#define SANLK_RUN_DIR "/var/run/sanlock"
#define SANLK_SOCKET_NAME "sanlock.sock"

#define SM_MAGIC 0x04282010
#define SM_PROTO 0x00000001

#define SM_CB_PROTO 0x00000001

#define MAX_CLIENT_MSG (1024 * 1024) /* TODO: this is random */

enum {
	SM_CMD_REGISTER		 = 1,
	SM_CMD_ADD_LOCKSPACE	 = 2,
	SM_CMD_REM_LOCKSPACE	 = 3,
	SM_CMD_SHUTDOWN		 = 4,
	SM_CMD_STATUS		 = 5,
	SM_CMD_LOG_DUMP		 = 6,
	SM_CMD_ACQUIRE		 = 7,
	SM_CMD_RELEASE		 = 8,
	SM_CMD_INQUIRE		 = 9,
	SM_CMD_RESTRICT		 = 10,
	SM_CMD_REQUEST		 = 11,
	SM_CMD_ALIGN		 = 12,
	SM_CMD_EXAMINE_LOCKSPACE = 13,
	SM_CMD_EXAMINE_RESOURCE	 = 14,
	SM_CMD_HOST_STATUS	 = 15,
	SM_CMD_INQ_LOCKSPACE	 = 16,
	SM_CMD_KILLPATH		 = 17,
	SM_CMD_WRITE_LOCKSPACE   = 18,
	SM_CMD_WRITE_RESOURCE    = 19,
	SM_CMD_READ_LOCKSPACE    = 20,
	SM_CMD_READ_RESOURCE     = 21,
	SM_CMD_GET_LOCKSPACES    = 22,
	SM_CMD_GET_HOSTS         = 23,
	SM_CMD_READ_RESOURCE_OWNERS = 24,
	SM_CMD_SET_LVB		 = 25,
	SM_CMD_GET_LVB		 = 26,
	SM_CMD_CONVERT		 = 27,
	SM_CMD_VERSION		 = 28,
	SM_CMD_SHUTDOWN_WAIT     = 29,
	SM_CMD_REG_EVENT         = 30,
	SM_CMD_END_EVENT         = 31,
	SM_CMD_SET_EVENT         = 32,
};

#define SM_CB_GET_EVENT 1

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
#define SANLK_STATE_CLIENT      2
#define SANLK_STATE_LOCKSPACE   3
#define SANLK_STATE_RESOURCE    4
#define SANLK_STATE_HOST	5

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

struct event_cb {
	struct sm_header h;
	struct sanlk_host_event he;
	uint64_t from_host_id;
	uint64_t from_generation;
};

#endif
