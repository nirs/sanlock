/*
 * Copyright 2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __HELPER_H__
#define __HELPER_H__

/*
 * helper process
 * recvs 512 byte helper_msg on in_fd
 * sends 4 byte helper_status on out_fd
 */

#define SANLK_HELPER_MSG_LEN 512

#define HELPER_MSG_RUNPATH 1

struct helper_msg {
	uint8_t type;
	uint8_t pad1;
	uint16_t pad2;
	uint32_t flags;
	int pid;
	char path[SANLK_HELPER_PATH_LEN]; /* 128 */
	char args[SANLK_HELPER_ARGS_LEN]; /* 128 */
	char pad[244];
};

#define HELPER_STATUS_INTERVAL 30

#define HELPER_STATUS 1

struct helper_status {
	uint8_t type;
	uint8_t status;
	uint16_t len;
};

int run_helper(int in_fd, int out_fd, int log_stderr);

#endif
