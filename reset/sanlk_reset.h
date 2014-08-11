/*
 * Copyright 2014 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __SANLK_RESET_H__
#define __SANLK_RESET_H__

#define EVENT_RESET              1
#define EVENT_RESETTING          2
#define EVENT_REBOOT             4
#define EVENT_REBOOTING          8

#define SANLK_RESETD_RUNDIR "/var/run/sanlk-resetd"
#define SANLK_RESETD_SOCKET SANLK_RESETD_RUNDIR "/sanlk-resetd.sock"
#define SANLK_RESETD_SOCKET_MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)

#define UPDATE_SIZE 256  /* sendmsg size on unix socket */

static inline int setup_resetd_socket(void)
{
	int s;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0)
		return s;

	memset(&update_addr, 0, sizeof(update_addr));
	update_addr.sun_family = AF_LOCAL;
	strcpy(update_addr.sun_path, SANLK_RESETD_SOCKET);
	update_addrlen = sizeof(sa_family_t) + strlen(update_addr.sun_path) + 1;

	return s;
}

#endif

