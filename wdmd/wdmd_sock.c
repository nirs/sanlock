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
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "wdmd.h"
#include "wdmd_internal.h"
#include "wdmd_sock.h"

int wdmd_socket_address(struct sockaddr_un *addr)
{
	memset(addr, 0, sizeof(struct sockaddr_un));
	addr->sun_family = AF_LOCAL;
	snprintf(addr->sun_path, sizeof(addr->sun_path) - 1, "%s/%s",
		 WDMD_RUN_DIR, WDMD_SOCKET_NAME);
	return 0;
}

