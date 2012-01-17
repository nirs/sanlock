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
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "wdmd.h"
#include "wdmd_sock.h"

int wdmd_socket_address(struct sockaddr_un *addr)
{
	memset(addr, 0, sizeof(struct sockaddr_un));
	addr->sun_family = AF_LOCAL;
	snprintf(addr->sun_path, sizeof(addr->sun_path) - 1, "%s/%s",
		 WDMD_RUN_DIR, WDMD_SOCKET_NAME);
	return 0;
}

