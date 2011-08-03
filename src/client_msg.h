/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __CLIENT_MSG_H__
#define __CLIENT_MSG_H__

int connect_socket(int *sock_fd);
int send_header(int sock, int cmd, uint32_t cmd_flags, int datalen,
		uint32_t data, uint32_t data2);
int send_command(int cmd, uint32_t data);

#endif
