/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#ifndef __CLIENT_CMD_H__
#define __CLIENT_CMD_H__

int sanlock_status(int debug, char sort_arg);
int sanlock_host_status(int debug, char *lockspace_name);
int sanlock_log_dump(int max_size);
int sanlock_shutdown(void);

#endif
