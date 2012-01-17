/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef	__LOCKFILE_H__
#define	__LOCKFILE_H__

int lockfile(const char *dir, const char *name);
void unlink_lockfile(int fd, const char *dir, const char *name);

#endif
