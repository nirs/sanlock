/*
 * Copyright 2018 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef	__ENV_H__
#define	__ENV_H__

const char *env_get(const char *key, const char *defval);
int env_get_bool(const char *key, int defval);

#endif
