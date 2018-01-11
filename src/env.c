/*
 * Copyright 2018 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h>

#include "env.h"

const char *env_get(const char *key, const char *defval)
{
	const char *val;

	val = getenv(key);
	if (val == NULL)
		return defval;

	return val;
}

int env_get_bool(const char *key, int defval)
{
	const char *val;

	val = getenv(key);
	if (val == NULL)
		return defval;

	return strcmp(val, "1") ? 0 : 1;
}
