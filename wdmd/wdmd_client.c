/*
 * Copyright 2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "wdmd.h"

int main(int argc, char *argv[])
{
	char name[WDMD_NAME_SIZE];
	uint64_t t, last_keepalive;
	int test_interval, fire_timeout;
	int con, rv;
	int i = 0;
	int iter = 10;

	if (argc > 1)
		iter = atoi(argv[1]);

	memset(name, 0, sizeof(name));
	sprintf(name, "%s", "wdmd_client");

	con = wdmd_connect();
	printf("wdmd_connect %d\n", con);
	if (con < 0)
		return con;

	rv = wdmd_register(con, name);
	printf("wdmd_register %d\n", rv);
	if (rv < 0)
		return rv;

	rv = wdmd_status(con, &test_interval, &fire_timeout, &last_keepalive);
	printf("wdmd_status %d test_interval %d fire_timeout %d last_keepalive %llu\n",
	       rv, test_interval, fire_timeout,
	       (unsigned long long)last_keepalive);
	if (rv < 0)
		return rv;

	while (1) {
		sleep(10);

		t = time(NULL);

		rv = wdmd_test_live(con, t, t + 40);
		printf("wdmd_test_live %d %llu %llu\n", rv,
		       (unsigned long long)t,
		       (unsigned long long)(t + 40));

		if (i++ > iter)
			break;
	}

	rv = wdmd_test_live(con, t, 0);
	printf("wdmd_test_live 0 %d\n", rv);

	return 0;
}

