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
	uint64_t t, last_keepalive;
	int test_interval, fire_timeout;
	int con, rv;
	int i = 0;

	con = wdmd_connect();
	printf("wdmd_connect %d\n", con);
	if (con < 0)
		return con;

	rv = wdmd_register(con, "wdmd_client");
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

		if (i++ > 10)
			break;
	}

	rv = wdmd_test_live(con, t, 0);
	printf("wdmd_test_live 0 %d\n", rv);

	return 0;
}

