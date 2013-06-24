#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <sys/signalfd.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <signal.h>

#include "sanlock.h"
#include "sanlock_resource.h"

/* gcc with -lsanlock */

int main(int argc, char *argv[])
{
	char rd[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	struct sanlk_resource *res;
	int sleep_sec;
	int fd, rv;

	if (argc < 6) {
		printf("acquire, [sleep], release\n");
		printf("sanlk_lockr <lockspace_name> <resource_name> <path> <resource_offset> <sleep_sec>\n");
		return -1;
	}

	memset(rd, 0, sizeof(rd));

	res = (struct sanlk_resource *)&rd;

	strcpy(res->lockspace_name, argv[1]);
	strcpy(res->name, argv[2]);
	res->num_disks = 1;
	strcpy(res->disks[0].path, argv[3]);
	res->disks[0].offset = atoi(argv[4]);

	sleep_sec = atoi(argv[5]);

	fd = sanlock_register();
	if (fd < 0) {
		fprintf(stderr, "register error %d\n", fd);
		return -1;
	}

	rv = sanlock_acquire(fd, -1, 0, 1, &res, NULL);
	if (rv < 0) {
		fprintf(stderr, "acquire error %d\n", rv);
		return -1;
	}

	if (sleep_sec)
		sleep(sleep_sec);

	rv = sanlock_release(fd, -1, 0, 1, &res);
	if (rv < 0) {
		fprintf(stderr, "release error %d\n", rv);
		return -1;
	}

	return 0;
}

