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
	char rd2[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	struct sanlk_resource *res;
	struct sanlk_resource *res2;
	struct sanlk_resource **res_args;
	int fd, rv;

	if (argc < 6) {
		printf("acquire with old name, release with new name\n");
		printf("sanlk_rename <lockspace_name> <resource_name_old> <resource_name_new> <path> <resource_offset>\n");
		return -1;
	}

	res_args = malloc(2 * sizeof(struct sanlk_resource *));

	memset(rd, 0, sizeof(rd));
	memset(rd2, 0, sizeof(rd2));

	res = (struct sanlk_resource *)&rd;
	res2 = (struct sanlk_resource *)&rd2;

	res_args[0] = res;
	res_args[1] = res2;

	strcpy(res->lockspace_name, argv[1]);
	strcpy(res->name, argv[2]);
	strcpy(res2->name, argv[3]);
	res->num_disks = 1;
	strcpy(res->disks[0].path, argv[4]);
	res->disks[0].offset = atoi(argv[5]);

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

	rv = sanlock_release(fd, -1, SANLK_REL_RENAME, 2, res_args);
	if (rv < 0) {
		fprintf(stderr, "release error %d\n", rv);
		return -1;
	}

	return 0;
}

