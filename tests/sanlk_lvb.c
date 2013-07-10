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
	char lvb[512];
	char *filename;
	char *act;
	FILE *fp;
	int fd, rv;
	int set = 0, get = 0;

	memset(lvb, 0, sizeof(lvb));

	if (argc < 7) {
		printf("read file, write it to lvb:\n");
		printf("sanlk_lvb set <lockspace_name> <resource_name> <path> <resource_offset> <file>\n");
		printf("\n");
		printf("read lvb, write it to file:\n");
		printf("sanlk_lvb get <lockspace_name> <resource_name> <path> <resource_offset> <file>\n");
		return -1;
	}

	memset(rd, 0, sizeof(rd));

	res = (struct sanlk_resource *)&rd;

	act = argv[1];
	strcpy(res->lockspace_name, argv[2]);
	strcpy(res->name, argv[3]);
	res->num_disks = 1;
	strcpy(res->disks[0].path, argv[4]);
	res->disks[0].offset = atoi(argv[5]);
	filename = argv[6];

	if (!strcmp(act, "set")) {
		set = 1;
		fp = fopen(filename, "r");
	} else if (!strcmp(act, "get")) {
		get = 1;
		fp = fopen(filename, "w");
	} else {
		printf("bad action %s\n", act);
		return -1;
	}

	if (!fp) {
		printf("fopen failed %s\n", strerror(errno));
		return -1;
	}

	fd = sanlock_register();
	if (fd < 0) {
		printf("register error %d\n", fd);
		return -1;
	}

	rv = sanlock_acquire(fd, -1, SANLK_ACQUIRE_LVB, 1, &res, NULL);
	if (rv < 0) {
		printf("acquire error %d\n", rv);
		return -1;
	}

	if (get) {
		rv = sanlock_get_lvb(0, res, lvb, sizeof(lvb));
		if (rv < 0) {
			printf("get_lvb error %d\n", rv);
			return -1;
		}

		fwrite(lvb, sizeof(lvb), 1, fp);
		if (ferror(fp)) {
			printf("fwrite error\n");
			return -1;
		}

	}

	if (set) {
		fread(lvb, sizeof(lvb), 1, fp);
		if (ferror(fp)) {
			printf("fread error\n");
			return -1;
		}

		rv = sanlock_set_lvb(0, res, lvb, sizeof(lvb));
		if (rv < 0) {
			printf("set_lvb error %d\n", rv);
			return -1;
		}
	}

	fclose(fp);

	rv = sanlock_release(fd, -1, 0, 1, &res);
	if (rv < 0) {
		fprintf(stderr, "release error %d\n", rv);
		return -1;
	}

	return 0;
}

