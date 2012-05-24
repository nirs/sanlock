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

int main(int argc, char *argv[])
{
	char rd[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	char path[SANLK_HELPER_PATH_LEN];
	char args[SANLK_HELPER_PATH_LEN];
	struct sanlk_resource *res;
	time_t now, last;
	int sock, rv, i;

	if (argc < 6) {
		printf("sanlk_client <lockspace_name> <resource_name> <lease_path> <lease_offset> <kill_path> <kill_args...>\n");
		return -1;
	}

	memset(rd, 0, sizeof(rd));
	memset(path, 0, sizeof(path));
	memset(args, 0, sizeof(args));

	res = (struct sanlk_resource *)&rd;

	strcpy(res->lockspace_name, argv[1]);
	strcpy(res->name, argv[2]);
	res->num_disks = 1;
	strcpy(res->disks[0].path, argv[3]);
	res->disks[0].offset = atoi(argv[4]);

	strcpy(path, argv[5]);

	if (argc > 6) {
		for (i = 6; i < argc; i++) {
			strcat(args, argv[i]);
			strcat(args, " ");
		}
	}

	sock = sanlock_register();
	if (sock < 0) {
		fprintf(stderr, "register error %d\n", sock);
		return -1;
	}

	rv = sanlock_killpath(sock, SANLK_KILLPATH_PID, path, args);
	if (rv < 0) {
		fprintf(stderr, "killpath error %d\n", rv);
		return -1;
	}

	rv = sanlock_acquire(sock, -1, 0, 1, &res, NULL);
	if (rv < 0) {
		fprintf(stderr, "acquire error %d\n", rv);
		return -1;
	}

	rv = sanlock_restrict(sock, SANLK_RESTRICT_ALL);
	if (rv < 0) {
		fprintf(stderr, "restrict error %d\n", rv);
		return -1;
	}

	printf("%d running\n", getpid());

	last = time(NULL);
	while (1) {
		now = time(NULL);
		if (now - last > 2)
			printf("%d running (paused %llu sec)\n",
				getpid(), (unsigned long long)(now - last));
		last = now;
		sleep(1);
	}
}

