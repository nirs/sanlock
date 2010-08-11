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
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sm.h"
#include "sm_msg.h"
#include "disk_paxos.h"
#include "lockfile.h"
#include "log.h"

int lockfile(struct token *token, const char *dir, const char *name)
{
	char path[PATH_MAX];
	char buf[16];
	struct flock lock;
	int fd, rv;

	snprintf(path, PATH_MAX, "%s/%s", dir, name);

	fd = open(path, O_CREAT|O_WRONLY|O_CLOEXEC, 0666);
	if (fd < 0) {
		log_error(token, "lockfile open error %d", errno);
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	rv = fcntl(fd, F_SETLK, &lock);
	if (rv < 0) {
		log_error(token, "lockfile setlk error %d", errno);
		goto fail;
	}

	rv = ftruncate(fd, 0);
	if (rv < 0) {
		log_error(token, "lockfile truncate error %d", errno);
		goto fail;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d\n", getpid());

	rv = write(fd, buf, strlen(buf));
	if (rv <= 0) {
		log_error(token, "lockfile write error %d", errno);
		goto fail;
	}

	return fd;
 fail:
	close(fd);
	return -1;
}

void unlink_lockfile(int fd, const char *dir, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", dir, name);
	unlink(path);
	close(fd);
}

