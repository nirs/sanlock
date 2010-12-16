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
#include <pthread.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "sanlock_internal.h"
#include "diskio.h"
#include "leader.h"
#include "log.h"
#include "client_msg.h"
#include "sanlock_admin.h"

int sanlock_shutdown(void)
{
	struct sm_header h;
	int fd, rv;

	fd = send_command(SM_CMD_SHUTDOWN, 0);
	if (fd < 0)
		return fd;

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h))
		rv = -errno;
	else
		rv = 0;

	close(fd);
	return rv;
}

int sanlock_status(void)
{
	return 0;
}

int sanlock_log_dump(void)
{
	struct sm_header h;
	char *buf;
	int fd, rv, len;

	fd = send_command(SM_CMD_LOG_DUMP, 0);
	if (fd < 0)
		return fd;

	memset(&h, 0, sizeof(h));

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	len = h.length - sizeof(h);

	buf = malloc(len);
	if (!buf) {
		rv = -ENOMEM;
		goto out;
	}
	memset(buf, 0, len);

	rv = recv(fd, buf, len, MSG_WAITALL);
	if (rv != len) {
		rv = -errno;
		goto out;
	}

	rv = 0;
	printf("%s\n", buf);
 out:
	close(fd);
	return rv;
}

int sanlock_set_host_id(uint64_t host_id, char *path, uint64_t offset)
{
	struct sm_header h;
	int sock, rv;

	sock = send_command(SM_CMD_SET_HOST_ID, host_id);
	if (sock < 0)
		return sock;

	/* TODO: send host_id, offset, path */

	rv = recv(sock, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	if (!h.data)
		rv = 0;
	else
		rv = -1;
 out:
	close(sock);
	return rv;
}

