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
	struct sanlk_disk sd;
	int fd, rv;

	fd = send_command(SM_CMD_SET_HOST_ID, 0);
	if (fd < 0)
		return fd;

	rv = send(fd, &host_id, sizeof(uint64_t), 0);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}

	memset(&sd, 0, sizeof(sd));
	strncpy(sd.path, path, SANLK_PATH_LEN-1);
	sd.offset = offset;

	rv = send(fd, &sd, sizeof(sd), 0);
	if (rv < 0) {
		rv = -errno;
		goto out;
	}

	rv = recv(fd, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	if (!h.data)
		rv = 0;
	else
		rv = -1;
 out:
	close(fd);
	return rv;
}

/* TODO: nicer way of printing some of the debug fields */

int sanlock_status(int debug)
{
	struct sm_header h;
	struct sanlk_state dst;
	struct sanlk_state hst;
	struct sanlk_state cst;
	struct sanlk_state rst;
	struct sanlk_resource res;
	struct sanlk_disk disk;
	char str[SANLK_STATE_MAXSTR];
	int fd, rv, ci, i, j;

	fd = send_command(SM_CMD_STATUS, 0);
	if (fd < 0)
		return fd;

	rv = recv(fd, &h, sizeof(h), MSG_WAITALL);
	if (rv != sizeof(h))
		return -errno;

	rv = recv(fd, &dst, sizeof(dst), MSG_WAITALL);
	if (rv != sizeof(dst))
		return -errno;

	printf("daemon: our_host_id %llu\n",
	       (unsigned long long)dst.data64);

	if (dst.len) {
		rv = recv(fd, str, dst.len, MSG_WAITALL);
		if (rv != dst.len)
			return -errno;
		if (debug)
			printf("debug: %s\n", str);
	}

	rv = recv(fd, &hst, sizeof(hst), MSG_WAITALL);
	if (rv != sizeof(hst))
		return -errno;

	printf("host_id: our_host_id %llu\n",
	       (unsigned long long)hst.data64);

	if (hst.len) {
		rv = recv(fd, str, hst.len, MSG_WAITALL);
		if (rv != hst.len)
			return -errno;
		if (debug)
			printf("debug: %s\n", str);
	}

	for (ci = 0; ci < dst.count; ci++) {

		rv = recv(fd, &cst, sizeof(cst), MSG_WAITALL);

		printf("pid %u ", cst.data32);
		printf("%.*s\n", SANLK_NAME_LEN, cst.name);

		if (cst.len) {
			rv = recv(fd, str, cst.len, MSG_WAITALL);
			if (debug)
				printf("debug: %s\n", str);
		}

		for (i = 0; i < cst.count; i++) {
			rv = recv(fd, &rst, sizeof(rst), MSG_WAITALL);
			if (rst.len)
				rv = recv(fd, str, rst.len, MSG_WAITALL);

			rv = recv(fd, &res, sizeof(res), MSG_WAITALL);

			printf("    %.*s", SANLK_NAME_LEN, rst.name);

			for (j = 0; j < res.num_disks; j++) {
				rv = recv(fd, &disk, sizeof(disk), MSG_WAITALL);

				printf(":%s:%llu\n", disk.path,
				       (unsigned long long)disk.offset);
			}

			if (rst.len && debug)
				printf("debug: %s\n", str);
		}
	}

	return 0;
}

