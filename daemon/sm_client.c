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

#include "sm.h"
#include "sm_msg.h"
#include "disk_paxos.h"
#include "sm_options.h"
#include "token_manager.h"
#include "lockfile.h"
#include "log.h"
#include "diskio.h"
#include "sm_client.h"

/* TODO: make this file a library */

int sm_register(void)
{
	int sock, rv;

	rv = connect_socket(MAIN_SOCKET_NAME, sizeof(MAIN_SOCKET_NAME), &sock);
	if (rv < 0)
		return rv;

	rv = send_header(sock, SM_CMD_REGISTER, 0, 0);
	if (rv < 0) {
		close(sock);
		return rv;
	}

	return sock;
}

int sm_acquire(int sock, int token_count, struct token *token_args[])
{
	struct token *t;
	struct sm_header h;
	int rv, i;

	rv = send_header(sock, SM_CMD_ACQUIRE, token_count, 0);
	if (rv < 0)
		return rv;

	for (i = 0; i < token_count; i++) {
		t = token_args[i];
		rv = send(sock, t, sizeof(struct token), 0);
		if (rv < 0) {
			rv = -errno;
			goto out;
		}

		rv = send(sock, t->disks, sizeof(struct sync_disk) * t->num_disks, 0);
		if (rv < 0) {
			rv = -errno;
			goto out;
		}
	}

	memset(&h, 0, sizeof(h));

	rv = recv(sock, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	if (h.data != token_count) {
		rv = -1;
		goto out;
	}
	rv = 0;
 out:
	return rv;
}

/* tell daemon to release lease(s) for given pid.
   I don't think the pid itself will usually tell sm to release leases,
   but it will be requested by a manager overseeing the pid */

int sm_release(int pid, int token_count, struct token *token_args[])
{
	struct sm_header h;
	int results[MAX_LEASE_ARGS];
	int sock, rv, i;

	rv = connect_socket(MAIN_SOCKET_NAME, sizeof(MAIN_SOCKET_NAME), &sock);
	if (rv < 0)
		return rv;

	rv = send_header(sock, SM_CMD_RELEASE, token_count, pid);
	if (rv < 0)
		goto out;

	for (i = 0; i < token_count; i++) {
		rv = send(sock, token_args[i]->resource_name, NAME_ID_SIZE, 0);
		if (rv < 0) {
			rv = -errno;
			goto out;
		}
	}

	memset(&h, 0, sizeof(h));
	memset(&results, 0, sizeof(results));

	rv = recv(sock, &h, sizeof(struct sm_header), MSG_WAITALL);
	if (rv != sizeof(h)) {
		rv = -errno;
		goto out;
	}

	rv = recv(sock, &results, sizeof(int) * token_count, MSG_WAITALL);
	if (rv != sizeof(int) * token_count) {
		rv = -errno;
		goto out;
	}

	rv = 0;
	for (i = 0; i < token_count; i++) {
		if (results[i] != 1) {
			rv = -1;
		}
	}
 out:
	close(sock);
	return rv;
}

static int send_command(int cmd, uint32_t data)
{
	int rv, sock;

	rv = connect_socket(MAIN_SOCKET_NAME, sizeof(MAIN_SOCKET_NAME), &sock);
	if (rv < 0)
		return -1;

	rv = send_header(sock, cmd, data, 0);
	if (rv < 0)
		goto clean;

	return sock;
 clean:
	close(sock);
	return rv;
}

int sm_shutdown(void)
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

int sm_status(void)
{
	return 0;
}

int sm_log_dump(void)
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

int sm_set_host_id(uint32_t our_host_id)
{
	struct sm_header h;
	int sock, rv;

	sock = send_command(SM_CMD_SET_HOST_ID, our_host_id);
	if (sock < 0)
		return sock;

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

