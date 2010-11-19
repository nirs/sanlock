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

static int get_socket_address(const char *name, int length,
                              struct sockaddr_un *addr)
{
	char path[PATH_MAX];

	if (strnlen(name, length) == length) {
		log_error(NULL, "name parameter was not null terminated %d", errno);
		return -1;
	}

	snprintf(path, PATH_MAX, "%s/%s", DAEMON_SOCKET_DIR, name);

	memset(addr, 0, sizeof(struct sockaddr_un));
	addr->sun_family = AF_LOCAL;
	strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
	return 0;
}

int setup_listener_socket(const char* name, int length, int *listener_socket)
{
	int rv, s;
	struct sockaddr_un addr;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0) {
		log_error(NULL, "socket error %d %d", s, errno);
		return s;
	}

	rv = get_socket_address(name, length, &addr);
	if (rv < 0) {
		return rv;
	}
	unlink(addr.sun_path);
	rv = bind(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (rv < 0) {
		log_error(NULL, "bind error %d %s %d %s", rv, addr.sun_path,
		                                  errno, strerror(errno));
		close(s);
		return rv;
	}

	rv = listen(s, 5);
	if (rv < 0) {
		log_error(NULL, "listen error %d %d", rv, errno);
		close(s);
		return rv;
	}

	rv = fchmod(s, 666);
	if (rv < 0) {
		log_error(NULL, "permission change error %d %d", rv, errno);
		close(s);
		return rv;
	}
	*listener_socket = s;
	return 0;
}

int connect_socket(const char* name, int length, int *sock_fd)
{
	int rv, s;
	struct sockaddr_un addr;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0) {
		log_error(NULL, "socket error %d %d", s, errno);
		return s;
	}

	rv = get_socket_address(name, length, &addr);
	if (rv < 0) {
		return rv;
	}

	rv = connect(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (rv < 0) {
		log_tool("connect error %d %d", rv, errno);
		close(s);
		return rv;
	}
	*sock_fd = s;
	return 0;
}

int send_header(int sock, int cmd, uint32_t data, uint32_t data2)
{
	struct sm_header header;
	int rv;

	memset(&header, 0, sizeof(struct sm_header));
	header.magic = SM_MAGIC;
	header.cmd = cmd;
	header.data = data;
	header.data2 = data2;

	log_tool("send_header cmd %d data %u data2 %u", cmd, data, data2);

	rv = send(sock, (void *) &header, sizeof(struct sm_header), 0);
	if (rv < 0) {
		log_tool("send error %d %d", rv, errno);
		return rv;
	}

	return 0;
}

