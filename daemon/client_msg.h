#ifndef __CLIENT_MSG_H__
#define __CLIENT_MSG_H__

#define MAX_CLIENT_MSG (1024 * 1024) /* TODO: this is random */

enum {
	SM_CMD_SET_HOST_ID = 1,
	SM_CMD_REGISTER,
	SM_CMD_SHUTDOWN,
	SM_CMD_STATUS,
	SM_CMD_LOG_DUMP,
	SM_CMD_ACQUIRE,
	SM_CMD_RELEASE,
	SM_CMD_MIGRATE,
	SM_CMD_SETOWNER,
};

#define SANLK_STATE_MAXSTR	4096

#define SANLK_STATE_DAEMON      1
#define SANLK_STATE_HOSTID      2
#define SANLK_STATE_CLIENT      3
#define SANLK_STATE_RESOURCE    4

struct sanlk_state {
	uint32_t type; /* SANLK_STATE_ */
	uint32_t count;
	uint32_t flags;
	uint32_t data32; /* pid (for client) */
	uint64_t data64;
	char name[SANLK_NAME_LEN]; /* client name or resource name */
	uint32_t len;
	char str[0]; /* string of internal state */
};

int setup_listener_socket(int *listener_socket);
int connect_socket(int *sock_fd);
int send_header(int sock, int cmd, int datalen, uint32_t data, uint32_t data2);
int send_command(int cmd, uint32_t data);

#endif
