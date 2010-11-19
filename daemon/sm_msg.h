#ifndef __SM_MSG_H__
#define __SM_MSG_H__

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

struct sm_header {
	uint32_t magic;
	uint32_t version;
	uint32_t cmd;
	uint32_t length;
	uint32_t seq;
	uint32_t pad;
	uint32_t data;
	uint32_t data2;
};

int setup_listener_socket(const char *name, int length, int *listener_socket);
int connect_socket(const char *name, int length, int* sock_fd);
int send_header(int sock, int cmd, uint32_t data, uint32_t data2);

#endif
