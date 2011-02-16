#ifndef __WDMD_INTERNAL_H__
#define __WDMD_INTERNAL_H__

#ifndef GNUC_UNUSED
#define GNUC_UNUSED __attribute__((__unused__))
#endif

#define WDMD_RUN_DIR "/var/run/wdmd"
#define WDMD_SOCKET_NAME "wdmd_sock"

enum {
	CMD_REGISTER = 1,
	CMD_REFCOUNT_SET,
	CMD_REFCOUNT_CLEAR,
	CMD_TEST_LIVE,
	CMD_STATUS,
};

struct wdmd_header {
	uint32_t magic;
	uint32_t cmd;
	uint32_t len;
	uint32_t flags;
	uint32_t test_interval;
	uint32_t fire_timeout;
	uint64_t last_keepalive;
	uint64_t renewal_time;
	uint64_t expire_time;
	char name[WDMD_NAME_SIZE];
};

#endif
