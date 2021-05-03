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
#include <sys/socket.h>

#include "sanlock.h"
#include "sanlock_resource.h"
#include "sanlock_admin.h"
#include "sanlock_sock.h"

/* gcc with -lsanlock */

/*
 * sanlock direct init -s 1271384c-24db-4c9b-bebf-61a1916b6cb1:0:/dev/test/main:0
 * sanlock add_lockspace -s 1271384c-24db-4c9b-bebf-61a1916b6cb1:1:/dev/test/main:0
 */

/* copied from client.c */
static int send_header(int sock, int cmd, uint32_t cmd_flags, int datalen,
                       uint32_t data, uint32_t data2)
{
        struct sm_header header;
        int rv;

        memset(&header, 0, sizeof(header));
        header.magic = SM_MAGIC;
        header.version = SM_PROTO;
        header.cmd = cmd;
        header.cmd_flags = cmd_flags;
        header.length = sizeof(header) + datalen;
        header.data = data;
        header.data2 = data2;

retry:  
        rv = send(sock, (void *) &header, sizeof(header), 0);
        if (rv == -1 && errno == EINTR)
                goto retry;

        if (rv < 0)
                return -errno;

        return 0;
}

int main(int argc, char *argv[])
{
	char rd1[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	char rd2[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	struct sanlk_resource *res1;
	struct sanlk_resource *res2;
	const char *lsname;
	const char *resname1;
	const char *resname2;
	char *path;
	int fd, rv;

	if (argc < 2) {
		printf("%s <path>\n", argv[0]);
		return -1;
	}

	path = argv[1];

	lsname =   "1271384c-24db-4c9b-bebf-61a1916b6cb1";
	resname1 = "2e794e7a-5a9c-4617-8cd0-dc03c917d7a1";
	resname2 = "2e794e7a-5a9c-4617-8cd0-dc03c917d7a2";

	memset(rd1, 0, sizeof(rd1));
	memset(rd2, 0, sizeof(rd2));

	res1 = (struct sanlk_resource *)&rd1;
	res2 = (struct sanlk_resource *)&rd2;

	strcpy(res1->lockspace_name, lsname);
	sprintf(res1->name, "%s", resname1);
	res1->num_disks = 1;
	strcpy(res1->disks[0].path, path);
	res1->disks[0].offset = 1048576;

	strcpy(res2->lockspace_name, lsname);
	sprintf(res2->name, "%s", resname2);
	res2->num_disks = 1;
	strcpy(res2->disks[0].path, path);
	res2->disks[0].offset = 2 * 1048576;

	/*
	struct sanlk_lockspace ls = { 0 };
	sprintf(ls.name, lsname);
	sprintf(ls.host_id_disk.path, path);

	rv = sanlock_write_lockspace(&ls, 0, 0, 0);
	if (rv < 0) {
		printf("write_lockspace error %d\n", rv);
		return -1;
	}
	*/

	rv = sanlock_write_resource(res1, 0, 0, 0);
	if (rv < 0) {
		printf("write_resource1 error %d\n", rv);
		return -1;
	}
	rv = sanlock_write_resource(res2, 0, 0, 0);
	if (rv < 0) {
		printf("write_resource2 error %d\n", rv);
		return -1;
	}

	fd = sanlock_register();
	if (fd < 0) {
		printf("register error %d\n", fd);
		return -1;
	}

	printf("acquiring both leases for registered fd %d\n", fd);

	rv = sanlock_acquire(fd, -1, 0, 1, &res1, NULL);
	if (rv < 0) {
		printf("acquire res1 error %d\n", rv);
		return -1;
	}

	rv = sanlock_acquire(fd, -1, 0, 1, &res2, NULL);
	if (rv < 0) {
		printf("acquire res2 error %d\n", rv);
		return -1;
	}

	printf("sleeping... check that both leases are held\n");
	sleep(20);

	printf("sending res1 release header only\n");
	rv = send_header(fd, SM_CMD_RELEASE, 0, sizeof(struct sanlk_resource), 1, -1);
	if (rv < 0)
		printf("send bad header error %d\n", rv);
	else
		printf("send bad header ok\n");

	printf("sending res2 release interleaved\n");
	rv = sanlock_release(fd, -1, 0, 1, &res2);
	if (rv < 0)
		printf("odd release res2 error %d\n", rv);
	else
		printf("odd release res2 ok\n");

	printf("sending res1 release body only\n");
	rv = send(fd, res1, sizeof(struct sanlk_resource), 0);
	if (rv < 0)
		printf("send bad body error %d\n", rv);
	else
		printf("send bad body ok\n");

	/*
	 * This is not simulating the recv() that each sanlock_release
	 * would do in libsanlock to get a result for each release.
	 * These would likely just cause the client block indefinitely
	 * waiting for a reply that won't come because the bad release
	 * calls were ignored.
	 */

	printf("sleeping... check which leases are held\n");
	sleep(20);
	
	printf("releasing both leases normally\n");
	rv = sanlock_release(fd, -1, 0, 1, &res1);
	if (rv < 0)
		printf("release res1 error %d\n", rv);
	else
		printf("release res1 ok\n");

	rv = sanlock_release(fd, -1, 0, 1, &res2);
	if (rv < 0)
		printf("release res2 error %d\n", rv);
	else
		printf("release res2 ok\n");

	printf("sleeping... check that both leases are released\n");
	sleep(20);

	printf("acquiring lease res1\n");
	rv = sanlock_acquire(fd, -1, 0, 1, &res1, NULL);
	if (rv < 0)
		printf("acquire res1 error %d\n", rv);
	else
		printf("acquire res1 ok\n");

	/* exit should close our registered connection and
	   automatically release res1 */

	printf("exiting... check if held lease is released after exit\n");

	return 0;
}

