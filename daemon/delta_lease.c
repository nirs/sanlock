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
#include <pthread.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sm.h"
#include "sm_msg.h"
#include "disk_paxos.h"
#include "token_manager.h"
#include "watchdog.h"
#include "lockfile.h"
#include "log.h"
#include "diskio.h"
#include "host_id.h"
#include "delta_lease.h"

int delta_lease_read_timestamp(struct sync_disk *disk, uint64_t host_id,
			       uint64_t *timestamp)
{
	return 0;
}

int delta_lease_acquire(struct sync_disk *disk, uint64_t host_id)
{
	return 1;
}

int delta_lease_renew(struct sync_disk *disk, uint64_t host_id)
{
	return 1;
}

int delta_lease_release(struct sync_disk *disk, uint64_t host_id)
{
	return 1;
}

/* the host_id lease area begins disk->offset bytes from the start of
   block device disk->path */

int delta_lease_init(struct sync_disk *disk, int num_hosts, int max_hosts)
{
	struct leader_record leader;
	int i, rv;
	uint64_t bb, be, sb, se;
	uint32_t ss;

	printf("initialize leases for host_id 1 - %d\n", max_hosts);
	printf("disk %s offset %llu sector_size %d\n",
	       disk->path, (unsigned long long)disk->offset, disk->sector_size);

	ss = disk->sector_size;
	bb = disk->offset;
	be = disk->offset + (disk->sector_size * max_hosts) - 1;
	sb = bb / ss;
	se = be / ss;

	printf("bytes %llu - %llu len %llu, sectors %llu - %llu len %llu\n",
	       (unsigned long long)bb,
	       (unsigned long long)be,
	       (unsigned long long)be - bb,
	       (unsigned long long)sb,
	       (unsigned long long)se,
	       (unsigned long long)se - sb);

	memset(&leader, 0, sizeof(struct leader_record));

	leader.magic = PAXOS_DISK_MAGIC;
	leader.version = PAXOS_DISK_VERSION_MAJOR | PAXOS_DISK_VERSION_MINOR;
	leader.cluster_mode = options.cluster_mode;
	leader.sector_size = disk->sector_size;
	leader.num_hosts = num_hosts;
	leader.max_hosts = max_hosts;
	leader.timestamp = LEASE_FREE;

	/* host_id N is block offset N-1 */

	for (i = 0; i < max_hosts; i++) {
		memset(leader.resource_name, 0, NAME_ID_SIZE);
		snprintf(leader.resource_name, NAME_ID_SIZE, "host_id_%d", i+1);
		leader.checksum = leader_checksum(&leader);

		rv = write_sector(disk, i, (char *)&leader,
				  sizeof(struct leader_record),
				  to.io_timeout_seconds, "host_id_leader");

		if (rv < 0) {
			log_error(NULL, "delta_lease_init write_sector %d rv %d", i, rv);
			return rv;
		}
	}

	return 0;
}

