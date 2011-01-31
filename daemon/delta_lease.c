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

#include "sanlock_internal.h"
#include "diskio.h"
#include "log.h"
#include "paxos_lease.h"
#include "delta_lease.h"

/* Based on "Light-Weight Leases for Storage-Centric Coordination"
   by Gregory Chockler and Dahlia Malkhi */

/* delta_leases are a series max_hosts leader_records, one leader per sector,
   host N's delta_lease is the leader_record in sectors N-1 */

static int verify_leader(struct sync_disk *disk,
			 char *space_name,
			 char *resource_name,
			 struct leader_record *lr)
{
	uint32_t sum;

	if (lr->magic != DELTA_DISK_MAGIC) {
		log_error("verify_leader wrong magic %x %s",
			  lr->magic, disk->path);
		return DP_BAD_MAGIC;
	}

	if ((lr->version & 0xFFFF0000) != DELTA_DISK_VERSION_MAJOR) {
		log_error("verify_leader wrong version %x %s",
			  lr->version, disk->path);
		return DP_BAD_VERSION;
	}

	if (lr->cluster_mode != options.cluster_mode) {
		log_error("verify_leader wrong cluster mode %d %d %s",
			  lr->cluster_mode, options.cluster_mode, disk->path);
		return DP_BAD_CLUSTERMODE;
	}

	if (lr->sector_size != disk->sector_size) {
		log_error("verify_leader wrong sector size %d %d %s",
			  lr->sector_size, disk->sector_size, disk->path);
		return DP_BAD_SECTORSIZE;
	}

	if (strncmp(lr->space_name, space_name, NAME_ID_SIZE)) {
		log_error("verify_leader wrong space name %.48s %.48s %s",
			  lr->space_name, space_name, disk->path);
		return DP_BAD_LOCKSPACE;
	}

	if (strncmp(lr->resource_name, resource_name, NAME_ID_SIZE)) {
		log_error("verify_leader wrong resource name %.48s %.48s %s",
			  lr->resource_name, resource_name, disk->path);
		return DP_BAD_RESOURCEID;
	}

	sum = leader_checksum(lr);

	if (lr->checksum != sum) {
		log_error("verify_leader wrong checksum %x %x %s",
			  lr->checksum, sum, disk->path);
		return DP_BAD_CHECKSUM;
	}

	return DP_OK;
}

int delta_lease_leader_read(struct sync_disk *disk, char *space_name,
			    uint64_t host_id, struct leader_record *leader_ret)
{
	char resource_name[NAME_ID_SIZE];
	int rv, error;

	/* host_id N is block offset N-1 */

	rv = read_sectors(disk, host_id - 1, 1, (char *)leader_ret,
			  sizeof(struct leader_record),
			  to.io_timeout_seconds, options.use_aio, "delta_leader");
	if (rv < 0)
		return DP_READ_LEADERS;

	memset(resource_name, 0, NAME_ID_SIZE);
	snprintf(resource_name, NAME_ID_SIZE, "host_id_%llu",
		 (unsigned long long)host_id);

	error = verify_leader(disk, space_name, resource_name, leader_ret);

	return error;
}

int delta_lease_acquire(struct space *sp, struct sync_disk *disk,
			char *space_name,
			uint64_t our_host_id, uint64_t host_id,
			struct leader_record *leader_ret)
{
	struct leader_record leader;
	struct leader_record leader1;
	uint64_t new_ts;
	int error, delay, delta_delay;

	log_space(sp, "delta_acquire %llu begin", (unsigned long long)host_id);

	error = delta_lease_leader_read(disk, space_name, host_id, &leader);
	if (error < 0)
		return error;

 retry:
	if (leader.timestamp == LEASE_FREE)
		goto write_new;

	/* we need to ensure that a host_id cannot be acquired and released
	 * sooner than host_id_timeout_seconds because the change in host_id
	 * ownership affects the host_id "liveness" determination used by paxos
	 * leases, and the ownership of paxos leases cannot change until after
	 * host_id_timeout_seconds to ensure that the watchdog has fired.  So,
	 * I think we want the delay here to be the max of
	 * host_id_timeout_seconds and the D+6d delay.
	 *
	 * Per the algorithm in the paper, a delta lease can change ownership
	 * in the while loop below after the delta_delay of D+6d.  However,
	 * because we use the change of delta lease ownership to directly
	 * determine the change in paxos lease ownership, we need the delta
	 * delay to also meet the delay requirements of the paxos leases.
	 * The paxos leases cannot change ownership until a min of
	 * host_id_timeout_seconds to ensure the watchdog has fired.  So, the
	 * timeout we use here must be the max of the delta delay (D+6d) and
	 * paxos delay host_id_timeout_seconds, so that it covers the requirements
	 * of both paxos and delta algorithms. */

	delay = to.host_id_timeout_seconds; /* for paxos leases */
	delta_delay = to.host_id_renewal_seconds + (6 * to.io_timeout_seconds);
	if (delta_delay > delay)
		delay = delta_delay;

	while (1) {
		memcpy(&leader1, &leader, sizeof(struct leader_record));

		log_space(sp, "delta_acquire long sleep %d", delay);
		sleep(delay);

		error = delta_lease_leader_read(disk, space_name, host_id, &leader);
		if (error < 0)
			return error;

		if (!memcmp(&leader1, &leader, sizeof(struct leader_record)))
			break;

		if (leader.timestamp == LEASE_FREE)
			break;
	}

 write_new:
	new_ts = time(NULL);
	leader.timestamp = new_ts;
	leader.owner_id = our_host_id;
	leader.owner_generation++;
	leader.checksum = leader_checksum(&leader);

	log_space(sp, "delta_acquire write new %llu", (unsigned long long)new_ts);

	error = write_sector(disk, host_id - 1, (char *)&leader,
			     sizeof(struct leader_record),
			     to.io_timeout_seconds, options.use_aio, "delta_leader");
	if (error < 0)
		return error;

	delay = 2 * to.io_timeout_seconds;
	log_space(sp, "delta_acquire sleep 2d %d", delay);
	sleep(delay);

	error = delta_lease_leader_read(disk, space_name, host_id, &leader);
	if (error < 0)
		return error;

	if ((leader.timestamp != new_ts) || (leader.owner_id != our_host_id))
		goto retry;

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return DP_OK;
}

int delta_lease_renew(struct space *sp, struct sync_disk *disk,
		      char *space_name,
		      uint64_t our_host_id, uint64_t host_id,
		      struct leader_record *leader_ret)
{
	struct leader_record leader;
	uint64_t new_ts;
	int error, delay;

	log_space(sp, "delta_renew %llu begin", (unsigned long long)host_id);

	error = delta_lease_leader_read(disk, space_name, host_id, &leader);
	if (error < 0)
		return error;

	if (leader.owner_id != our_host_id)
		return DP_BAD_LEADER;

	new_ts = time(NULL);

	if (leader.timestamp >= new_ts) {
		log_erros(sp, "delta_renew timestamp too small");
	}

	leader.timestamp = new_ts;
	leader.checksum = leader_checksum(&leader);

	log_space(sp, "delta_renew write new %llu", (unsigned long long)new_ts);

	error = write_sector(disk, host_id - 1, (char *)&leader,
			     sizeof(struct leader_record),
			     to.io_timeout_seconds, options.use_aio, "delta_leader");
	if (error < 0)
		return error;

	delay = 2 * to.io_timeout_seconds;
	log_space(sp, "delta_renew sleep 2d %d", delay);
	sleep(delay);

	error = delta_lease_leader_read(disk, space_name, host_id, &leader);
	if (error < 0)
		return error;

	if ((leader.timestamp != new_ts) || (leader.owner_id != our_host_id))
		return DP_BAD_LEADER;

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return DP_OK;
}

int delta_lease_release(struct space *sp, struct sync_disk *disk,
			char *space_name GNUC_UNUSED,
			uint64_t host_id,
			struct leader_record *leader_last,
			struct leader_record *leader_ret)
{
	struct leader_record leader;
	int error;

	log_space(sp, "delta_release %llu begin", (unsigned long long)host_id);

	memcpy(&leader, leader_last, sizeof(struct leader_record));
	leader.timestamp = LEASE_FREE;
	leader.checksum = leader_checksum(&leader);

	error = write_sector(disk, host_id - 1, (char *)&leader,
			     sizeof(struct leader_record),
			     to.io_timeout_seconds, options.use_aio, "delta_leader");
	if (error < 0)
		return error;

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return DP_OK;
}

/* the host_id lease area begins disk->offset bytes from the start of
   block device disk->path */

int delta_lease_init(struct sync_disk *disk, char *space_name, int max_hosts)
{
	struct leader_record leader;
	int i, rv;
	uint64_t bb, be, sb, se;
	uint32_t ss;

	printf("initialize leases for host_id 1 - %d\n", max_hosts);
	printf("disk %s offset %llu/%llu sector_size %d\n",
	       disk->path,
	       (unsigned long long)disk->offset,
	       (unsigned long long)(disk->offset / disk->sector_size),
	       disk->sector_size);

	ss = disk->sector_size;
	bb = disk->offset;
	be = disk->offset + (disk->sector_size * max_hosts) - 1;
	sb = bb / ss;
	se = be / ss;

	printf("%llu/%llu - %llu/%llu len %llu/%llu\n",
	       (unsigned long long)bb,
	       (unsigned long long)sb,
	       (unsigned long long)be,
	       (unsigned long long)se,
	       (unsigned long long)be - bb + 1,
	       (unsigned long long)se - sb + 1);

	memset(&leader, 0, sizeof(struct leader_record));

	leader.magic = DELTA_DISK_MAGIC;
	leader.version = DELTA_DISK_VERSION_MAJOR | DELTA_DISK_VERSION_MINOR;
	leader.cluster_mode = options.cluster_mode;
	leader.sector_size = disk->sector_size;
	leader.max_hosts = 1;
	leader.timestamp = LEASE_FREE;
	strncpy(leader.space_name, space_name, NAME_ID_SIZE);

	/* host_id N is block offset N-1 */

	for (i = 0; i < max_hosts; i++) {
		memset(leader.resource_name, 0, NAME_ID_SIZE);
		snprintf(leader.resource_name, NAME_ID_SIZE, "host_id_%d", i+1);
		leader.checksum = leader_checksum(&leader);

		rv = write_sector(disk, i, (char *)&leader, sizeof(struct leader_record),
				  to.io_timeout_seconds, options.use_aio, "delta_leader");

		if (rv < 0) {
			log_tool("delta_init write_sector %d rv %d", i, rv);
			return rv;
		}
	}

	return 0;
}

