#ifndef __DELTA_LEASE_H__
#define __DELTA_LEASE_H__

int delta_lease_leader_read(struct sync_disk *disk, uint64_t host_id,
			    struct leader_record *leader_ret);
int delta_lease_acquire(struct sync_disk *disk, uint64_t host_id,
			struct leader_record *leader_ret);
int delta_lease_renew(struct sync_disk *disk, uint64_t host_id,
		      struct leader_record *leader_ret);
int delta_lease_release(struct sync_disk *disk, uint64_t host_id,
			struct leader_record *leader_last,
			struct leader_record *leader_ret);
int delta_lease_init(struct sync_disk *disk, int max_hosts);

#endif
