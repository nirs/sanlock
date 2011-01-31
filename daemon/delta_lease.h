#ifndef __DELTA_LEASE_H__
#define __DELTA_LEASE_H__

int delta_lease_leader_read(struct sync_disk *disk, char *space_name,
			    uint64_t host_id, struct leader_record *leader_ret);
int delta_lease_acquire(struct space *sp, struct sync_disk *disk, char *space_name,
			uint64_t our_host_id, uint64_t host_id,
			struct leader_record *leader_ret);
int delta_lease_renew(struct space *sp, struct sync_disk *disk, char *space_name,
		      uint64_t our_host_id, uint64_t host_id,
		      struct leader_record *leader_ret);
int delta_lease_release(struct space *sp, struct sync_disk *disk, char *space_name,
			uint64_t host_id,
			struct leader_record *leader_last,
			struct leader_record *leader_ret);
int delta_lease_init(struct sync_disk *disk, char *space_name, int max_hosts);

#endif
