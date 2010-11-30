#ifndef __DELTA_LEASE_H__
#define __DELTA_LEASE_H__

int delta_lease_read_timestamp(struct sync_disk *disk, uint64_t host_id, uint64_t *timestamp);
int delta_lease_acquire(struct sync_disk *disk, uint64_t host_id);
int delta_lease_renew(struct sync_disk *disk, uint64_t host_id);
int delta_lease_release(struct sync_disk *disk, uint64_t host_id);
int delta_lease_init(struct sync_disk *disk, int num_hosts, int max_hosts);

#endif
