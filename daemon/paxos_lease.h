#ifndef __PAXOS_LEASE_H__
#define __PAXOS_LEASE_H__

enum {
	DP_OK = 1,
	DP_NONE = 0,	/* unused */
	DP_ERROR = -1,
	DP_INVAL = -2,
	DP_NOMEM = -3,
	DP_LIVE_LEADER = -4,
	DP_DIFF_LEADERS = -5,
	DP_READ_LEADERS = -6,
	DP_OWN_DBLOCK = -7,
	DP_WRITE1_DBLOCKS = -8,
	DP_WRITE2_DBLOCKS = -9,
	DP_WRITE_REQUESTS = -10,
	DP_WRITE_LEADERS = -11,
	DP_READ1_MBAL = -12,
	DP_READ1_LVER = -13,
	DP_READ2_MBAL = -14,
	DP_READ2_LVER = -15,
	DP_READ1_DBLOCKS = -16,
	DP_READ2_DBLOCKS = -17,
	DP_BAD_MAGIC = -18,
	DP_BAD_VERSION = -19,
	DP_BAD_CLUSTERMODE = -20,
	DP_BAD_RESOURCEID = -21,
	DP_BAD_NUMHOSTS = -22,
	DP_BAD_CHECKSUM = -23,
	DP_BAD_LEADER = -24,
	DP_OTHER_INP = -25,
	DP_BAD_SECTORSIZE = -26,
	DP_REACQUIRE_LVER = -27,
};

uint32_t leader_checksum(struct leader_record *lr);
int majority_disks(struct token *token, int num);
int paxos_lease_leader_read(struct token *token, struct leader_record *leader_ret);
int paxos_lease_acquire(struct token *token, int force,
		        struct leader_record *leader_ret,
		        uint64_t reacquire_lver);
int paxos_lease_migrate(struct token *token,
                        struct leader_record *leader_last,
                        struct leader_record *leader_ret,
                        uint64_t target_host_id);
int paxos_lease_release(struct token *token,
		        struct leader_record *leader_last,
		        struct leader_record *leader_ret);
int paxos_lease_init(struct token *token, int num_hosts, int max_hosts);

#endif
