#ifndef __DISK_PAXOS_H__
#define __DISK_PAXOS_H__

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

/* for all disk structures:
   uint64 aligned on 8 byte boundaries,
   uint32 aligned on 4 byte boundaries, etc */

/* NB. adjust LEADER_COMPARE_LEN and LEADER_CHECKSUM_LEN when changing
   this struct.
   LEADER_CHECKSUM_LEN should end just before the checksum field.
   LEADER_COMPARE_LEN should end just before timestamp.
   The checksum field should follow the timestamp field.
   The leader may be partially through updating the timestamp on
   multiple leader blocks in a lease, but for the purpose of counting
   repetitions of a leader block owned by a single host they should be
   counted together, so COMPARE_LEN should exclude timestamp. */

#define LEADER_COMPARE_LEN 96
#define LEADER_CHECKSUM_LEN 104

struct leader_record {
	uint32_t magic;
	uint32_t version;
	uint32_t cluster_mode;
	uint32_t sector_size;
	uint64_t num_hosts;
	uint64_t max_hosts;
	uint64_t owner_id; /* host_id of owner */
	uint64_t lver;
	char resource_name[NAME_ID_SIZE]; /* resource being locked */
	uint64_t timestamp;
	uint32_t checksum;
	uint32_t pad2;
};

struct request_record {
	uint64_t lver;
	uint8_t force_mode;
};

/* ref: ballot_ticket_record */
struct paxos_dblock {
	uint64_t mbal; /* aka curr_bal */
	uint64_t bal;  /* aka inp_bal */
	uint64_t inp;  /* aka inp_val */
	uint64_t lver; /* leader version */
};

/* Once token and token->disks are initialized by the main loop, the only
   fields that are modified are disk fd's by open_disks() in the lease
   threads. */

struct token {
	int idx;
	int token_id;
	int num_disks;
	int acquire_result;
	int keep_resource;
	int reacquire;
	uint64_t prev_lver;
	struct sync_disk *disks;
	struct leader_record leader;
	char resource_name[NAME_ID_SIZE];
};

int majority_disks(struct token *token, int num);
int disk_paxos_acquire(struct token *token, int force,
		       struct leader_record *leader_ret,
		       uint64_t reacquire_lver);
int disk_paxos_renew(struct token *token,
		     struct leader_record *leader_last,
		     struct leader_record *leader_ret);
int disk_paxos_transfer(struct token *token, int hostid,
			struct leader_record *leader_last,
			struct leader_record *leader_ret);
int disk_paxos_release(struct token *token,
		       struct leader_record *leader_last,
		       struct leader_record *leader_ret);
int disk_paxos_init(struct token *token, int num_hosts, int max_hosts);

#endif
