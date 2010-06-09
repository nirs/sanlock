#ifndef __DISK_PAXOS_H__
#define __DISK_PAXOS_H__

enum {
	DP_OK = 1,
	DP_NONE = 0,	/* unused */
	DP_ERROR = -1,
	DP_INVAL = -2,
	DP_NOMEM = -3,
	DP_BAD_NUMHOSTS = -4,
	DP_BAD_NAME = -5,
	DP_LIVE_LEADER = -6,
	DP_DIFF_LEADERS = -7,
	DP_READ_LEADERS = -8,
	DP_OWN_DBLOCK = -9,
	DP_WRITE1_DBLOCKS = -10,
	DP_WRITE2_DBLOCKS = -11,
	DP_WRITE_REQUESTS = -12,
	DP_WRITE_LEADERS = -13,
	DP_READ1_MBAL = -14,
	DP_READ1_LVER = -15,
	DP_READ2_MBAL = -16,
	DP_READ2_LVER = -17,
	DP_READ1_DBLOCKS = -18,
	DP_READ2_DBLOCKS = -19,
};

/* paxos_disk + offset:
   points to 1 leader_record + 1 request_record + MAX_HOSTS paxos_dblock's =
   256 blocks = 128KB, ref: lease_item_record */

struct paxos_disk {
	int fd;
	uint64_t offset;
	char path[DISK_PATH_LEN];
};

/* Once token and token->disks are initialized by the main loop, the only
   fields that are modified are disk fd's by open_disks() in the lease
   threads. */

struct token {
	int num;
	int num_disks;
	uint32_t type;
	char name[NAME_ID_SIZE];
	struct paxos_disk *disks;
};

/* for all disk structures:
   uint64 aligned on 8 byte boundaries,
   uint32 aligned on 4 byte boundaries, etc */

struct leader_record {
	uint64_t owner_id; /* host_id of owner, host_id's are 1-255 */
	uint64_t lver;
	uint64_t num_hosts;
	uint64_t max_hosts;
	uint32_t cluster_mode; /* what's this? */
	uint32_t version;
	uint32_t pad1;
	uint32_t token_type;
	char token_name[NAME_ID_SIZE]; /* object being locked */
	uint64_t timestamp;
	uint32_t checksum; /* TODO */
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


int majority_disks(struct token *token, int num);
int disk_paxos_acquire(struct token *token, int force, 
		       struct leader_record *leader_ret);
int disk_paxos_renew(struct token *token,
		     struct leader_record *leader_last,
		     struct leader_record *leader_ret);
int disk_paxos_transfer(struct token *token, int hostid,
			struct leader_record *leader_last,
			struct leader_record *leader_ret);
int disk_paxos_release(struct token *token,
		       struct leader_record *leader_last,
		       struct leader_record *leader_ret);
int disk_paxos_init(struct token *token, int num_hosts);

#endif
