#define MAX_DISKS 128

#define MAX_PATH_LEN 1024

#define MAX_HOSTS 254 /* host id's 1-254 */

#define TOKEN_NAME_SIZE 32

/* TODO: add useful error codes to return from disk paxos code */
enum {
	DP_ERROR = -1,
	DP_NONE = 0,	/* unused */
	DP_OK = 1,
};

/* paxos_disk + offset:
   points to 1 leader_record + 1 request_record + MAX_HOSTS paxos_dblock's =
   256 blocks = 128KB, ref: lease_item_record */

struct paxos_disk {
	int fd;
	uint64_t offset;
	char path[MAX_PATH_LEN];
};

struct token {
	char name[TOKEN_NAME_SIZE];
	uint32_t type;
	int num_disks;
	struct paxos_disk *disks;
};

/* for all disk structures:
   uint64 aligned on 8 byte boundaries,
   uint32 aligned on 4 byte boundaries, etc */

struct leader_record {
	uint64_t owner_id; /* host_id of owner, host_id's are 1-255 */
	uint64_t lver;
	uint64_t num_hosts;
	uint64_t num_alloc_slots; /* what's this? */
	uint32_t cluster_mode; /* what's this? */
	uint32_t version; /* what's this? */
	uint32_t pad1;
	uint32_t token_type;
	char token_name[TOKEN_NAME_SIZE]; /* object being locked */
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
int disk_paxos_renew(struct token *token, struct leader_record *leader_ret);
int disk_paxos_release(struct token *token, struct leader_record *leader_ret);
int disk_paxos_transfer(struct token *token, uint64_t hostid,
			struct leader_record *leader_ret);

