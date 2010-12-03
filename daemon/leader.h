#ifndef __LEADER_H__
#define __LEADER_H__

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
   counted together, so COMPARE_LEN should exclude timestamp.

   The leader may also be partially through updating next_owner_id on
   multiple leader blocks in a lease, but this potential inconsistency,
   like timestamp, should not factor against the repetition count. */

#define LEADER_COMPARE_LEN 96
#define LEADER_CHECKSUM_LEN 112
#define LEASE_FREE 0

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
	uint64_t next_owner_id;
	uint32_t checksum;
	uint32_t pad2;
};

/* Once token and token->disks are initialized by the main loop, the only
   fields that are modified are disk fd's by open_disks() in the lease
   threads. */

#define OPT_ACQUIRE_PREV 1
#define OPT_ACQUIRE_RECV 2

struct token {
	int cmd_option;
	int token_id;
	int num_disks;
	int acquire_result;
	int migrate_result;
	int release_result;
	int setowner_result;
	uint64_t prev_lver;
	struct leader_record leader; /* copy of last leader_record we wrote */
	char resource_name[NAME_ID_SIZE];
	struct sync_disk *disks;
};

#endif
