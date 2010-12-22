#ifndef __SANLOCK_H__
#define __SANLOCK_H__

/* pid can own this many resources at once */

#define SANLK_MAX_RESOURCES	8

/* max resource name length */

#define SANLK_NAME_LEN		48   

/* max disk path length */

#define SANLK_PATH_LEN		1024

/* disk offset units */

#define SANLK_UNITS_BYTES	0
#define SANLK_UNITS_SECTORS	1
#define SANLK_UNITS_KB		2
#define SANLK_UNITS_MB		3

struct sanlk_disk {
	char path[SANLK_PATH_LEN]; /* must include terminating \0 */
	uint64_t offset;
	uint32_t units;
	uint32_t pad1;
	uint32_t pad2;
};

struct sanlk_resource {
	char name[SANLK_NAME_LEN]; /* terminating \0 not required */
	uint32_t num_disks;
	uint32_t data32;   /* per-resource command-specific data */
	uint64_t data64;   /* per-resource command-specific data */
	/* followed by num_disks sanlk_disk structs */
	struct sanlk_disk disks[0];
};

/* command-specific command options (can include per resource data, but
   that requires the extra work of segmenting it by resource name) */

#define SANLK_FLG_REACQUIRE	0x1
#define SANLK_FLG_INCOMING	0x2
#define SANLK_FLG_NUM_HOSTS	0x4

struct sanlk_options {
	char owner_name[SANLK_NAME_LEN]; /* optional user friendly name */
	uint32_t flags;
	uint32_t len;
	/* followed by len bytes (migration input will use this) */
	char str[0];
};

#endif

