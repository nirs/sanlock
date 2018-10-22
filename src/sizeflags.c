/*
 * Copyright 2018 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

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
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <blkid/blkid.h>

#include "sanlock_internal.h"
#include "sanlock.h"
#include "sizeflags.h"
#include "log.h"

int size_to_max_hosts(int sector_size, int align_size)
{
	if ((align_size == ALIGN_SIZE_1M) && (sector_size == 512)) {
		return 2000;
	} else if ((align_size == ALIGN_SIZE_1M) && (sector_size == 4096)) {
		return 250;
	} else if ((align_size == ALIGN_SIZE_2M) && (sector_size == 4096)) {
		return 500;
	} else if ((align_size == ALIGN_SIZE_4M) && (sector_size == 4096)) {
		return 1000;
	} else if ((align_size == ALIGN_SIZE_8M) && (sector_size == 4096)) {
		return 2000;
	} else {
		return 0;
	}
}

/*
 * In previous versions, 512 always implied 1M, and 4K implied 8M.
 * We fall back to this if an align size flag is not set in the
 * leader record.
 */

int sector_size_to_align_size_old(int sector_size)
{
	if (sector_size == 512)
		return ALIGN_SIZE_1M;
	if (sector_size == 4096)
		return ALIGN_SIZE_8M;
	return -1;
}

const char *align_size_debug_str(int align_size)
{
	if (align_size == ALIGN_SIZE_1M)
		return "1M";
	if (align_size == ALIGN_SIZE_2M)
		return "2M";
	if (align_size == ALIGN_SIZE_4M)
		return "4M";
	if (align_size == ALIGN_SIZE_8M)
		return "8M";
	return NULL;
}

/*
 * struct leader_record
 */

uint32_t leader_align_flag_from_size(int align_size)
{
	if (align_size == ALIGN_SIZE_1M)
		return LFL_ALIGN_1M;
	if (align_size == ALIGN_SIZE_2M)
		return LFL_ALIGN_2M;
	if (align_size == ALIGN_SIZE_4M)
		return LFL_ALIGN_4M;
	if (align_size == ALIGN_SIZE_8M)
		return LFL_ALIGN_8M;
	log_error("leader_align_flag_from_num unknown %d", align_size);
	return 0;
}

int leader_align_size_from_flag(uint32_t flags)
{
	if (flags & LFL_ALIGN_1M)
		return ALIGN_SIZE_1M;
	if (flags & LFL_ALIGN_2M)
		return ALIGN_SIZE_2M;
	if (flags & LFL_ALIGN_4M)
		return ALIGN_SIZE_4M;
	if (flags & LFL_ALIGN_8M)
		return ALIGN_SIZE_8M;
	return 0;
}

/*
 * struct rindex_header
 */

uint32_t rindex_header_align_flag_from_size(int align_size)
{
	if (align_size == ALIGN_SIZE_1M)
		return RHF_ALIGN_1M;
	if (align_size == ALIGN_SIZE_2M)
		return RHF_ALIGN_2M;
	if (align_size == ALIGN_SIZE_4M)
		return RHF_ALIGN_4M;
	if (align_size == ALIGN_SIZE_8M)
		return RHF_ALIGN_8M;
	log_error("rindex_header_align_flag_from_size unknown %d", align_size);
	return 0;
}

int rindex_header_align_size_from_flag(uint32_t flags)
{
	if (flags & RHF_ALIGN_1M)
		return ALIGN_SIZE_1M;
	if (flags & RHF_ALIGN_2M)
		return ALIGN_SIZE_2M;
	if (flags & RHF_ALIGN_4M)
		return ALIGN_SIZE_4M;
	if (flags & RHF_ALIGN_8M)
		return ALIGN_SIZE_8M;
	return 0;
}

/*
 * struct sanlk_lockspace
 */

int sanlk_lsf_sector_flag_to_size(uint32_t flags)
{
	if (flags & SANLK_LSF_SECTOR512)
		return 512;
	if (flags & SANLK_LSF_SECTOR4K)
		return 4096;
	return 0;
}

uint32_t sanlk_lsf_sector_size_to_flag(int sector_size)
{
	if (sector_size == 512)
		return SANLK_LSF_SECTOR512;
	if (sector_size == 4096)
		return SANLK_LSF_SECTOR4K;
	log_error("sanlk_lsf_sector_size_to_flag invalid sector size %d", sector_size);
	return 0;
}

void sanlk_lsf_sector_flags_clear(uint32_t *flags)
{
	*flags &= ~SANLK_LSF_SECTOR512;
	*flags &= ~SANLK_LSF_SECTOR4K;
}

void sanlk_lsf_align_flags_clear(uint32_t *flags)
{
	*flags &= ~SANLK_LSF_ALIGN1M;
	*flags &= ~SANLK_LSF_ALIGN2M;
	*flags &= ~SANLK_LSF_ALIGN4M;
	*flags &= ~SANLK_LSF_ALIGN8M;
}

int sanlk_lsf_align_flag_to_size(uint32_t flags)
{
	if (flags & SANLK_LSF_ALIGN1M)
		return ALIGN_SIZE_1M;
	if (flags & SANLK_LSF_ALIGN2M)
		return ALIGN_SIZE_2M;
	if (flags & SANLK_LSF_ALIGN4M)
		return ALIGN_SIZE_4M;
	if (flags & SANLK_LSF_ALIGN8M)
		return ALIGN_SIZE_8M;
	return 0;
}

uint32_t sanlk_lsf_align_size_to_flag(int align_size)
{
	if (align_size == ALIGN_SIZE_1M)
		return SANLK_LSF_ALIGN1M;
	if (align_size == ALIGN_SIZE_2M)
		return SANLK_LSF_ALIGN2M;
	if (align_size == ALIGN_SIZE_4M)
		return SANLK_LSF_ALIGN4M;
	if (align_size == ALIGN_SIZE_8M)
		return SANLK_LSF_ALIGN8M;
	log_error("sanlk_lsf_align_size_to_flag invalid align size %d", align_size);
	return 0;
}

/*
 * struct sanlk_resource
 */

int sanlk_res_sector_flag_to_size(uint32_t flags)
{
	if (flags & SANLK_RES_SECTOR512)
		return 512;
	if (flags & SANLK_RES_SECTOR4K)
		return 4096;
	return 0;
}

uint32_t sanlk_res_sector_size_to_flag(int sector_size)
{
	if (sector_size == 512)
		return SANLK_RES_SECTOR512;
	if (sector_size == 4096)
		return SANLK_RES_SECTOR4K;
	log_error("sanlk_res_sector_size_to_flag invalid sector size %d", sector_size);
	return 0;
}

void sanlk_res_sector_flags_clear(uint32_t *flags)
{
	*flags &= ~SANLK_RES_SECTOR512;
	*flags &= ~SANLK_RES_SECTOR4K;
}

void sanlk_res_align_flags_clear(uint32_t *flags)
{
	*flags &= ~SANLK_RES_ALIGN1M;
	*flags &= ~SANLK_RES_ALIGN2M;
	*flags &= ~SANLK_RES_ALIGN4M;
	*flags &= ~SANLK_RES_ALIGN8M;
}

int sanlk_res_align_flag_to_size(uint32_t flags)
{
	if (flags & SANLK_RES_ALIGN1M)
		return ALIGN_SIZE_1M;
	if (flags & SANLK_RES_ALIGN2M)
		return ALIGN_SIZE_2M;
	if (flags & SANLK_RES_ALIGN4M)
		return ALIGN_SIZE_4M;
	if (flags & SANLK_RES_ALIGN8M)
		return ALIGN_SIZE_8M;
	return 0;
}

uint32_t sanlk_res_align_size_to_flag(int align_size)
{
	if (align_size == ALIGN_SIZE_1M)
		return SANLK_RES_ALIGN1M;
	if (align_size == ALIGN_SIZE_2M)
		return SANLK_RES_ALIGN2M;
	if (align_size == ALIGN_SIZE_4M)
		return SANLK_RES_ALIGN4M;
	if (align_size == ALIGN_SIZE_8M)
		return SANLK_RES_ALIGN8M;
	log_error("sanlk_res_align_size_to_flag invalid align size %d", align_size);
	return 0;
}

/*
 * struct sanlk_rindex
 */

int sanlk_rif_sector_flag_to_size(uint32_t flags)
{
	if (flags & SANLK_RIF_SECTOR512)
		return 512;
	if (flags & SANLK_RIF_SECTOR4K)
		return 4096;
	return 0;
}

uint32_t sanlk_rif_sector_size_to_flag(int sector_size)
{
	if (sector_size == 512)
		return SANLK_RIF_SECTOR512;
	if (sector_size == 4096)
		return SANLK_RIF_SECTOR4K;
	log_error("sanlk_rif_sector_size_to_flag invalid sector size %d", sector_size);
	return 0;
}

int sanlk_rif_align_flag_to_size(uint32_t flags)
{
	if (flags & SANLK_RIF_ALIGN1M)
		return ALIGN_SIZE_1M;
	if (flags & SANLK_RIF_ALIGN2M)
		return ALIGN_SIZE_2M;
	if (flags & SANLK_RIF_ALIGN4M)
		return ALIGN_SIZE_4M;
	if (flags & SANLK_RIF_ALIGN8M)
		return ALIGN_SIZE_8M;
	return 0;
}

uint32_t sanlk_rif_align_size_to_flag(int align_size)
{
	if (align_size == ALIGN_SIZE_1M)
		return SANLK_RIF_ALIGN1M;
	if (align_size == ALIGN_SIZE_2M)
		return SANLK_RIF_ALIGN2M;
	if (align_size == ALIGN_SIZE_4M)
		return SANLK_RIF_ALIGN4M;
	if (align_size == ALIGN_SIZE_8M)
		return SANLK_RIF_ALIGN8M;
	log_error("sanlk_rif_align_size_to_flag invalid align size %d", align_size);
	return 0;
}

/*
 * Translate struct flags passed from libsanlock to numbers.
 */

int sizes_from_flags(uint32_t flags, int *sector_size, int *align_size, int *max_hosts, const char *kind)
{
	int no_align_flag = 0;
	int no_sector_flag = 0;

	*sector_size = 0;
	*align_size = 0;
	*max_hosts = 0;

	/* SANLK_RES flags in sanlk_resource.flags */

	if (!strcmp(kind, "RES")) {
		*align_size = sanlk_res_align_flag_to_size(flags);
		if (!*align_size)
			no_align_flag = 1;

		*sector_size = sanlk_res_sector_flag_to_size(flags);
		if (!*sector_size)
			no_sector_flag = 1;
	}

	/* SANLK_LSF flags in sanlk_lockspace.flags */

	else if (!strcmp(kind, "LSF")) {
		*align_size = sanlk_lsf_align_flag_to_size(flags);
		if (!*align_size)
			no_align_flag = 1;

		*sector_size = sanlk_lsf_sector_flag_to_size(flags);
		if (!*sector_size)
			no_sector_flag = 1;
	}

	/* SANLK_RIF flags in sanlk_rindex.flags */

	else if (!strcmp(kind, "RIF")) {
		*align_size = sanlk_rif_align_flag_to_size(flags);
		if (!*align_size)
			no_align_flag = 1;

		*sector_size = sanlk_rif_sector_flag_to_size(flags);
		if (!*sector_size)
			no_sector_flag = 1;
	}
	
	else {
		log_error("unknown kind %s of flags %x", kind, flags);
		return -1;
	}

	if (no_sector_flag != no_align_flag) {
		log_error("ALIGN and SECTOR flags %s %x must both be set", kind, flags);
		return -1;
	}

	if (!*sector_size)
		return 0;

	*max_hosts = size_to_max_hosts(*sector_size, *align_size);
	if (!*max_hosts) {
		log_error("Invalid combination of ALIGN and SECTOR flags %s %x", kind, flags);
		return -1;
	}

	return 0;
}

