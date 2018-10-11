/*
 * Copyright 2018 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __SIZES_H__
#define __SIZES_H__

#define ALIGN_SIZE_1M 1048576
#define ALIGN_SIZE_2M (2 * ALIGN_SIZE_1M)
#define ALIGN_SIZE_4M (4 * ALIGN_SIZE_1M)
#define ALIGN_SIZE_8M (8 * ALIGN_SIZE_1M)

int size_to_max_hosts(int sector_size, int align_size);
int sector_size_to_align_size_old(int sector_size);
const char *align_size_debug_str(int align_size);

uint32_t leader_align_flag_from_size(int align_size);
int leader_align_size_from_flag(uint32_t flags);

uint32_t rindex_header_align_flag_from_size(int align_size);
int rindex_header_align_size_from_flag(uint32_t flags);

int sanlk_lsf_sector_flag_to_size(uint32_t flags);
uint32_t sanlk_lsf_sector_size_to_flag(int sector_size);
int sanlk_lsf_align_flag_to_size(uint32_t flags);
uint32_t sanlk_lsf_align_size_to_flag(int align_size);

int sanlk_res_sector_flag_to_size(uint32_t flags);
uint32_t sanlk_res_sector_size_to_flag(int sector_size);
int sanlk_res_align_flag_to_size(uint32_t flags);
uint32_t sanlk_res_align_size_to_flag(int align_size);

int sanlk_rif_sector_flag_to_size(uint32_t flags);
uint32_t sanlk_rif_sector_size_to_flag(int sector_size);
int sanlk_rif_align_flag_to_size(uint32_t flags);
uint32_t sanlk_rif_align_size_to_flag(int align_size);

int sizes_from_flags(uint32_t flags, int *sector_size, int *align_size, int *max_hosts, const char *kind);

#endif
