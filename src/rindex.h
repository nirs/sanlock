/*
 * Copyright 2018 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __RINDEX_H__
#define __RINDEX_H__

int rindex_format(struct task *task, struct sanlk_rindex *ri);
int rindex_rebuild(struct task *task, struct sanlk_rindex *ri, uint32_t cmd_flags);

int rindex_lookup(struct task *task, struct sanlk_rindex *ri,
                  struct sanlk_rentry *re, struct sanlk_rentry *re_ret, uint32_t cmd_flags);
int rindex_update(struct task *task, struct sanlk_rindex *ri,
                  struct sanlk_rentry *re, struct sanlk_rentry *re_ret, uint32_t cmd_flags);

int rindex_create(struct task *task, struct sanlk_rindex *ri,
                  struct sanlk_rentry *re, struct sanlk_rentry *re_ret,
		  uint32_t num_hosts, uint32_t max_hosts);
int rindex_delete(struct task *task, struct sanlk_rindex *ri,
                  struct sanlk_rentry *re, struct sanlk_rentry *re_ret);
#endif
