/*
 * Copyright (c) 2019 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <inttypes.h>

#if HAVE_GETIFADDRS
#include <net/if.h>
#include <ifaddrs.h>
#endif

#include <ofi_util.h>

#include <rdma/fi_collective.h>
#include <rdma/fi_cm.h>
#include <ofi_list.h>

struct util_av_set_entry {
	fi_addr_t		fi_addr;
	struct slist_entry 	entry;
};

struct util_av_set {
	struct fid_av_set	av_set_fid;
	struct util_av		*av;
	struct slist		fi_addr_list;
	size_t			fi_addr_count;
	int 			my_fi_addr;
	void			*context;
	uint64_t		flags;
	ofi_atomic32_t		ref;
	fastlock_t		lock;
};

struct util_coll {
	struct fid_mc	mc_fid;
	struct util_av	*av;
	struct slist	plist;
};

struct av_to_fi_addr_list {
	fi_addr_t		*array;
	size_t 			count;
};

int ofi_av_set_union(struct fid_av_set *dst, const struct fid_av_set *src)
{
	return -FI_ENOSYS;
}

int ofi_av_set_intersect(struct fid_av_set *dst, const struct fid_av_set *src)
{
	return -FI_ENOSYS;
}

int ofi_av_set_diff(struct fid_av_set *dst, const struct fid_av_set *src)
{
	return -FI_ENOSYS;
}

int ofi_av_set_insert(struct fid_av_set *set, fi_addr_t addr)
{
	return -FI_ENOSYS;
}

int ofi_av_set_remove(struct fid_av_set *set, fi_addr_t addr)
{
	return -FI_ENOSYS;
}

int ofi_join_collective(struct fid_ep *ep, fi_addr_t coll_addr,
		       const struct fid_av_set *set,
		       uint64_t flags, struct fid_mc **mc, void *context)
{
	size_t addrlen = ;
	int ret;

	ret = fi_getname(ep, (void *)addr, &addrlen);
	if (ret)
		return ret;


	return -FI_ENOSYS;
}


static struct fi_ops_av_set util_av_set_ops= {
	.set_union	= 	ofi_av_set_union,
	.intersect	=	ofi_av_set_intersect,
	.diff		=	ofi_av_set_diff,
	.insert		=	ofi_av_set_insert,
	.remove		=	ofi_av_set_remove,
};

static int util_av_aggregator(struct util_av *av, void *addr,
			      fi_addr_t fi_addr, void *arg)
{
	struct av_to_fi_addr_list *addr_list;

	addr_list = (struct av_to_fi_addr_list *) arg;
	addr_list->array[addr_list->count] = fi_addr;
	addr_list->count++;
	return FI_SUCCESS;
}

int ofi_av_set(struct fid_av *av, struct fi_av_set_attr *attr,
	       struct fid_av_set **av_set_fid, void * context)
{
	struct util_av *util_av = container_of(av, struct util_av, av_fid);
	struct av_to_fi_addr_list addr_list;
	fi_addr_t mem[util_av->count];
	struct util_av_set *av_set;
	int ret, iter;

	addr_list.array = mem;
	addr_list.count = 0;

	ret = ofi_av_elements_iter(util_av, util_av_aggregator, (void *)&addr_list);
	if (ret)
		return ret;

	av_set = calloc(1,sizeof(*av_set));
	if (!av_set)
		return -FI_ENOMEM;

	ret = fastlock_init(&av_set->lock);
	if (ret)
		goto err1;

	av_set->fi_addr_array =
		calloc(attr->count, sizeof(*av_set->fi_addr_array));
	if (!av_set->fi_addr_array)
		goto err2;

	for (iter = 0; iter < attr->count; iter++) {
		av_set->fi_addr_array[iter] =
			addr_list.array[iter*attr->stride];
		av_set->fi_addr_count++;
	}

	(*av_set_fid) = &av_set->av_set_fid;
	(*av_set_fid)->ops = &util_av_set_ops;
	av_set->context = context;
	return FI_SUCCESS;
err2:
	fastlock_destroy(&av_set->lock);
err1:
	free(av_set);
	return ret;
}
