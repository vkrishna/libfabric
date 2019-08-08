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
#include <ofi_coll.h>

uint64_t context_id;

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
	int ret;

	/* if (coll_addr == FI_ADDR_UNAVAIL) { */
	/* 	set->av->av_set */
	/* } else { */
	/* 	ret = fi_allgather(ep, buf, count, desc, result, result_desc, */
	/* 			   coll_addr, FI_UINT64, flags, context); */
	/* } */
	/* if coll_addr_is_valid */
	/* 	call allreduce to get context id on all processes in av */
	/* else */
	/* 	call allreduce on all the fi_addrs corresponding to coll_addr */


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

ssize_t util_coll_handle_comp(struct fid_ep *ep,
			      struct fi_cq_data_entry *comp)
{
	return -FI_ENOSYS;
}

ssize_t	ofi_ep_barrier(struct fid_ep *ep, fi_addr_t coll_addr, void *context)
{
	struct util_coll_mc *coll_mc = (struct util_coll_mc *) coll_addr;
	fi_addr_t my_fi_addr;
	fi_addr_t target_addr;
	fi_addr_t source_addr;
	struct fi_msg_tagged msg;

	assert(ep == coll_mc->ep);
	my_fi_addr = coll_mc->member_array[coll_mc->my_id];

	source_addr = coll_mc->member_array[coll_mc->num_members - 1];
	fi_trecv(ep, );
	coll_mc->state = BARRIER_INIT;

	if (!coll_mc->my_id) {
		target_addr = coll_mc->member_array[(coll_mc->my_id + 1) %
						    coll_mc->num_members];
		fi_tsend();
	}

	return -FI_ENOSYS;
}

ssize_t	ofi_ep_writeread(struct fid_ep *ep, const void *buf, size_t count,
		     void *desc, void *result, void *result_desc,
		     fi_addr_t coll_addr, enum fi_datatype datatype,
		     enum fi_op op, uint64_t flags, void *context)
{
	return -FI_ENOSYS;
}


ssize_t ofi_ep_writereadmsg(struct fid_ep *ep, const struct fi_msg_collective *msg,
			struct fi_ioc *resultv, void **result_desc,
			size_t result_count, uint64_t flags)
{
	return -FI_ENOSYS;
}
