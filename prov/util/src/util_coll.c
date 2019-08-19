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

static inline void util_coll_init_context_id()
{
	int i;

	for (i = 0; i < OFI_CONTEXT_ID_SIZE; i++) {
		util_coll_context_id[i] = -1;
	}
}

static inline int util_coll_mc_alloc(struct util_coll_mc **coll_mc)
{

	*coll_mc = calloc(1, sizeof(**coll_mc));
	if (!*coll_mc)
		return -FI_ENOMEM;

	slist_init((*coll_mc)->pend_work_list);
	slist_init((*coll_mc)->work_list);
	return FI_SUCCESS;
}

static inline int util_coll_pof2(int num)
{
	int pof2 = 1;

	while (pof2 <= num)
		pof2 <<= 1;

	return (pof2 >> 1);
}

static int util_coll_sched_send(struct util_coll_mc *coll_mc, int dest, void *buf,
				int count, enum fi_datatype datatype)
{
	struct util_coll_xfer_item *xfer_item;

	xfer_item = calloc(1, sizeof(*xfer_item));
	if (!xfer_item)
		return -FI_ENOMEM;

	xfer_item->type = UTIL_COLL_SEND;
	xfer_item->buf = buf;
	xfer_item->count = count;
	xfer_item->datatype = datatype;

	slist_insert_tail(&xfer_item->entry, &coll_mc->work_list);
	return FI_SUCCESS;
}

static int util_coll_sched_recv(struct util_coll_mc *coll_mc, int src, void *buf,
				int count, enum fi_datatype datatype)
{
	struct util_coll_xfer_item *xfer_item;

	xfer_item = calloc(1, sizeof(*xfer_item));
	if (!xfer_item)
		return -FI_ENOMEM;

	xfer_item->type = UTIL_COLL_RECV;
	xfer_item->buf = buf;
	xfer_item->count = count;
	xfer_item->datatype = datatype;

	slist_insert_tail(&xfer_item->entry, &coll_mc->work_list);
	return FI_SUCCESS;
}

static int util_coll_sched_reduce(struct util_coll_mc *coll_mc, void *in_buf,
				  void *inout_buf, int count,
				  enum fi_datatype datatype, enum fi_op op)
{
	struct util_coll_reduce_item *xfer_item;

	xfer_item = calloc(1, sizeof(*xfer_item));
	if (!xfer_item)
		return -FI_ENOMEM;

	xfer_item->type = UTIL_COLL_REDUCE;
	xfer_item->in_buf = in_buf;
	xfer_item->inout_buf = inout_buf;
	xfer_item->count = count;
	xfer_item->datatype = datatype;
	xfer_item->op = op;

	slist_insert_tail(&xfer_item->entry, &coll_mc->work_list);
	return FI_SUCCESS;
}

static int util_coll_sched_copy(struct util_coll_mc *coll_mc, void *in_buf,
				int in_count,enum fi_datatype in_datatype,
				void *out_buf, int out_count,
				enum fi_datatype out_datatype)
{
	struct util_coll_reduce_item *xfer_item;

	xfer_item = calloc(1, sizeof(*xfer_item));
	if (!xfer_item)
		return -FI_ENOMEM;

	xfer_item->type = UTIL_COLL_COPY;
	xfer_item->in_buf = in_buf;
	xfer_item->in_count = in_count;
	xfer_item->in_datatype = in_datatype;
	xfer_item->out_buf = out_buf;
	xfer_item->out_count = out_count;
	xfer_item->out_datatype = out_datatype;

	slist_insert_tail(&xfer_item->entry, &coll_mc->work_list);
	return FI_SUCCESS;


	return FI_SUCCESS;
}

int ofi_join_collective(struct fid_ep *ep, fi_addr_t coll_addr,
		       const struct fid_av_set *set,
		       uint64_t flags, struct fid_mc **mc, void *context)
{
	struct util_coll_mc *coll_mc;
	struct util_av_set *av_set;
	uint64_t tmp_buf[OFI_CONTEXT_ID_SIZE];
	int ret, rem, pof2, my_new_id;
	int dest, new_dest;
	int mask = 1;

	av_set = container_of(set, struct util_av_set, av_set_fid);

	ret = util_coll_mc_alloc(&coll_mc);
	if (ret)
		return ret;

	if (util_coll_cid_initialized == FALSE) {
		util_coll_init_context_id();
		util_coll_cid_initialized = TRUE;
	}

	coll_mc->mc_fid.fi_addr = coll_mc;
	coll_mc->member_array = av_set->fi_addr_array;
	coll_mc->num_members = av_set->fi_addr_count;
	coll_mc->my_id = av_set->my_rank;

	pof2 = util_coll_pof2(coll_mc->num_members);
	rem = coll_mc->num_members - pof2;

	if (coll_mc->my_id < 2 * rem) {
		if (coll_mc->my_id % 2 == 0) {
			util_coll_sched_send(coll_mc, util_coll_context_id,
					     coll_mc->my_id + 1,
					     OFI_CONTEXT_ID_SIZE, FI_INT64);
			my_new_id = -1;
		} else {
			util_coll_sched_recv(coll_mc, tmp_buf, coll_mc->my_id - 1,
					     OFI_CONTEXT_ID_SIZE, FI_INT64);
			my_new_id /= 2;

			util_coll_sched_reduce(coll_mc, tmp_buf, util_coll_context_id,
					       OFI_CONTEXT_ID_SIZE, FI_INT64, FI_BAND);
		}
	} else {
		my_new_id = coll_mc->my_id;
	}

	if (my_new_id != -1) {
		while (mask < pof2) {
			new_dest = my_new_id ^ mask;
			dest = (new_dest < rem) ? new_dest * 2 + 1 :
				new_dest + rem;

			util_coll_sched_recv(coll_mc, dest, tmp_buf,
					     OFI_CONTEXT_ID_SIZE, FI_INT64);
			util_coll_sched_send(coll_mc, dest, util_coll_context_id,
					     OFI_CONTEXT_ID_SIZE, FI_INT64;)
			if (is_commutative || (dest < coll_mc->my_id)) {
				util_coll_sched_reduce(coll_mc, tmp_buf, util_coll_context_id,
						       OFI_CONTEXT_ID_SIZE, FI_INT64, FI_BAND);
			} else {
				util_coll_sched_reduce(coll_mc, util_coll_context_id, tmp_buf,
						       OFI_CONTEXT_ID_SIZE, FI_INT64, FI_BAND);
				util_coll_sched_copy(coll_mc, util_coll_context_id,
						     OFI_CONTEXT_ID_SIZE, FI_INT64,
						     tmp_buf, OFI_CONTEXT_ID_SIZE, FI_INT64);
			}
			mask <<= 1;
		}
	}

	if (coll_mc->my_id < 2 * rem) {
		if (coll_mc->my_id % 2) {
			util_coll_sched_send(coll_mc, util_coll_context_id,
					     coll_mc->my_id - 1,
					     OFI_CONTEXT_ID_SIZE, FI_INT64);
		} else {
			util_coll_sched_recv(coll_mc, util_coll_context_id,
					     coll_mc->my_id + 1,
					     OFI_CONTEXT_ID_SIZE, FI_INT64);
		}
	}
	*mc = &coll_mc->mc_fid;
	return FI_SUCCESS;
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

	/* if (!av_set->av->av_set) */
	/* 	build_av_set(av); */

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

static int util_coll_process_work_items(struct util_coll_mc *coll_mc)
{
	struct util_coll_item *item;
	struct slist_entry *entry;
	int ret;

	while (!dlist_empty(&coll_mc->work_list)) {
		entry = slist_remove_head(coll_mc->pend_work_list);
		item = container_of(entry, struct util_coll_mc, entry);
		switch (item->type) {
		case UTIL_COLL_SEND:
			break;
		case UTIL_COLL_RECV:
			break;
		case UTIL_COLL_REDUCE:
			break;
		case UTIL_COLL_COPY:
			break;
		default:
			break;
		}

		if (item->is_barrier)
			break;
	}
	return FI_SUCCESS;
}

static int util_coll_schedule_start(struct util_coll_mc *coll_mc)
{
	int ret;

	if (dlist_empty(&coll_mc->pend_work_list)) {
		ret = util_coll_process_work_items(coll_mc);
		if (ret)
			return ret;
	}
	return FI_SUCCESS;
}

void util_coll_handle_comp(comp)
{
	int ret;

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
