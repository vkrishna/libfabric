/*
 * Copyright (c) 2018 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *	   Redistribution and use in source and binary forms, with or
 *	   without modification, are permitted provided that the following
 *	   conditions are met:
 *
 *		- Redistributions of source code must retain the above
 *		  copyright notice, this list of conditions and the following
 *		  disclaimer.
 *
 *		- Redistributions in binary form must reproduce the above
 *		  copyright notice, this list of conditions and the following
 *		  disclaimer in the documentation and/or other materials
 *		  provided with the distribution.
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

#include <rdma/fi_errno.h>
#include "rdma/fi_eq.h"
#include "ofi_iov.h"
#include <ofi_prov.h>
#include "tcpx.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <ofi_util.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netdb.h>

static ssize_t tcpx_rma_common(struct fid_ep *ep, const struct fi_msg_rma *msg,
		uint64_t flags, uint8_t op)
{
	struct tcpx_ep *tcpx_ep;
	struct tcpx_cq *tcpx_cq;
	struct tcpx_pe_entry *send_entry;
	uint64_t data_len;

	tcpx_ep = container_of(ep, struct tcpx_ep, util_ep.ep_fid);
	tcpx_cq = container_of(tcpx_ep->util_ep.tx_cq, struct tcpx_cq,
			       util_cq);

	send_entry = tcpx_pe_entry_alloc(tcpx_cq);
	if (!send_entry)
		return -FI_EAGAIN;

	assert(msg->iov_count <= TCPX_IOV_LIMIT);

	data_len = ofi_total_iov_len(msg->msg_iov, msg->iov_count);

	if (flags & FI_INJECT)
		assert(data_len <= TCPX_MAX_INJECT_SZ);

	send_entry->msg_hdr.version = OFI_CTRL_VERSION;
	send_entry->msg_hdr.op = op;
	send_entry->msg_hdr.size = htonll(data_len + sizeof(send_entry->msg_hdr));

	/* header */
	send_entry->msg_data.iov[0].iov_base = (void *) &send_entry->msg_hdr;
	send_entry->msg_data.iov[0].iov_len = sizeof(send_entry->msg_hdr);

	/* remote iov  */
	assert(msg->rma_iov_cnt < TCPX_IOV_LIMIT);
	send_entry->msg_data.iov[1].iov_base = (void *) &send_entry->msg_data.rma_data;
	send_entry->msg_data.iov[1].iov_len = sizeof(send_entry->msg_data.rma_data);

	send_entry->msg_data.iov_cnt = msg->iov_count + 2;

	if (flags & FI_INJECT) {
		ofi_copy_iov_buf(msg->msg_iov, msg->iov_count, 0,
				 send_entry->msg_data.inject,
				 data_len,
				 OFI_COPY_IOV_TO_BUF);

		send_entry->msg_data.iov[2].iov_base = (void *)send_entry->msg_data.inject;
		send_entry->msg_data.iov[2].iov_len = data_len;
		send_entry->msg_data.iov_cnt = 3;
	} else {
		memcpy(&send_entry->msg_data.iov[2], &msg->msg_iov[0],
		       msg->iov_count * sizeof(struct iovec));
	}

	if (flags & FI_REMOTE_CQ_DATA) {
		send_entry->msg_hdr.flags |= OFI_REMOTE_CQ_DATA;
		send_entry->msg_hdr.data = htonll(msg->data);
	}

	send_entry->msg_hdr.flags = htonl(send_entry->msg_hdr.flags);
	send_entry->ep = tcpx_ep;
	send_entry->context = msg->context;
	send_entry->done_len = 0;

	dlist_insert_tail(&send_entry->entry, &tcpx_ep->tx_queue);
	return FI_SUCCESS;
}

static ssize_t tcpx_rma_readmsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
		uint64_t flags)
{
	struct tcpx_ep *tcpx_ep;
	struct tcpx_cq *tcpx_cq;
	struct tcpx_pe_entry *send_entry;
	struct tcpx_pe_entry *recv_entry;
	uint64_t data_len;

	tcpx_ep = container_of(ep, struct tcpx_ep, util_ep.ep_fid);
	tcpx_cq = container_of(tcpx_ep->util_ep.tx_cq, struct tcpx_cq,
			       util_cq);

	send_entry = tcpx_pe_entry_alloc(tcpx_cq);
	if (!send_entry)
		return -FI_EAGAIN;

	recv_entry = tcpx_pe_entry_alloc(tcpx_cq);
	if (!recv_entry) {
		tcpx_pe_entry_release(send_entry);
		return -FI_EAGAIN;
	}

	assert(msg->iov_count <= TCPX_IOV_LIMIT);

	data_len = ofi_total_iov_len(msg->msg_iov, msg->iov_count);

	if (flags & FI_INJECT)
		assert(data_len <= TCPX_MAX_INJECT_SZ);

	send_entry->msg_hdr.version = OFI_CTRL_VERSION;
	send_entry->msg_hdr.op = ofi_op_read_req;
	send_entry->msg_hdr.size = htonll(data_len + sizeof(send_entry->msg_hdr));

	/* header */
	send_entry->msg_data.iov[0].iov_base = (void *) &send_entry->msg_hdr;
	send_entry->msg_data.iov[0].iov_len = sizeof(send_entry->msg_hdr);

	/* remote iov  */
	assert(msg->rma_iov_cnt < TCPX_IOV_LIMIT);
	send_entry->msg_data.iov[1].iov_base = (void *) &send_entry->msg_data.rma_data;
	send_entry->msg_data.iov[1].iov_len = sizeof(send_entry->msg_data.rma_data);

	send_entry->msg_data.iov_cnt = msg->iov_count + 2;

	if (flags & FI_INJECT) {
		ofi_copy_iov_buf(msg->msg_iov, msg->iov_count, 0,
				 send_entry->msg_data.inject,
				 data_len,
				 OFI_COPY_IOV_TO_BUF);

		send_entry->msg_data.iov[2].iov_base = (void *)send_entry->msg_data.inject;
		send_entry->msg_data.iov[2].iov_len = data_len;
		send_entry->msg_data.iov_cnt = 3;
	} else {
		memcpy(&send_entry->msg_data.iov[2], &msg->msg_iov[0],
		       msg->iov_count * sizeof(struct iovec));
	}

	if (flags & FI_REMOTE_CQ_DATA) {
		send_entry->msg_hdr.flags |= OFI_REMOTE_CQ_DATA;
		send_entry->msg_hdr.data = htonll(msg->data);
	}

	send_entry->msg_hdr.flags = htonl(send_entry->msg_hdr.flags);
	send_entry->ep = tcpx_ep;
	send_entry->context = msg->context;
	send_entry->done_len = 0;

	dlist_insert_tail(&send_entry->entry, &tcpx_ep->tx_queue);
	return FI_SUCCESS;
}

static ssize_t tcpx_rma_read(struct fid_ep *ep, void *buf, size_t len, void *desc,
		fi_addr_t src_addr, uint64_t addr, uint64_t key, void *context)
{
	struct iovec msg_iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.key = key,
		.len = len,
	};
	struct fi_msg_rma msg = {
		.msg_iov = &msg_iov,
		.desc = &desc,
		.iov_count = 1,
		.rma_iov_count = 1,
		.rma_iov = &rma_iov,
		.addr = src_addr,
		.context = context,
		.data = 0,
	};

	return tcpx_rma_readmsg(ep, &msg, 0);
}

static ssize_t tcpx_rma_readv(struct fid_ep *ep, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t src_addr, uint64_t addr, uint64_t key,
		void *context)
{
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.len = ofi_total_iov_len(iov, count),
		.key = key,
	};
	struct fi_msg_rma msg = {
		.msg_iov = iov,
		.desc = desc,
		.iov_count = count,
		.rma_iov_count = 1,
		.rma_iov = &rma_iov,
		.addr = src_addr,
		.context = context,
		.data = 0,
	};

	return tcpx_rma_readmsg(ep, &msg, 0);
}

static ssize_t tcpx_rma_writemsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
		uint64_t flags)
{
	return tcpx_rma_common(ep, msg, flags, ofi_op_write);
}

static ssize_t tcpx_rma_write(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
	struct iovec msg_iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.key = key,
		.len = len,
	};
	struct fi_msg_rma msg = {
		.msg_iov = &msg_iov,
		.desc = &desc,
		.iov_count = 1,
		.rma_iov_count = 1,
		.rma_iov = &rma_iov,
		.addr = dest_addr,
		.context = context,
		.data = 0,
	};

	return tcpx_rma_writemsg(ep, &msg, 0);
}

static ssize_t tcpx_rma_writev(struct fid_ep *ep, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		void *context)
{
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.key = key,
		.len = ofi_total_iov_len(iov, count),
	};
	struct fi_msg_rma msg = {
		.msg_iov = iov,
		.desc = desc,
		.iov_count = count,
		.rma_iov_count = 1,
		.rma_iov = &rma_iov,
		.addr = dest_addr,
		.context = context,
		.data = 0,
	};

	return tcpx_rma_writemsg(ep, &msg, 0);
}


static ssize_t tcpx_rma_writedata(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		uint64_t data, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		void *context)
{
	struct iovec msg_iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.key = key,
		.len = len,
	};
	struct fi_msg_rma msg = {
		.desc = &desc,
		.iov_count = 1,
		.rma_iov_count = 1,
		.rma_iov = &rma_iov,
		.msg_iov = &msg_iov,
		.addr = dest_addr,
		.context = context,
		.data = data,
	};

	return tcpx_rma_writemsg(ep, &msg, FI_REMOTE_CQ_DATA);
}

static ssize_t tcpx_rma_inject(struct fid_ep *ep, const void *buf, size_t len,
		fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	struct iovec msg_iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.key = key,
		.len = len,
	};
	struct fi_msg_rma msg = {
		.iov_count = 1,
		.rma_iov_count = 1,
		.rma_iov = &rma_iov,
		.msg_iov = &msg_iov,
		.desc = NULL,
		.addr = dest_addr,
		.context = NULL,
		.data = 0,
	};

	return tcpx_rma_writemsg(ep, &msg, FI_INJECT | TCPX_NO_COMPLETION);
}

static ssize_t tcpx_rma_injectdata(struct fid_ep *ep, const void *buf, size_t len,
		uint64_t data, fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	struct iovec msg_iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct fi_rma_iov rma_iov = {
		.addr = addr,
		.key = key,
		.len = len,
	};
	struct fi_msg_rma msg = {
		.iov_count = 1,
		.rma_iov_count = 1,
		.rma_iov = &rma_iov,
		.msg_iov = &msg_iov,
		.desc = NULL,
		.addr = dest_addr,
		.context = NULL,
		.data = data,
	};

	return tcpx_rma_writemsg(ep, &msg, FI_INJECT | FI_REMOTE_CQ_DATA |
				 TCPX_NO_COMPLETION );
}

struct fi_ops_rma tcpx_rma_ops = {
	.size = sizeof(struct fi_ops_rma),
	.read = tcpx_rma_read,
	.readv = tcpx_rma_readv,
	.readmsg = tcpx_rma_readmsg,
	.write = tcpx_rma_write,
	.writev = tcpx_rma_writev,
	.writemsg = tcpx_rma_writemsg,
	.inject = tcpx_rma_inject,
	.writedata = tcpx_rma_writedata,
	.injectdata = tcpx_rma_injectdata,
};
