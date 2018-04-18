/*
 * Copyright (c) 2017 Intel Corporation. All rights reserved.
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
#include <ofi_prov.h>
#include <sys/types.h>
#include <ofi_util.h>
#include <ofi_iov.h>
#include "tcpx.h"

int tcpx_send_msg(struct tcpx_pe_entry *pe_entry)
{
	ssize_t bytes_sent;

	bytes_sent = ofi_writev_socket(pe_entry->ep->conn_fd,
				       pe_entry->msg_data.iov,
				       pe_entry->msg_data.iov_cnt);
	if (bytes_sent < 0)
		return -errno;

	if (pe_entry->done_len < ntohll(pe_entry->msg_hdr.size)) {
		ofi_consume_iov(pe_entry->msg_data.iov,
				&pe_entry->msg_data.iov_cnt,
				bytes_sent);
	}

	pe_entry->done_len += bytes_sent;
	return FI_SUCCESS;
}

static int tcpx_find_entry(struct tcpx_rx_hdr *rx_hdr)
{
	struct tcpx_ep *ep = container_of(rx_hdr, struct tcpx_ep, rx_hdr);
	struct tcpx_cq *cq;
	struct dlist_entry *entry;

	switch (rx_hdr->hdr.op) {
	case ofi_op_msg:

		if (dlist_empty(&ep->rx_queue))
			return -FI_EAGAIN;

		entry = ep->rx_queue.next;
		ep->cur_rx_entry = container_of(entry, struct tcpx_pe_entry,
						entry);

		ofi_truncate_iov(ep->cur_rx_entry->msg_data.iov,
				 &ep->cur_rx_entry->msg_data.iov_cnt,
				 (ntohll(rx_hdr->hdr.size) -
				  sizeof(rx_hdr->hdr)));
		break;
	case ofi_op_read_rsp:
		if (dlist_empty(&ep->rx_queue))
			return -FI_EAGAIN;

		entry = ep->rma_read_queue.next;
		ep->cur_rx_entry = container_of(entry, struct tcpx_pe_entry,
						entry);
		break;
	case ofi_op_read_req:
	case ofi_op_write:
		cq = container_of(ep->util_ep.rx_cq, struct tcpx_cq, util_cq);
		ep->cur_rx_entry = tcpx_pe_entry_alloc(cq);
		break;
	default:
		return -FI_EINVAL;
	}

	ep->cur_rx_entry->msg_hdr = rx_hdr->hdr;
	ep->cur_rx_entry->done_len = sizeof(rx_hdr->hdr);
	return FI_SUCCESS;
}

int tcpx_recv_rx_hdr(struct tcpx_rx_hdr *rx_hdr)
{
	struct tcpx_ep *ep = container_of(rx_hdr, struct tcpx_ep, rx_hdr);
	ssize_t bytes_recvd;
	void *rem_hdr_buf;
	size_t rem_hdr_len;

	rem_hdr_buf = (uint8_t *)&rx_hdr->hdr + rx_hdr->done_len;
	rem_hdr_len = sizeof(rx_hdr->hdr) - rx_hdr->done_len;

	if (!rem_hdr_len)
		goto find_entry;

	bytes_recvd = ofi_recv_socket(ep->conn_fd, rem_hdr_buf,
				      rem_hdr_len, 0);
	if (bytes_recvd <= 0)
		return (bytes_recvd)? -errno: -FI_ENOTCONN;

	rx_hdr->done_len += bytes_recvd;

	if (rx_hdr->done_len < sizeof(rx_hdr->hdr))
		return -FI_EAGAIN;

find_entry:
	return tcpx_find_entry(rx_hdr);
}

static int validate_rma_iov(struct ofi_mr_map *map,
			    struct tcpx_rma_data *rma_data)
{
	int i,ret;

	/* validate rma_iov */
	for ( i = 0; i < rma_data->rma_iov_cnt ; i++) {
		ret = ofi_mr_map_verify(map,
					(uintptr_t *)&rma_data->rma_iov[i].addr,
					rma_data->rma_iov[i].len,
					rma_data->rma_iov[i].key,
					FI_REMOTE_WRITE, NULL);
		if (ret) {
			FI_DBG(&tcpx_prov, FI_LOG_EP_DATA,
			       "remote iov not valid\n");
			return -FI_EINVAL;
		}
	}
	return FI_SUCCESS;
}

static int tcpx_recv_rma_iov(struct tcpx_pe_entry *pe_entry,
			      size_t start_offset)
{
	ssize_t bytes_recvd;
	void *rem_rma_buf;
	size_t rem_rma_len;
	int i, ret;

	rem_rma_buf = ((uint8_t *)&pe_entry->rma_data +
		       (pe_entry->done_len - start_offset));
	rem_rma_len = (sizeof(pe_entry->rma_data) -
		       (pe_entry->done_len - start_offset));

	bytes_recvd = ofi_recv_socket(pe_entry->ep->conn_fd,
				      rem_rma_buf, rem_rma_len, 0);
	if (bytes_recvd <= 0)
		return (bytes_recvd)? -errno: -FI_ENOTCONN;

	pe_entry->done_len += bytes_recvd;

	if ((pe_entry->done_len - start_offset) <
	    sizeof(pe_entry->rma_data))
		return -FI_EAGAIN;

	/* validate rma_iov */
	ret = validate_rma_iov(&pe_entry->ep->util_ep.domain->mr_map,
			       &pe_entry->rma_data);
	if (ret) {
		FI_DBG(&tcpx_prov, FI_LOG_EP_DATA, "remote iov not valid\n");
	}

	/* copy rma iov to msg iov */
	if (pe_entry->msg_hdr.op == ofi_op_write) {
		for ( i = 0; i < pe_entry->rma_data.rma_iov_cnt ; i++) {
			pe_entry->msg_data.iov[i+1].iov_base =
				(void *) pe_entry->rma_data.rma_iov[i].addr;
			pe_entry->msg_data.iov[i+1].iov_len =
				pe_entry->rma_data.rma_iov[i].len;
		}
	} else if (pe_entry->msg_hdr.op == ofi_op_read_req) {

	}
	return FI_SUCCESS;
}

int tcpx_recv_msg(struct tcpx_pe_entry *pe_entry)
{
	ssize_t bytes_recvd;
	int ret;

	assert(pe_entry->done_len >= sizeof(pe_entry->msg_hdr));

	if (pe_entry->msg_hdr.op == ofi_op_read_req ||
	    pe_entry->msg_hdr.op == ofi_op_write) {
		ret = tcpx_recv_rma_iov(pe_entry, sizeof(pe_entry->msg_hdr));
		if (ret)
			return ret;
	}

	bytes_recvd = ofi_readv_socket(pe_entry->ep->conn_fd,
				       pe_entry->msg_data.iov,
				       pe_entry->msg_data.iov_cnt);
	if (bytes_recvd <= 0)
		return (bytes_recvd)? -errno: -FI_ENOTCONN;


	if (pe_entry->done_len < ntohll(pe_entry->msg_hdr.size)) {
		ofi_consume_iov(pe_entry->msg_data.iov,
				&pe_entry->msg_data.iov_cnt,
				bytes_recvd);
	}

	pe_entry->done_len += bytes_recvd;
	return FI_SUCCESS;
}
