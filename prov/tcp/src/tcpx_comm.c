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

int tcpx_recv_field(SOCKET sock, void *buf, size_t buf_len,
		    uint64_t *done_len, size_t start_offset)
{
	void *rem_buf;
	size_t rem_len;
	ssize_t bytes_recvd;

	rem_buf = (uint8_t *) buf + (*done_len - start_offset);
	rem_len = buf_len - (*done_len - start_offset);

	bytes_recvd = ofi_recv_socket(sock, rem_buf, rem_len, 0);
	if (bytes_recvd <= 0)
		return (bytes_recvd)? -errno: -FI_ENOTCONN;

	*done_len += bytes_recvd;
	return (buf_len - (*done_len - start_offset))?
		-FI_EAGAIN: FI_SUCCESS;
}

static int tcpx_process_read_req(struct tcpx_pe_entry *pe_entry)
{
	return -FI_ENODATA;
}

static int tcpx_process_read_rsp(struct tcpx_pe_entry *pe_entry)
{
	return -FI_ENODATA;
}

static int tcpx_process_write(struct tcpx_pe_entry *pe_entry)
{
	int i;

	pe_entry->msg_data.iov_cnt = pe_entry->rma_data.rma_iov_cnt;
	for ( i = 0 ; i < pe_entry->rma_data.rma_iov_cnt ; i++ ) {
		pe_entry->msg_data.iov[i].iov_base =
			(void *) pe_entry->rma_data.rma_iov[i].addr;
		pe_entry->msg_data.iov[i].iov_len =
			pe_entry->rma_data.rma_iov[i].len;
	}
	return FI_SUCCESS;
}

static int tcpx_validate_rma_data(struct tcpx_pe_entry *pe_entry)
{
	struct ofi_mr_map *map = &pe_entry->ep->util_ep.domain->mr_map;
	struct fi_rma_iov *rma_iov = pe_entry->rma_data.rma_iov;
	uint64_t access;
	int i, ret;

	switch (pe_entry->msg_hdr.op) {
	case ofi_op_read_req:
		access = FI_REMOTE_READ;
		break;
	case ofi_op_read_rsp:
	case ofi_op_write:
		access = FI_REMOTE_WRITE;
		break;
	default:
		return -FI_EINVAL;
	}

	for ( i = 0 ; i < pe_entry->rma_data.rma_iov_cnt ; i++) {
		ret = ofi_mr_map_verify(map,
					(uintptr_t *)&rma_iov[i].addr,
					rma_iov[i].len,
					rma_iov[i].key,
					access, NULL);
		if (ret) {
			FI_DBG(&tcpx_prov, FI_LOG_EP_DATA,
			       "invalid rma iov received\n");
			return -FI_EINVAL;
		}
	}
	return FI_SUCCESS;
}

static int tcpx_process_rma_data(struct tcpx_pe_entry *pe_entry)
{
	int ret;

	ret = tcpx_recv_field(pe_entry->ep->conn_fd, (void *) &pe_entry->rma_data,
			      sizeof(pe_entry->rma_data), &pe_entry->done_len,
			      sizeof(pe_entry->msg_hdr));
	if (ret)
		return ret;

	ret = tcpx_validate_rma_data(pe_entry);
	if (ret)
		/* todo process failure. send response*/
		return ret;

	switch (pe_entry->msg_hdr.op) {
	case ofi_op_read_req:
		ret = tcpx_process_read_req(pe_entry);
		break;
	case ofi_op_read_rsp:
		ret = tcpx_process_read_rsp(pe_entry);
		break;
	case ofi_op_write:
		ret = tcpx_process_write(pe_entry);
		break;
	default:
		return -FI_EINVAL;
	}
	return ret;
}

int tcpx_recv_msg(struct tcpx_pe_entry *pe_entry)
{
	ssize_t bytes_recvd;
	int ret;

	if (pe_entry->done_len < (sizeof(pe_entry->msg_hdr) +
				  sizeof(pe_entry->rma_data))) {
		switch (pe_entry->msg_hdr.op) {
		case ofi_op_read_req:
		case ofi_op_read_rsp:
		case ofi_op_write:
			ret = tcpx_process_rma_data(pe_entry);
			if (ret)
				return ret;
		}
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
