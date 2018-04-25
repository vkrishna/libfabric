/*
 * Copyright (c) 2017 Intel Corporation, Inc.  All rights reserved.
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

#include <rdma/fi_errno.h>

#include <ofi_prov.h>
#include "tcpx.h"
#include <poll.h>

#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <ofi_util.h>
#include <ofi_iov.h>

int tcpx_ep_shutdown_report(struct tcpx_ep *ep, fid_t fid)
{
	struct fi_eq_cm_entry cm_entry = {0};

	fastlock_acquire(&ep->cm_state_lock);
	if (ep->cm_state == TCPX_EP_SHUTDOWN) {
		fastlock_release(&ep->cm_state_lock);
		return FI_SUCCESS;
	}
	ep->cm_state = TCPX_EP_SHUTDOWN;
	fastlock_release(&ep->cm_state_lock);

	cm_entry.fid = fid;
	return fi_eq_write(&ep->util_ep.eq->eq_fid, FI_SHUTDOWN,
			  &cm_entry, sizeof(cm_entry), 0);
}

void process_tx_pe_entry(struct tcpx_pe_entry *pe_entry)
{
	uint64_t total_len = ntohll(pe_entry->msg_hdr.size);
	int ret;

	ret = tcpx_send_msg(pe_entry);
	if (OFI_SOCK_TRY_SND_RCV_AGAIN(-ret))
		return;

	if (ret) {
		FI_WARN(&tcpx_prov, FI_LOG_DOMAIN, "msg send failed\n");
		goto err;
	}

	if (pe_entry->done_len == total_len)
		goto done;
	return;
err:
	if (ret == -FI_ENOTCONN) {
		tcpx_ep_shutdown_report(pe_entry->ep,
					&pe_entry->ep->util_ep.ep_fid.fid);
	}
done:
	tcpx_cq_report_completion(pe_entry->ep->util_ep.tx_cq,
				  pe_entry, ret);
	dlist_remove(&pe_entry->entry);
	tcpx_pe_entry_release(pe_entry);
}

static void process_rx_pe_entry(struct tcpx_pe_entry *pe_entry)
{
	int ret;

	ret = tcpx_recv_msg(pe_entry);
	if (OFI_SOCK_TRY_SND_RCV_AGAIN(-ret))
		return;

	if (ret) {
		FI_WARN(&tcpx_prov, FI_LOG_DOMAIN, "msg recv Failed ret = %d\n", ret);
		goto err;
	}

	if (pe_entry->done_len &&
	    pe_entry->done_len == ntohll(pe_entry->msg_hdr.size))
		goto done;
	return;
err:
	if (ret == -FI_ENOTCONN) {
		tcpx_ep_shutdown_report(pe_entry->ep,
					&pe_entry->ep->util_ep.ep_fid.fid);
	}
done:
	tcpx_cq_report_completion(pe_entry->ep->util_ep.rx_cq,
				  pe_entry, ret);
	dlist_remove(&pe_entry->entry);
	tcpx_pe_entry_release(pe_entry);
}

static struct tcpx_pe_entry * tcpx_get_rx_pe_entry(struct tcpx_rx_hdr *rx_hdr)
{
	struct tcpx_pe_entry *pe_entry = NULL;
	struct dlist_entry *entry;
	struct tcpx_ep *tcpx_ep;
	struct tcpx_cq *tcpx_cq;

	tcpx_ep = container_of(rx_hdr, struct tcpx_ep, rx_hdr);
	tcpx_cq = container_of(tcpx_ep->util_ep.rx_cq, struct tcpx_cq,
			       util_cq);

	switch (rx_hdr->hdr.op) {
	case ofi_op_msg:
		if (dlist_empty(&tcpx_ep->rx_queue))
			return NULL;

		entry = tcpx_ep->rx_queue.next;
		pe_entry = container_of(entry, struct tcpx_pe_entry,
					entry);

		pe_entry->msg_hdr = rx_hdr->hdr;
		pe_entry->msg_hdr.op_data = TCPX_OP_MSG_RECV;
		pe_entry->done_len = sizeof(rx_hdr->hdr);

		if (ofi_truncate_iov(pe_entry->msg_data.iov,
				     &pe_entry->msg_data.iov_cnt,
				     (ntohll(pe_entry->msg_hdr.size) -
				      sizeof(pe_entry->msg_hdr))))
			return NULL;

		break;
	case ofi_op_read_req:
	case ofi_op_write:
		pe_entry = tcpx_pe_entry_alloc(tcpx_cq);
		if (!pe_entry)
			return NULL;

		pe_entry->msg_hdr = rx_hdr->hdr;
		pe_entry->msg_hdr.op_data = TCPX_OP_MSG_RECV;
		pe_entry->ep = tcpx_ep;
		pe_entry->flags = TCPX_NO_COMPLETION;
		pe_entry->done_len = sizeof(rx_hdr->hdr);
		break;
	case ofi_op_read_rsp:
		/* todo complete this case */
	default:
		return NULL;
	}
	rx_hdr->done_len = 0;
	return pe_entry;
}

static void tcpx_process_rx_msg(struct tcpx_ep *ep)
{
	int ret;

	if (!ep->cur_rx_entry) {
		ret = tcpx_recv_field(ep->conn_fd, &ep->rx_hdr.hdr,
				      sizeof(ep->rx_hdr.hdr),
				      &ep->rx_hdr.done_len, 0);
		if (OFI_SOCK_TRY_SND_RCV_AGAIN(-ret))
			return;

		if (ret)
			goto err;

		ep->cur_rx_entry = tcpx_get_rx_pe_entry(&ep->rx_hdr);
		if (!ep->cur_rx_entry) {
			/* todo: print debug info here */
			return;
		}
	}
	process_rx_pe_entry(ep->cur_rx_entry);
	return;
err:
	if (ret == -FI_ENOTCONN)
		tcpx_ep_shutdown_report(ep, &ep->util_ep.ep_fid.fid);
}

static void process_tx_queue(struct tcpx_ep *ep)
{
	struct tcpx_pe_entry *pe_entry;
	struct dlist_entry *entry;

	if (dlist_empty(&ep->tx_queue))
		return;

	entry = ep->tx_queue.next;
	pe_entry = container_of(entry, struct tcpx_pe_entry,
				entry);
	process_tx_pe_entry(pe_entry);
}

void tcpx_progress(struct util_ep *util_ep)
{
	struct tcpx_ep *ep;

	ep = container_of(util_ep, struct tcpx_ep, util_ep);
	fastlock_acquire(&ep->queue_lock);
	tcpx_process_rx_msg(ep);
	process_tx_queue(ep);
	fastlock_release(&ep->queue_lock);
	return;
}

static int tcpx_try_func(void *util_ep)
{
	/* nothing to do here. When endpoints
	 have incoming data, cq drives progress*/
	return FI_SUCCESS;
}

int tcpx_progress_ep_add(struct tcpx_ep *ep)
{
	if (!ep->util_ep.rx_cq->wait)
		return FI_SUCCESS;

	return ofi_wait_fd_add(ep->util_ep.rx_cq->wait,
			       ep->conn_fd, tcpx_try_func,
			       (void *)&ep->util_ep, NULL);
}

void tcpx_progress_ep_del(struct tcpx_ep *ep)
{
	fastlock_acquire(&ep->cm_state_lock);
	if (ep->cm_state == TCPX_EP_CONNECTING) {
		goto out;
	}

	if (ep->util_ep.rx_cq->wait) {
		ofi_wait_fd_del(ep->util_ep.rx_cq->wait, ep->conn_fd);
	}
out:
	fastlock_release(&ep->cm_state_lock);
}
