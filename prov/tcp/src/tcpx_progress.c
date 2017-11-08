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

#include <prov.h>
#include "tcpx.h"
#include <poll.h>

#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <fi_util.h>

#define PE_INDEX(_p, _e) (_e - &_p->pe_table[0])

int tcpx_progress_close(struct tcpx_domain *domain)
{
	struct tcpx_progress *progress = domain->progress;

	if (!dlist_empty(&progress->ep_list)) {
		FI_WARN(&tcpx_prov, FI_LOG_DOMAIN,
		       "All EPs are not removed from progress\n");
		return -FI_EBUSY;
	}

	progress->do_progress = 0;
	if (progress->progress_thread &&
	    pthread_join(&progress->progress_thread, NULL)) {
		FI_WARN(&tcpx_prov, FI_LOG_DOMAIN,
		       "progress thread failed to join\n");
	}
	fd_signal_free(&progress->signal);
	poll_fd_data_free(progress->pf_data);
	pthread_mutex_destroy(&progress->list_lock);
	fastlock_destroy(&progress->signal_lock);
	fastlock_destroy(&progress->lock);
	free(progress)
	return FI_SUCCESS;
}

int tcpx_progress_signal(struct tcpx_progress *progress)
{
	fd_signal_set(&progress->signal);
}

static inline ssize_t tcpx_pe_send_field(struct tcpx_pe_entry *pe_entry,
					 void *field, size_t field_len,
					 size_t field_offset)
{
	int ret;
	size_t field_rem_len, field_done_len;
	uint8_t *buf;

	if (pe_entry->done_len >= (field_offset + field_len))
		return 0;

	field_done_len = pe_entry->done_len - field_offset;
	field_rem_len = field_len - field_done_len;
	buf = (uint8_t *) field + field_done_len;

	ret = tcpx_comm_send(pe_entry, buf, field_rem_len);
	if (ret <= 0)
		return -1;

	pe_entry->done_len += ret;
	return (ret == field_rem_len) ? 0 : -1;
}

static inline ssize_t tcpx_pe_recv_field(struct tcpx_pe_entry *pe_entry,
					 void *field, size_t field_len,
					 size_t field_offset)
{
	int ret;
	size_t field_rem_len, field_done_len;
	uint8_t *buf;

	if (pe_entry->done_len >= (field_offset + field_len))
		return 0;

	field_done_len = pe_entry->done_len - field_offset;
	field_rem_len = field_len - field_done_len;
	buf = (uint8_t *) field + field_done_len;

	ret = tcpx_comm_recv(pe_entry, buf, field_rem_len);
	if (ret <= 0)
		return -1;

	pe_entry->done_len += ret;
	return (ret == field_rem_len) ? 0 : -1;
}

static void process_tx_pe_entry(struct tcpx_pe_entry *pe_entry)
{

	size_t field_offset;
	int i;

	if (TCPX_XFER_WAIT_FOR_ACK == pe_entry->state) {
		return ;
	}
	if (TCPX_XFER_STARTED == pe_entry->state) {
		field_offset = 0;
		if (0 == tcpx_pe_send_field(pe_entry, &pe_entry->msg_hdr,
					    sizeof(pe_entry->msg_hdr),
					    field_offset)) {
			pe_entry->state = TCPX_XFER_HDR_SENT;
		}
	}

	if (TCPX_XFER_HDR_SENT == pe_entry->state) {
		field_offset += sizeof(pe_entry->msg_hdr);
		for (i = 0 ; i < pe_entry->iov_count ; i++) {
			if (0 != tcpx_pe_send_field(pe_entry, pe_entry->iov[i].iov.addr,
						    pe_entry->iov[i].iov.len,
						    field_offset)) {
				break;
			}
			field_offset += pe_entry->iov[i].iov.len;
		}

		if (pe_entry->done_len == pe_entry->total_len)
			pe_entry->state = TCPX_XFER_FLUSH_COMM_BUF;
	}

	if (TCPX_XFER_FLUSH_COMM_BUF == pe_entry->state) {
		if (!ofi_rbempty(pe_entry->comm_buf)) {
			/* flush until comm buffer is empty */
			tcpx_comm_flush();
		} else {
			if (pe_entry->wait_for_resp)
				pe_entry->state = TCPX_XFER_WAIT_FOR_ACK;
		}
	}

	if (TCPX_XFER_COMPLETE == pe_entry->state) {
		/* remove the pe entry from the list */
		/* write completion to the CQ? */
	}
}

static void process_rx_pe_entry(struct tcpx_pe_entry *pe_entry)
{
	size_t field_offset;

	if (TCPX_XFER_STARTED == pe_entry->state) {
		field_offset = 0;
		if (0 == tcpx_pe_recv_field(pe_entry, &pe_entry->msg_hdr,
					    sizeof(pe_entry->msg_hdr),
					    field_offset)) {
			pe_entry->msg_hdr.flags = ntohl(pe_entry->msg_hdr.flags);
			pe_entry->msg_hdr.size = ntohll(pe_entry->msg_hdr.size);
			pe_entry->msg_hdr.data = ntohll(pe_entry->msg_hdr.data);
			pe_entry->msg_hdr.remote_idx = ntohll(pe_entry->msg_hdr.remote_idx);
			pe_entry->state = TCPX_XFER_HDR_RECVD;
		}
	}

	if (TCPX_XFER_HDR_RECVD == pe_entry->state) {
		switch (pe_entry->msg_hdr.op_data) {
		case TCPX_OP_MSG_SEND:
			field_offset += sizeof(pe_entry->msg_hdr);
			for (i = 0 ; i < pe_entry->iov_count ; i++) {
				if (0 != tcpx_pe_recv_field(pe_entry, pe_entry->iov[i].iov.addr,
							    pe_entry->iov[i].iov.len,
							    field_offset)) {
					break;
				}
				field_offset += pe_entry->iov[i].iov.len;
			}

			if (pe_entry->done_len == pe_entry->total_len)
				if (pe_entry->msg_hdr.flags & FI_INJECT)
					pe_entry->state = TCPX_XFER_COMPLETE;
				else
					pe_entry->state = TCPX_XFER_WAIT_SENDING_ACK;
			break;
		case TCPX_OP_MSG_SEND_COMPLETE:
			field_offset += sizeof(pe_entry->msg_hdr);
			if (0 == tcpx_pe_recv_field(pe_entry, &pe_entry->msg_resp,
						    sizeof(pe_entry->msg_resp),
						    field_offset)) {

				/* to do :mark the the send pe complete */

				pe_entry->state = TCPX_XFER_COMPLETE;
			}
			break;
		default:
			FI_WARN(&tcpx_prov, FI_LOG_EP_DATA,
				"undefined message op code received");
		}
	}

	if (TCPX_XFER_WAIT_SENDING_ACK == pe_entry->state) {
		if (0 == tcpx_pe_send_field(pe_entry, &pe_entry->msg_resp,
					    sizeof(pe_entry->msg_hdr),
					    field_offset)) {
			pe_entry->state = TCPX_XFER_COMPLETE;
		}
	}

	if (TCPX_XFER_COMPLETE == pe_entry->state) {

	}
}

static void process_rx_pe_list(struct tcpx_ep *ep)
{
	struct tcpx_pe_entry *pe_entry;
	struct dlist_entry *entry;

	if (dlist_empty(ep->rx_pe_entry_list))
		return ;

	entry = ep->rx_pe_entry_list.next;
	pe_entry = container_of(entry, struct tcpx_pe_entry,
				ep_entry);
	process_rx_pe_entry(pe_entry);

	if (pe_entry->state == TCPX_XFER_COMPLETE) {
		/* remove it from the list */
		dlist_remove(entry, &ep->rx_pe_list);
	}
}

static void process_tx_pe_list(struct tcpx_ep *ep)
{
	struct tcpx_pe_entry *pe_entry;
	struct dlist_entry *entry;

	if (dlist_empty(ep->tx_pe_entry_list))
		return ;

	entry = ep->tx_pe_entry_list.next;
	pe_entry = container_of(entry, struct tcpx_pe_entry,
				ep_entry);
	process_tx_pe_entry(pe_entry);

	if (pe_entry->state == TCPX_XFER_COMPLETE) {
		/* remove it from the list */
		dlist_remove(entry, &ep->tx_pe_list);
	}
}

static void process_ep_rx_requests(struct tcpx_progress *progress)
{
	int i;
	struct tcpx_ep *ep;
	struct tcpx_pe_entry *pe_entry;
	struct poll_fd_data *pf_data = progress->pf_data;
	struct poll_fd_info *fd_info;

	for (i = 1; i < pf_data->nfds ; i++) {
		if (pf_data->poll_fds[i].revents & POLLIN) {

			fd_info = pf_data->fd_info;
			ep = container_of(fd_info->fid, struct tcpx_ep,
					  util_ep.ep_fid.fid);

			/* create new pe_entry  */
			pe_entry = get_new_pe_entry(progress);
			if (!pe_entry) {
				FI_WARN(&tcpx_prov, FI_LOG_EP_DATA,
					"failed to allocate pe entry")
				goto err;
			}

			pe_entry->state = TCPX_XFER_STARTED;
			pe_entry->ep = ep;

			/* add it to ep rx pe entry list */
			dlist_insert_tail(pe_entry->ep_entry, &ep->rx_pe_list);
		}
	}
err:
	return;
}

static struct tcpx_pe_entry *get_new_pe_entry(struct tcpx_progress *progress)
{
	struct dlist_entry *entry;
	struct tcpx_pe_entry *pe_entry;

	if (dlist_empty(&progress->free_list)) {
		pe_entry = util_buf_alloc(progress->pe_pool);
		if (pe_entry) {
			memset(pe_entry, 0, sizeof(*pe_entry));
			pe_entry->is_pool_entry = 1;
			if (ofi_rbinit(&pe_entry->comm_buf, TCPX_PE_COMM_BUFF_SZ))
				FI_WARN(&tcpx_prov, FI_LOG_DOMAIN,"failed to init comm-cache\n");
			pe_entry->cache_sz = TCPX_PE_COMM_BUFF_SZ;
			dlist_insert_tail(&pe_entry->entry, &progress->pool_list);
		}
	} else {
		entry = progress->free_list.next;
		dlist_remove(entry);
		dlist_insert_tail(entry, &progress->busy_list);
		pe_entry = container_of(entry, struct tcpx_pe_entry, ep_entry);
		assert(ofi_rbempty(&pe_entry->comm_buf));
		memset(pe_entry, 0, sizeof(*pe_entry));
	}
	return pe_entry;
}

static void process_ep_tx_requests(struct tcpx_progress *progress,
				   struct tcpx_ep *ep)
{
	struct tcpx_pe_entry *pe_entry;
	struct tcpx_domain tcpx_domain;
	size total_len = 0;

	tcpx_domain = container_of(ep->util_ep.domain,
				   struct tcpx_domain,
				   util_domain);
	fastlock_acquire(&ep->rb_lock);
	while (!ofi_rbempty(&ep->rb)) {
		pe_entry = get_new_pe_entry(tcpx_domain->progress);
		pe_entry->state = TCPX_XFER_STARTED;
		pe_entry->msg_hdr.version = TCPX_PROTO_VERSION;
		pe_entry->msg_hdr.op = ofi_op_msg;

		ofi_rbread(&ep->rb, &pe_entry->msg_hdr.op_data,
			   sizeof(pe_entry->msg_hdr.op_data));
		ofi_rbread(&ep->rb, &pe_entry->pe.tx_iov_cnt,
			   sizeof(pe_entry->pe.tx_iov_cnt));
		ofi_rbread(&tcpx_ep->rb, &pe_entry->flags,
			   sizeof(&pe_entry->flags));
		ofi_rbread(&tcpx_ep->rb, &pe_entry->context,
			   sizeof(pe_entry->context));
		ofi_rbread(&tcpx_ep->rb, &pe_entry->addr,
			   sizeof(pe_entry->addr));

		if (pe_entry->flags & FI_REMOTE_CQ_DATA) {
			pe_entry->msg_hdr.flags |= OFI_REMOTE_CQ_DATA;
			ofi_rbread(&tcpx_ep->rb, &pe_entry->msg_hdr.data,
				   sizeof(pe_entry->msg_hdr.data));
		}
		ofi_rbread(&tcpx_ep->rb, &pe_entry->ep, sizeof(pe_entry->ep));

		for (i = 0; i < pe_entry->pe.tx_iov_cnt; i++) {
			ofi_rbread(&tcpx_ep->rb, &pe_entry->iov[i],
				   sizeof(pe_entry->iov[i]));
		}

		pe_entry->msg_hdr.flags = ntohl(pe_entry->msg_hdr.flags);
		pe_entry->msg_hdr.data = ntohll(pe_entry->msg_hdr.data);
		pe_entry->msg_hdr.size = htonl(total_len);
		pe_entry->msg_hdr.remote_idx = htonll(PE_INDEX(progress, pe_entry));

		/* Add the new pe_entry to the list */
		dlist_insert_tail(pe_entry->ep_entry, &ep->tx_pe_list);
	}
	fastlock_release(&ep->rb_lock);
}

static int handle_progress_fd_list(struct tcpx_progress *progress,
			       struct poll_fd_data *pf_data)
{
	int ret = FI_SUCCESS;
	struct dlist_entry *entry;
	struct poll_fd_info *fd_info_entry;

	fastlock_acquire(&progress->fd_list_lock);
	while (!dlist_empty(&progress->fd_list)) {
		entry = progress->fd_list.next;
		fd_info_entry = (container_of(entry,
					struct poll_fd_info,
					entry));

		ret = poll_fds_find_dup(pf_data, fd_info_entry);
		if (ret >= 0) {
			if (fd_info_entry->flags & TCPX_SOCK_DEL) {
				poll_fds_swap_del_last(ret, pf_data);
			}
			dlist_remove(&progress->fd_list);
			free(fd_info_entry);
			continue;
		}

		ret = poll_fds_add_item(pf_data, fd_info_entry);
		if (ret)
			goto out;

		dlist_remove(&progress->fd_list);
		free(fd_info_entry);
	}
out:
	fastlock_release(&tcpx_fabric->fd_list_lock);
	return ret;
}

static int tcpx_progress_wait(struct tcpx_progress *progress)
{
	int ret;

	ret = poll(progress->pf_data->poll_fds,
		   progress->pf_data->nfds, -1);
	if (ret < 0) {
		FI_WARN(&tcpx_prov, FI_LOG_DOMAIN,
			"Poll failed\n");
		return -errno;
	}
	if (progress->pf_data->poll_fds[0].revents & POLLIN) {
		fd_signal_reset(&progress->signal);
		if (ret = handle_progress_fd_list(progress,
						  &progress->pf_data)) {
			FI_WARN(&tcpx_prov, FI_LOG_DOMAIN,
				"fd list add or remove failed\n");
			return ret;
		}
	}
	return FI_SUCCESS;
}

static int tcpx_progress_wait_ok(struct tcpx_progress *progress)
{
	struct dlist_entry *ep_entry;
	struct tcpx_ep *ep;
	struct tcpx_pe_entry *pe_entry;
	int ret = 0;

	pthread_mutex_lock(progress->ep_list_lock);
	dlist_foreach(&progress->ep_list, ep_entry) {
		ep = container_of(ep_entry, struct tcpx_ep, ep_entry);
		if (!dlist_empty(&ep->rb) ||
		    !dlist_empty(&ep->tx_pe_entry_list)
		    !dlist_empty(&ep->rx_pe_entry_list)) {
			goto out;
		}
	}
	ret = 1;
 out:
	pthread_mutex_unlock(progress->ep_list_lock);
	return ret;
}

void *tcpx_progress_thread(void *data)
{
	struct tcpx_progress *progress;
	struct dlist_entry  *ep_entry;
	struct tcpx_ep *ep;

	progress = (struct tcpx_progress *) data;
	while (progress->do_progress) {
		if (tcpx_progress_wait_ok(progress)) {
			tcpx_progress_wait(progress);
		}

		process_ep_rx_requests(progress);

		dlist_foreach(&progress->ep_list, ep_entry) {
			ep = container_of(ep_entry, struct tcpx_ep,
					  ep_entry);

			process_ep_tx_requests(progress, ep);
			process_tx_pe_list(ep);
			process_rx_pe_list(ep);
		}
	}
}

int tcpx_progress_table_init(struct progress *progress)
{
	memset(&progress->pe_table, 0,
	       sizeof(struct sock_pe_entry) * TCPX_PE_MAX_ENTRIES);

	dlist_init(&progress->free_list);
	dlist_init(&progress->busy_list);
	dlist_init(&progress->pool_list);

	for (i = 0; i < TCPX_PE_MAX_ENTRIES; i++) {
		dlist_insert_head(&progress->pe_table[i].entry, &progress->free_list);
		progress->pe_table[i].cache_sz = TCPX_PE_COMM_BUFF_SZ;
		if (ofi_rbinit(&progress->pe_table[i].comm_buf, TCPX_PE_COMM_BUFF_SZ))
			FI_WARN(&tcpx_prov, FI_LOG_DOMAIN,
				"failed to init comm-cache\n");
	}
	FI_DBG(&tcpx_prov, FI_LOG_DOMAIN,
		"PE table init: OK\n");
}

static int tcpx_progress_fd_poll_init(struct progress *progress)
{
	int ret;

	progress->pf_data->max_nfds = 64;
	ret = poll_fd_data_alloc(progress->pf_data, 64);
	if (ret) {
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
			"poll_fd memory alloc failed\n");
		return -FI_ENOMEM;
	}
	progress->pf_data.poll_fds[0].fd = progress->signal.fd[FI_READ_FD];
	progress->pf_data.poll_fds[0].events = POLLIN;
	progress->pf_data.nfds = 1;
	return -FI_SUCCESS;
}

int tcpx_progress_init(struct tcpx_domain *domain)
{
	struct tcpx_progress *progress = domain->progress;

	progress = calloc(1, sizeof(*progress));
	if (!progress)
		return -FI_ENOMEM;

	tcpx_progress_table_init(progress);


	fastlock_init(&progress->lock);
	fastlock_init(&progress->signal_lock);
	fastlock_init(&progress->fd_list_lock);
	pthread_mutex_init(&progress->list_lock, NULL);
	dlist_init(&progress->ep_list);
	dlist_init(&progress->fd_list);
	progress->domain = domain;

	progress->pe_pool = util_buf_pool_create(sizeof(struct tcpx_pe_entry),
					      16, 0, 1024);
	if (!progress->pe_pool) {
		FI_WARN(&tcpx_prov, FI_LOG_DOMAIN,
			"failed to create buffer pool\n");
		goto err1;
	}

	progress->rx_entry_pool = util_buf_pool_create(sizeof(struct tcpx_rx_entry),
					      16, 0, 1024);
	if (!progress->rx_entry_pool) {
		FI_WARN(&tcpx_prov, FI_LOG_DOMAIN,
			"failed to create buffer pool\n");
		goto err2;
	}

	ret = fd_signal_init(&progress->signal);
	if (ret) {
		FI_WARN(&tcpx_prov, FI_LOG_FABRIC,"signal init failed\n");
		goto err3;
	}

	ret = tcpx_progress_fd_poll_init(progress);
	if (ret) {
		FI_WARN(&tcpx_prov, FI_LOG_FABRIC,"signal init failed\n");
		goto err4;
	}
	progress->do_progress = 1;
	if (pthread_create(&progress->progress_thread, NULL,
			   tcpx_progress_thread, (void *)progress)) {
		goto err5;
	}
	return FI_SUCCESS;
err5:
	poll_fd_data_free(progress->pf_data);
err4:
	fd_signal_free(&progress->signal);
err3:
	util_buf_pool_destroy(progress->rx_entry_pool);
err2:
	util_buf_pool_destroy(progress->pe_pool);
err1:
	fastlock_destroy(&progress->lock);
	fastlock_destroy(&progress->signal_lock);
	pthread_mutex_destroy(&progress->list_lock);
	fastlock_destroy(&progress->fd_list_lock);
	free(progress);
	return ret;
}
