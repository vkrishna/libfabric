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
#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <rdma/fabric.h>
#include <rdma/fi_atomic.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_trigger.h>

#include <fi.h>
#include <fi_enosys.h>
#include <fi_rbuf.h>
#include <fi_list.h>
#include <fi_signal.h>
#include <fi_util.h>

#ifndef _TCP_H_
#define _TCP_H_

#define TCPX_MAJOR_VERSION 0
#define TCPX_MINOR_VERSION 1


extern struct fi_provider tcpx_prov;
extern struct util_prov tcpx_util_prov;
extern struct fi_info tcpx_info;

#define TCPX_PE_MAX_ENTRIES 128
#define TCPX_PE_COMM_BUFF_SZ (1024)
#define TCPX_IOV_LIMIT 4
#define TCPX_MAX_INJECT_SZ 63
#define TCPX_MAX_SOCK_REQS (1<<10)

#define TCPX_NO_COMPLETION (1ULL << 30)

#define TCPX_SOCK_ADD (1ULL << 0)
#define TCPX_SOCK_DEL (1ULL << 1)

int tcpx_create_fabric(struct fi_fabric_attr *attr,
		struct fid_fabric **fabric,
		void *context);

int tcpx_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
		    struct fid_pep **pep, void *context);

int tcpx_domain_open(struct fid_fabric *fabric, struct fi_info *info,
		     struct fid_domain **domain, void *context);


int tcpx_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep_fid, void *context);


int tcpx_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq_fid, void *context);

int poll_fd_data_alloc(struct poll_fd_data *pf_data, int size);
void poll_fds_swap_del_last(int index, struct poll_fd_data *pf_data);
int poll_fds_find_dup(struct poll_fd_data *pf_data, struct poll_fd_info *fd_info_entry);
int poll_fds_add_item(struct poll_fd_data *pf_data, struct poll_fd_info *fd_info_entry);

ssize_t tcpx_comm_send(struct sock_pe_entry *pe_entry, void *buf, size_t len);
ssize_t tcpx_comm_recv(struct sock_pe_entry *pe_entry, void *buf, size_t len);

enum tcpx_xfer_states {
	TCPX_XFER_STARTED,
	TCPX_XFER_HDR_SENT,
	TCPX_XFER_WAIT_FOR_ACK,
	TCPX_XFER_HDR_RECVD,
	TCPX_XFER_WAIT_SENDING_ACK,
	TCPX_XFER_COMPLETE,
};

enum tcpx_xfer_op_codes {
	TCPX_OP_MSG_SEND,
	TCPX_OP_MSG_SEND_COMPLETE,
	TCPX_OP_MSG_RECV,
	TCPX_OP_CONN_MSG, /* TO DO */
};

enum tcpx_xfer_field {
	TCPX_MSG_HDR_FIELD,
	TCPX_DATA_FIELD,
};

struct poll_fd_info {
	fid_t fid;
	int flags;
	struct fi_info *info;
	struct dlist_entry entry;
};

struct poll_fd_data {
	struct pollfd *poll_fds;
	struct poll_fd_info *fd_info;
	int nfds;
	int max_nfds;
};

union tcpx_iov {
	struct fi_rma_iov iov;
	struct fi_rma_ioc ioc;
};

struct tcpx_conn_handle {
	struct fid handle;
	SOCKET conn_fd;
};

struct tcpx_pep {
	struct util_pep util_pep;
	struct fi_info info;
	SOCKET sock;
	int sock_fd_closed;
};

struct tcpx_rx_pe {
};

struct tcpx_tx_pe {
	/* uint8_t op; */
	/* uint8_t tx_iov_cnt; */
	/* uint8_t rsvd[2]; */
	enum tx_state state;
	/* uint8_t header_sent; */
	/* uint8_t send_done; */
	/* uint8_t reserved[6]; */
	/* struct sock_tx_iov tx_iov[TCPX_IOV_LIMIT]; */
	/* char inject[SOCK_EP_MAX_INJECT_SZ]; */
};

struct tcpx_op_send {
	uint8_t op;
	uint8_t buf_iov_cnt;
	uint8_t rsvd[6];
	uint64_t flags;
	uint64_t context;
	uint64_t dest_addr;
	uint64_t buf_iov;
	struct tcpx_ep *ep;
};

struct tcpx_ep {
	struct util_ep util_ep;
	struct fi_info info;
	struct dlist_entry rx_pe_entry_list;
	struct dlist_entry tx_pe_entry_list;
	SOCKET conn_fd;
	struct dlist_entry ep_entry;
	int pe_ref_count;
	struct tcpx_pe_entry *cur_pe_entry;
	pthread_mutex_t rx_entry_list_lock;
	struct dlist_entry rx_entry_list;
	fastlock_t rb_lock;
	struct ofi_ringbuf rb_buf;
};

struct tcpx_fabric {
	struct util_fabric util_fabric;
	struct fd_signal signal;
	struct poll_fd_list pf_list;
	pthread_t conn_mgr_thread;
	int run_cm_thread;
};

struct tcpx_domain {
	struct util_domain util_domain;
	struct tcpx_progress *progress;
};

struct tcpx_pe_entry {
	enum tx_state state;
	struct ofi_op_hdr msg_hdr;
	struct tcpx_iov iov[TCPX_IOV_LIMIT];
	/* char inject[TCPX_MAX_INJECT_SZ]; */
	struct tcpx_msg_response msg_resp;
	struct dlist_entry entry;
	struct dlist_entry ep_entry;
	struct ofi_ringbuf comm_buf;
	struct tcpx_ep *ep;
	size_t cache_sz;
	uint64_t flags;
	uint64_t context;
	uint64_t addr;
	uint64_t tag;
	uint64_t buf;
	uint64_t total_len;
	uint64_t done_len;
	uint8_t iov_count;
	uint8_t wait_for_resp;
	uint8_t is_pool_entry;
	uint8_t rsvd[5];
};

struct tcpx_progress {
	struct util_domain *domain;
	struct tcpx_pe_entry pe_table[TCPX_PE_MAX_ENTRIES];
	struct dlist_entry free_list;
	struct dlist_entry busy_list;
	struct dlist_entry pool_list;
	fastlock_t lock;
	fastlock_t signal_lock;
	pthread_mutex_t ep_list_lock;
	struct fd_signal signal;
	struct util_buf_pool *pe_pool;
	struct util_buf_pool *rx_entry_pool;
	struct dlist_entry ep_list;
	fastlock_t fd_list_lock;
	struct dlist_entry fd_list;
	pthread_t progress_thread;
	int do_progress;
	struct poll_fd_data *pf_data;
};

struct tcpx_rx_entry {
	uint8_t op;
	uint8_t rsvd[7];
	uint64_t flags;
	uint64_t context;
	uint64_t data;
	uint64_t tag;
	union tcpx_iov iov[SOCK_EP_MAX_IOV_LIMIT];
	struct dlist_entry entry;
	struct slist_entry pool_entry;
	struct tcpx_ep *ep;
};

#endif //_TCP_H_
