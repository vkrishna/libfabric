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

#include <ofi.h>
#include <ofi_enosys.h>
#include <ofi_rbuf.h>
#include <ofi_list.h>
#include <ofi_signal.h>
#include <ofi_util.h>
#include <ofi_proto.h>

#ifndef _TCP_H_
#define _TCP_H_

#define TCPX_MAJOR_VERSION 0
#define TCPX_MINOR_VERSION 1

#define TCPX_NO_COMPLETION	(1ULL << 63)

#define POLL_MGR_FREE		(1 << 0)
#define POLL_MGR_DEL		(1 << 1)
#define POLL_MGR_ACK		(1 << 2)

#define TCPX_MAX_CM_DATA_SIZE	(1<<8)
#define TCPX_IOV_LIMIT		(4)
#define TCPX_MAX_INJECT_SZ	(64)

extern struct fi_provider	tcpx_prov;
extern struct util_prov		tcpx_util_prov;
extern struct fi_info		tcpx_info;
struct tcpx_fabric;
struct tcpx_domain;
struct tcpx_pe_entry;
struct tcpx_cq;
struct tcpx_ep;

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
void tcpx_cq_report_completion(struct util_cq *cq,
			       struct tcpx_pe_entry *pe_entry,
			       int err);

int tcpx_conn_mgr_init(struct tcpx_fabric *tcpx_fabric);
void tcpx_conn_mgr_close(struct tcpx_fabric *tcpx_fabric);
int tcpx_recv_msg(struct tcpx_pe_entry *pe_entry);
int tcpx_send_msg(struct tcpx_pe_entry *pe_entry);
struct tcpx_pe_entry *tcpx_pe_entry_alloc(struct tcpx_cq *cq);
void tcpx_pe_entry_release(struct tcpx_pe_entry *pe_entry);
void tcpx_progress(struct util_ep *util_ep);
int tcpx_ep_shutdown_report(struct tcpx_ep *ep, fid_t fid, int err);
int tcpx_progress_ep_add(struct tcpx_ep *ep);
void tcpx_progress_ep_del(struct tcpx_ep *ep);

enum tcpx_xfer_op_codes {
	TCPX_OP_MSG_SEND,
	TCPX_OP_MSG_RECV,
};

enum poll_fd_type {
	CONNECT_SOCK,
	PASSIVE_SOCK,
	ACCEPT_SOCK,
};

enum poll_fd_state {
	ESTABLISH_CONN,
	RCV_RESP,
	CONNECT_DONE,
};

struct poll_fd_info {
	fid_t			fid;
	struct dlist_entry	entry;
	int			flags;
	enum poll_fd_type	type;
	enum poll_fd_state	state;
	size_t			cm_data_sz;
	char			cm_data[TCPX_MAX_CM_DATA_SIZE];
};

struct poll_fd_mgr {
	struct fd_signal	signal;
	struct dlist_entry	list;
	fastlock_t		lock;
	int			run;

	struct pollfd		*poll_fds;
	struct poll_fd_info	*poll_info;
	int			nfds;
	int			max_nfds;
};

struct tcpx_conn_handle {
	struct fid		handle;
	SOCKET			conn_fd;
};

struct tcpx_pep {
	struct util_pep 	util_pep;
	struct fi_info		info;
	SOCKET			sock;
	struct poll_fd_info	poll_info;
};

enum tcpx_cm_state {
	TCPX_EP_INIT,
	TCPX_EP_CONN_ACTIVE,
	TCPX_EP_CONN_SHUTDOWN,
};

struct tcpx_ep {
	struct util_ep		util_ep;
	SOCKET			conn_fd;
	struct dlist_entry	ep_entry;
	struct dlist_entry	rx_queue;
	struct dlist_entry	tx_queue;
	/* lock for protecting tx/rx queues */
	fastlock_t		queue_lock;
	enum tcpx_cm_state	cm_state;
	fastlock_t		cm_state_lock;
};

struct tcpx_fabric {
	struct util_fabric	util_fabric;
	struct poll_fd_mgr	poll_mgr;
	pthread_t		conn_mgr_thread;
};

struct tcpx_msg_data {
	size_t		iov_cnt;
	union {
		struct iovec		iov[TCPX_IOV_LIMIT+1];
		struct fi_rma_iov	rma_iov[TCPX_IOV_LIMIT+1];
		struct fi_rma_ioc	rma_ioc[TCPX_IOV_LIMIT+1];
	};
	uint8_t			inject[TCPX_MAX_INJECT_SZ];
};

struct tcpx_pe_entry {
	struct ofi_op_hdr	msg_hdr;
	struct tcpx_msg_data	msg_data;
	struct dlist_entry	entry;
	struct tcpx_ep		*ep;
	uint64_t		flags;
	void			*context;
	uint64_t		done_len;
};

struct tcpx_domain {
	struct util_domain	util_domain;
};

struct tcpx_cq {
	struct util_cq		util_cq;
	ofi_atomic64_t		cq_free_size;
	struct util_buf_pool	*pe_entry_pool;
};

#endif //_TCP_H_
