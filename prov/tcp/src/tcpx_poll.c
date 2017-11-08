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

void poll_fd_data_free(struct poll_fd_data *pf_data)
{
	free(pf_data->poll_fds);
	free(pf_data->fd_info);
}

int poll_fd_data_alloc(struct poll_fd_data *pf_data, int size)
{
	struct pollfd *new_poll_fds;
	struct poll_fd_info *new_fd_info;

	new_poll_fds = calloc(size,
			      sizeof(*new_poll_fds));
	new_fd_info = calloc(size,
			     sizeof(*new_fd_info));
	if (!new_poll_fds || !new_fd_info)
		return -FI_ENOMEM;

	pf_data->max_nfds = size;
	memcpy(new_poll_fds, pf_data->poll_fds,
	       pf_data->max_nfds*sizeof(*new_poll_fds));
	free(pf_data->poll_fds);
	pf_data->poll_fds = new_poll_fds;

	memcpy(new_fd_info, pf_data->fd_info,
	       pf_data->max_nfds*sizeof(*new_fd_info));
	free(pf_data->fd_info);
	pf_data->fd_info = new_fd_info;

	return 0;
}

void poll_fds_swap_del_last(int index,
			    struct poll_fd_data *pf_data)
{
	pf_data->poll_fds[index] = pf_data->poll_fds[(pf_data->nfds)-1];
	pf_data->fd_info[index] = pf_data->fd_info[(pf_data->nfds)-1];
	pf_data->nfds--;
}

int poll_fds_find_dup(struct poll_fd_data *pf_data,
		      struct poll_fd_info *fd_info_entry)
{
	struct tcpx_ep *tcpx_ep;
	struct tcpx_pep *tcpx_pep;
	int i;

	for (i = 1 ; i < pf_data->nfds ; i++) {

		switch (fd_info_entry->fid->fclass) {
		case FI_CLASS_EP:
			tcpx_ep = container_of(fd_info_entry->fid, struct tcpx_ep,
					       util_ep.ep_fid.fid);
			if (pf_data->poll_fds[i].fd == tcpx_ep->conn_fd)
				return i;
			break;
		case FI_CLASS_PEP:
			tcpx_pep = container_of(fd_info_entry->fid, struct tcpx_pep,
						util_pep.pep_fid.fid);
			if (pf_data->poll_fds[i].fd == tcpx_pep->sock)
				return i;
			break;
		default:
			continue;
		}
	}
	return -1;
}

int poll_fds_add_item(struct poll_fd_data *pf_data,
		      struct poll_fd_info *fd_info_entry)
{
	struct tcpx_ep *tcpx_ep;
	struct tcpx_pep *tcpx_pep;
	int ret = FI_SUCCESS;

	if (pf_data->nfds >= pf_data->max_nfds) {
		ret = poll_fd_data_alloc(pf_data, pf_data->max_nfds*2);
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
			"memory allocation failed\n");
		goto out;
	}

	pf_data->fd_info[pf_data->nfds] = *fd_info_entry;

	switch (fd_info_entry->fid->fclass) {
	case FI_CLASS_EP:
		tcpx_ep = container_of(fd_info_entry->fid, struct tcpx_ep,
				       util_ep.ep_fid.fid);
		pf_data->poll_fds[pf_data->nfds].fd = tcpx_ep->conn_fd;
		pf_data->poll_fds[pf_data->nfds].events = POLLOUT;
		break;
	case FI_CLASS_PEP:
		tcpx_pep = container_of(fd_info_entry->fid, struct tcpx_pep,
				       util_pep.pep_fid.fid);

		pf_data->poll_fds[pf_data->nfds].fd = tcpx_pep->sock;
		pf_data->poll_fds[pf_data->nfds].events = POLLIN;
		break;
	default:
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
			"invalid fd\n");
		ret = -FI_EINVAL;
	}
	pf_data->nfds++;
out:
	return ret;
}
