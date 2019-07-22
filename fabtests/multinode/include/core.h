/*
 * Copyright (c) 2017-2018 Intel Corporation. All rights reserved.
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

#pragma once

#include <stdlib.h>
#include <stdbool.h>

#include <rdma/fabric.h>
#include <rdma/fi_trigger.h>
#include <sys/uio.h>

#include "pattern.h"

struct pm_job_info {
	size_t		rank;
	size_t		ranks;
	int		sock;
	int		*clients; //only valid for server
	struct sockaddr *oob_server_addr;
	void		*names;
	size_t		name_len;
	fi_addr_t	*fi_addrs;
	int (*allgather)(void *my_item, void *items,
			 int size);
	void (*barrier)();
};


struct multinode_xfer_state {
	int 			iteration;
	size_t			recvs_posted;
	size_t			sends_posted;
	size_t			recvs_done;
	size_t			sends_done;

	size_t			tx_window;
	size_t			rx_window;

	/* pattern iterator state */
	int			cur_sender;
	int			cur_receiver;

	bool			all_recvs_done;
	bool			all_sends_done;
	bool			all_completions_done;

	uint64_t		tx_flags;
	uint64_t		rx_flags;
};

extern struct pm_job_info pm_job;
int multinode_run_tests(int argc, char **argv);
