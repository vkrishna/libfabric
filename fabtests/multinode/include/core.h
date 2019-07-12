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

#include "pattern.h"
#include "test.h"


/*
 * -----------------------------------------------------------------------------
 * CORE API
 * -----------------------------------------------------------------------------
 */


struct pm_job_info {
	size_t		rank;
	size_t		ranks;
	int		sock;
	int		*clients; //only valid for server
	struct sockaddr *oob_server_addr;
	struct sockaddr *my_oob_addr;
	void		*addrs;
	fi_rma_iov	*remote_iovs;
	int (*allgather)(void *my_item, void *items,
			 int size);
	void (*barrier)();
};


struct op_context {
	/* struct context_info	*ctxinfo; */
	enum op_state		state;
	uint8_t			*buf;
	uint64_t		core_context;
	uint64_t		test_context;
	struct fid_mr		*tx_mr;
	struct fid_cntr		*tx_cntr;
	struct fid_domain	*domain;
	uint64_t		test_state; /* reserved for test internal accounting */
};

/* Core loop progress information and context state. */
struct multinode_state {
	size_t			iteration;
	/* allocated and pre-initialized memory resources */
	uint8_t			*buf;
	uint8_t			*rx_buf;
	uint8_t			*tx_buf;
	struct op_context	*tx_context;
	struct op_context	*rx_context;
	uint64_t		*keys;

	/* initiated and completed operation counters, not reset per iteration */
	size_t			recvs_posted;
	size_t			sends_posted;
	size_t			recvs_done;
	size_t			sends_done;

	/* sends/recvs completed at beginning of current iteration */
	size_t			sends_done_prev;
	size_t			recvs_done_prev;

	/* window slots */
	size_t			tx_window;
	size_t			rx_window;

	/* pattern iterator state */
	int			cur_sender;
	int			cur_receiver;
	/* int			cur_sender_rx_threshold; */
	/* int			cur_receiver_tx_threshold; */

	/* current iteration is complete when all three are true */
	bool			all_recvs_done;
	bool			all_sends_done;
	bool			all_completions_done;

	/* options */
	uint64_t		tx_flags;
	uint64_t		rx_flags;
};

/*
 * Core combines a test and pattern, and drives the callback routines in each.
 *
 * Core doesn't interact with MPI directly, rather it's passed some data about
 *     the MPI environment and callback functions that invoke MPI functionality.
 *
 * Arguments:
 *
 *  argc,argv: command line arguments passed from main (in harness.c).  This
 *     includes the pattern and test arguments, which are separated out by core.
 *
 *  num_mpi_ranks: number of ranks in MPI job.
 *
 *  our_mpi_rank: MPI rank of current process.
 *
 *  address_exchange: MPI allgather function used to share host addresses.
 *
 *  barrier: MPI barrier function.
 */

int core(const int argc, char * const *argv, struct pm_job_info *job);
void hpcs_error(const char* format, ...);
void hpcs_verbose(const char* format, ...);
