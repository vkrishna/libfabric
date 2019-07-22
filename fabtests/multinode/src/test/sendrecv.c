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

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <unistd.h>
#include <getopt.h>

#include <rdma/fi_errno.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_tagged.h>

#include <test.h>


#define DEFAULT_TRANSFER_SIZE 4
static int tx_transfer(const struct test_arguments *arguments,
		const size_t transfer_id,
		const size_t transfer_count,
		const fi_addr_t rx_address,
		struct fid_ep *endpoint,
		struct op_context *op_context,
		uint8_t *buffer,
		void *desc,
		uint64_t key,
		int rank,
		uint64_t flags)
{
	const uint64_t tag = transfer_id;
	struct context_info *ctxinfo = op_context->ctxinfo;
	int ret;

	ctxinfo->iov = (struct iovec) {
		.iov_base = buffer,
		.iov_len = arguments->transfer_size
	};

	ctxinfo->tagged = (struct fi_msg_tagged) {
		.msg_iov = &ctxinfo->iov,
		.iov_count = 1,
		.desc = desc,
		.addr = rx_address,
		.tag = tag,
		.context = &ctxinfo->fi_context,
		.data = 0
	};

	if (arguments->use_workqueue && flags & FI_TRIGGER) {
		struct fi_deferred_work *work = &ctxinfo->def_work;
		work->triggering_cntr =
				ctxinfo->fi_trig_context.trigger.threshold.cntr;
		work->threshold = ctxinfo->fi_trig_context.trigger.threshold.threshold;
		work->completion_cntr = op_context->tx_cntr;

		flags = flags & ~FI_TRIGGER;

		ctxinfo->tagged_op = (struct fi_op_tagged) {
			.ep = endpoint,
			.msg = ctxinfo->tagged,
			.flags = flags | FI_COMPLETION
		};
		work->op_type = FI_OP_TSEND;
		work->op.tagged = &ctxinfo->tagged_op;

		ret = fi_control(&op_context->domain->fid, FI_QUEUE_WORK, work);
	} else {
		ret = fi_tsendmsg(endpoint, &ctxinfo->tagged, flags);
	}

	return ret;
}

static int rx_transfer(const struct test_arguments *arguments,
		const size_t transfer_id,
		const size_t transfer_count,
		const fi_addr_t tx_address,
		struct fid_ep *endpoint,
		struct op_context *op_context,
		uint8_t *buffer,
		void *desc,
		uint64_t flags)
{
	return fi_trecv(endpoint, buffer, arguments->transfer_size, desc,
			tx_address, transfer_id, 0,
			&op_context->ctxinfo[0].fi_context);
}

struct test_api sendrecv_api = {
	.tx_init_buffer = &test_generic_tx_init_buffer,
	.rx_init_buffer = &test_generic_rx_init_buffer,
	.tx_create_mr = &test_generic_tx_create_mr,
	.rx_create_mr = NULL,

	.tx_window_usage = &test_generic_tx_window_usage,
	.rx_window_usage = &test_generic_rx_window_usage,

	.tx_transfer = &tx_transfer,
	.rx_transfer = &rx_transfer,
	.tx_cntr_completion = &test_generic_tx_cntr_completion,
	.rx_cntr_completion = &test_generic_rx_cntr_completion,
	.tx_cq_completion = &test_generic_tx_cq_completion,
	.rx_cq_completion = &test_generic_rx_cq_completion,

	.tx_datacheck = &test_generic_tx_datacheck,
	.rx_datacheck = &test_generic_rx_datacheck,

	.tx_fini_buffer = &test_generic_tx_fini_buffer,
	.rx_fini_buffer = &test_generic_rx_fini_buffer,
	.tx_destroy_mr = &test_generic_tx_destroy_mr,
	.rx_destroy_mr = NULL
};
