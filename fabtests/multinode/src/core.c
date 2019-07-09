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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHWARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. const NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER const AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS const THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>

#include <rdma/fi_errno.h>
#include <rdma/fi_domain.h>
#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_trigger.h>

#include <core.h>
#include <pattern.h>
#include <test.h>


struct core_state state;
struct pattern_api *pattern;

static int multinode_init_fabric()
{
	struct fi_info *hints;
	struct fi_info *info;

	opts = INIT_OPTS;
	opts.options |= FT_OPT_SIZE;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	hints->ep_attr->type = FI_EP_RDM;
	hints->caps = FI_MSG;
	hints->mode = FI_CONTEXT;
	hints->domain_attr->mr_mode = FI_MR_LOCAL | OFI_MR_BASIC_MAP;

	ft_init();

	if (!hints->ep_attr->type)
		hints->ep_attr->type = FI_EP_RDM;

	ret = fi_getinfo(FT_FIVERSION, node, service, flags, hints, &fi);
	if (ret) {
		FT_PRINTERR("fi_getinfo", ret);
		return ret;
	}

	ret = ft_open_fabric_res();
	if (ret)
		return ret;


	opts.av_size = job->ranks;
	ret = ft_alloc_active_res(fi);
	if (ret)
		return ret;


	ret = fi_getname(&domain_state->endpoint->fid, &our_name, &len);

	if (ret) {
		hpcs_error("error determining local endpoint name\n");
		goto err;
	}

	names = malloc(len * job->ranks);
	if (names == NULL) {
		hpcs_error("error allocating memory for address exchange\n");
		ret = -1;
		goto err;
	}

	ret = job->allgather(&our_name, names, len, job);
	if (ret) {
		hpcs_error("error exchanging addresses\n");
		goto err;
	}

	ret = fi_av_insert(domain_state->av, names, job->ranks,
			   domain_state->addresses, 0, NULL);
	if (ret != job->ranks) {
		hpcs_error("unable to insert all addresses into AV table\n");
		ret = -1;
		goto err;
	} else {
		ret = 0;
	}

	ret = ft_enable_ep_recv();
	if (ret)
		return ret;

	return 0;
}

static int multinode_close_fabric()
{
	ft_free_res();
	return ft_exit_code(ret);
}

/*
 * Pre-test setup of memory regions used by one-sided operations.
 * This includes exchanging keys with peers.
 *
 * This creates a single target-side memory region, which peers read
 * or write at some offset.
 */
static int core_setup_target_mr(struct domain_state *domain_state,
		struct arguments *args, struct test_config *config,
		struct pm_job_info *job, struct fid_mr **rx_mr,
		uint8_t *rx_buf, uint64_t *keys)
{
	uint64_t my_key;
	int i, ret;

	if (args->test_api.rx_create_mr == NULL || !config->rx_use_mr)
		return 0;

	if (args->window_size < job->ranks) {
		hpcs_error("for one-sided communication, window must be >= number of ranks\n");
		return (-FI_EINVAL);
	}

	/* Key can be any arbitrary number. */
	*rx_mr = args->test_api.rx_create_mr(args->test_arguments, domain_state->domain, 42+job->rank,
			rx_buf, args->window_size*args->buffer_size, config->mr_rx_flags, 0);
	if (*rx_mr == NULL) {
		hpcs_error("failed to create target memory region\n");
		return -1;
	}

	my_key = fi_mr_key(*rx_mr);
	job->allgather(&my_key, keys, sizeof(uint64_t), job);

	if (verbose) {
		hpcs_verbose("mr key exchange complete: rank %ld my_key %ld len %ld keys: ",
				job->rank, my_key, args->window_size*args->buffer_size);
		for (i=0; i < job->ranks; i++)
			printf("%ld ", keys[i]);
		printf("\n");
	}

	if (config->rx_use_cntr) {
		if (!domain_state->rx_cntr) {
			hpcs_error("no rx counter to bind mr to\n");
			return -FI_EINVAL;
		}

		ret = fi_mr_bind(*rx_mr, &domain_state->rx_cntr->fid, config->mr_rx_flags);
		if (ret) {
			hpcs_error("fi_mr_bind (rx_cntr) failed: %d\n", ret);

			/*
			 * Binding an MR with FI_REMOTE_READ isn't defined by the OFI spec,
 			 * so we don't consider this a failure.
			 */
			if (config->mr_rx_flags & FI_REMOTE_READ) {
					hpcs_error("FI_REMOTE_READ memory region bind flag unsupported by this provider, skipping test.\n");
				return -FI_EOPNOTSUPP;
			}

			return -1;
		}
	}

	ret = fi_mr_enable(*rx_mr);
	if (ret)
		hpcs_error("fi_mr_enable failed: %d\n", ret);

	job->barrier(job);

	return 0;
}

static int multinode_post_rx()
{
	int ret, prev;
	struct op_context* op_context;

	/* post receives */
	while (!state.all_recvs_done) {

		prev = state.cur_sender;

		ret = pattern.next_sender();
		if (ret == -ENODATA) {
			state.all_recvs_done = true;
			break;
		} else if (ret < 0) {
			return ret;
		}

		/*
		 * Doing window check after calling next_sender allows us to
		 * mark receives as done if our window is zero but there are
		 * no more senders.
		 */
		if (state.rx_window == 0) {
			state.cur_sender = prev;
			break;
		}

		/* find context and buff */
		/* post rx buff with associated context */

		state->recvs_posted++;
		state->rx_window--;
	};
	return 0;
}

/*
 * Initiate as many tx transfers as our window allows, within
 * a single iteration of test/pattern.
 *
 * Return 0 unless an error occurs.
 */

static int multinode_post_tx()
{
	int ret, i, prev;
	struct op_context* op_context;

	struct fid_mr* mr;
	void *mr_desc;

	/* post send(s) */
	while (!state->all_sends_done) {
		if (order == CALLBACK_ORDER_EXPECTED && !state->all_recvs_done)
			break;

		prev = state->cur_receiver;

		ret = pattern->next_receiver()
		if (ret == -ENODATA) {
			state->all_sends_done = true;
			break;
		} else if (ret < 0) {
			return ret;
		}

		if (state->tx_window == 0) {
			state->cur_receiver = prev;
			break;
		}

		op_context = CONTEXT(state->tx_context, state->sends_posted);
		if (op_context->state != OP_DONE) {
			state->cur_receiver = prev;
			state->cur_receiver_tx_threshold = prev_threshold;
			break;
		}

		test->tx_init_buffer(arguments->test_arguments,
				DATA_BUF(state->tx_buf, state->sends_posted),
				test_config->tx_buffer_size);

		if (test_config->tx_use_cntr) {
			mr = test->tx_create_mr(arguments->test_arguments,
					domain_state->domain, 0,
					DATA_BUF(state->tx_buf, state->sends_posted),
					arguments->buffer_size, FI_SEND, 0);
			if (mr == NULL) {
				ret = -1;
				hpcs_error("unable to register tx memory region\n");
				return ret;
			}

			mr_desc = fi_mr_desc(mr);
		} else {
			mr = NULL;
			mr_desc = NULL;
		}

		op_context->buf = DATA_BUF(state->tx_buf, state->sends_posted);
		op_context->tx_mr = mr;

		ret = test->tx_transfer(arguments->test_arguments,
				job->rank, 1,
				domain_state->addresses[state->cur_receiver],
				domain_state->endpoint, op_context,
				op_context->buf, mr_desc, state->keys[state->cur_receiver],
				job->rank, state->tx_flags);

		if (ret == -FI_EAGAIN) {
			state->cur_receiver = prev;
			state->cur_receiver_tx_threshold = prev_threshold;
			break;
		}

		hpcs_verbose("tx_transfer initiated from rank %ld "
				"to rank %d: ctx %p key %ld trigger %d ret %d\n",
				job->rank, state->cur_receiver, op_context,
				state->keys[state->cur_receiver],
				state->cur_receiver_tx_threshold, ret);

		if (ret) {
			hpcs_error("tx_transfer failed, ret=%d\n", ret);
			return ret;
		}

		op_context->state = OP_PENDING;
		op_context->core_context = state->sends_posted;

		state->sends_posted++;
		state->tx_window--;
	};

	return 0;
}

static int multinode_wait_for_comp()
{
	int ret, i;
	struct op_context* op_context;

	/* poll completions */
	if (test_config->rx_use_cq) {
		while ((ret = test->rx_cq_completion(arguments->test_arguments,
				&op_context,
				domain_state->rx_cq)) != -FI_EAGAIN) {
			if (ret) {
				hpcs_error("cq_completion (rx) failed, ret=%d\n", ret);
				return -1;
			}

			if (test->rx_datacheck(arguments->test_arguments,
					op_context->buf, test_config->rx_buffer_size, 0)) {
				hpcs_error("rank %d: rx data check error at iteration %ld\n",
						job->rank, state->iteration);
				return -FI_EFAULT;
			}

			op_context->state = OP_DONE;
			state->recvs_done++;
			state->rx_window++;

			hpcs_verbose("ctx %p receive %ld complete\n",
				     op_context, op_context->core_context);
		}
	}

	if (test_config->tx_use_cq) {
		while ((ret = test->tx_cq_completion(arguments->test_arguments,
				&op_context,
				domain_state->tx_cq)) != -FI_EAGAIN) {
			if (ret) {
				hpcs_error("cq_completion (tx) failed, ret=%d\n", ret);
				return -1;
			}
			hpcs_verbose("Received tx completion for ctx %lx\n",
				     op_context);

			if (test->tx_datacheck(arguments->test_arguments,
					op_context->buf,
					test_config->tx_buffer_size)) {
				hpcs_error("rank %d: tx data check error at iteration %ld\n",
						job->rank, state->iteration);
				return -FI_EFAULT;
			}

			if (test_config->tx_use_cntr && test->tx_destroy_mr != NULL) {
				ret = test->tx_destroy_mr(arguments->test_arguments,
						op_context->tx_mr);
				if (ret) {
					hpcs_error("unable to release tx memory region\n");
					return -1;
				}
			}

			op_context->state = OP_DONE;
			op_context->test_state = 0;
			state->sends_done++;
			state->tx_window++;

			hpcs_verbose("ctx %p send %ld complete\n",
				     op_context, op_context->core_context);
		}
	}

	/*
	 * Counters are generally used for RMA/atomics and completion is handled
	 * as all-or-nothing rather than tracking individual completions.
	 *
	 * Triggered ops tests may use counters and CQs at the same time, in which
	 * case we ignore the counter completions here.
	 */
	if (state->all_recvs_done && state->all_sends_done) {
		if (test_config->tx_use_cntr &&
				state->sends_done < state->sends_posted &&
				!test_config->tx_use_cq) {
			ret = test->tx_cntr_completion(arguments->test_arguments,
					state->sends_posted*test_config->tx_context_count,
					domain_state->tx_cntr);
			if (ret) {
				hpcs_error("cntr_completion (tx) failed, ret=%d\n",
						ret);
				return -1;
			}

			for (i = state->sends_done_prev; i < state->sends_posted; i++) {
				op_context = CONTEXT(state->tx_context, i);

				if (test_config->tx_use_cntr && test->tx_destroy_mr != NULL) {
					ret = test->tx_destroy_mr(arguments->test_arguments,
							op_context->tx_mr);
					if (ret) {
						hpcs_error("unable to release tx memory region\n");
						return -1;
					}
				}
				op_context->state = OP_DONE;
				op_context->test_state = 0;

				state->sends_done++;
				state->tx_window++;
			}

			if (state->sends_done != state->sends_posted) {
				hpcs_error("tx accounting internal error\n");
				return -FI_EFAULT;
			}

			hpcs_verbose("tx counter completion done\n");
		}

		if (test_config->rx_use_cntr &&
				state->recvs_done < state->recvs_posted &&
				!test_config->rx_use_cq) {
			ret = test->rx_cntr_completion(arguments->test_arguments,
					state->recvs_posted*test_config->rx_context_count,
					domain_state->rx_cntr);
			if (ret) {
				hpcs_error("cntr_completion (rx) failed, ret=%d\n", ret);
				return -1;
			}

			for (i = state->recvs_done_prev; i < state->recvs_posted; i++) {
				op_context = CONTEXT(state->rx_context, i);
				op_context->state = OP_DONE;
				op_context->test_state = 0;
				state->recvs_done++;
				state->rx_window++;
			}

			/*
			 * note: counter tests use rx_buf directly,
			 * rather than DATA_BUF(rx_buf, i)
			 */

			if (test->rx_datacheck(arguments->test_arguments, state->rx_buf,
					test_config->rx_buffer_size,
					state->recvs_posted - state->recvs_done_prev)) {
				hpcs_error("rx data check error at iteration %ld\n", i);
				return -FI_EFAULT;
			}

			if (state->recvs_done != state->recvs_posted) {
				hpcs_error("rx accounting internal error\n");
				return -FI_EFAULT;
			}

			hpcs_verbose("rx counter completion done\n");
		}
	}

	if (state->recvs_posted == state->recvs_done &&
			state->sends_posted == state->sends_done) {
		state->all_completions_done = true;
	} else {
		hpcs_verbose("rank %d: recvs posted/done = %ld/%ld, sends posted/done = %ld/%ld\n",
				job->rank, state->recvs_posted, state->recvs_done,
				state->sends_posted, state->sends_done);
		/* rate-limit print statements */
		if (verbose)
			usleep(50000);
	}

	return 0;
}

static int multinode_init_state()
{
	int i;
	struct op_context tx_context [window];
	struct op_context rx_context [window];

	state = (struct core_state) {
		.tx_context = tx_context,
		.rx_context = rx_context,
		.tx_window_size = opts.window_size,
		.rx_window_size = opts.window_size,

		.cur_sender = PATTERN_NO_CURRENT,
		.cur_receiver = PATTERN_NO_CURRENT,

		.all_sends_done = false,
		.all_recvs_done = false,
		.all_completions_done =	false,

		.tx_flags = pattern->enable_triggered ? FI_TRIGGER : 0,
		.rx_flags = 0,
	};

	state.tx_buf = calloc(opts.window_size,
			      test_config->tx_buffer_size);
	if (state.tx_buf == NULL)
		return -FI_ENOMEM;

	state.rx_buf = calloc(opts.window_size,
			      test_config->rx_buffer_size);
	if (state.rx_buf == NULL)
		return -FI_ENOMEM;

	state.keys = calloc(job->ranks, sizeof(uint64_t));
	if (state.keys == NULL)
		return -FI_ENOMEM;

	memset((char*)&tx_context[0], 0, sizeof(tx_context[0])*window);
	memset((char*)&rx_context[0], 0, sizeof(rx_context[0])*window);

	for (i = 0; i < window; i++) {
		tx_context[i].ctxinfo =
				calloc(test_config->tx_context_count,
						sizeof(struct context_info));
		rx_context[i].ctxinfo =
				calloc(test_config->rx_context_count,
						sizeof(struct context_info));

		if (tx_context[i].ctxinfo == NULL || rx_context[i].ctxinfo == NULL)
			return -FI_ENOMEM;

		/* Populate backlinks. */
		for (j = 0; j < test_config->tx_context_count; j++)
			tx_context[i].ctxinfo[j].op_context = &tx_context[i];

		for (j = 0; j < test_config->rx_context_count; j++)
			rx_context[i].ctxinfo[j].op_context = &rx_context[i];

	}
}

static int multinode_fini_state()
{
	/* free all the allocated memory */
}

static int multinode_run_test(struct pattern_ops pattern_ops)
{
	int ret;
	size_t i, j;
	size_t window = opts.window_size;
	size_t iterations = opts.iterations;

	ret = core_setup_target_mr(domain_state, arguments, test_config, job,
			&state.rx_mr, state.rx_buf, state.keys);
	if (ret == -FI_EOPNOTSUPP)
		return 0;
	else if (ret)
		return ret;

	for (state.iteration = 0; state.iteration < iterations; state.iteration++) {
		state.cur_sender = PATTERN_NO_CURRENT;
		state.cur_receiver = PATTERN_NO_CURRENT;
		state.cur_sender_rx_threshold = 0;
		state.cur_receiver_tx_threshold = 0;

		state.all_completions_done = false;
		state.all_recvs_done = false;
		state.all_sends_done = false;

		state.recvs_done_prev = state.recvs_done;
		state.sends_done_prev = state.sends_done;

		while (!state.all_completions_done ||
				!state.all_recvs_done ||
				!state.all_sends_done) {
			ret = multinode_post_rx(domain_state, arguments, pattern,
					test, test_config, job, &state);
			if (ret)
				return ret;

			ret = multinode_post_tx(domain_state, arguments, pattern,
					test, test_config, job, &state);
			if (ret)
				return ret;

			ret = multinode_wait_for_comp(domain_state, arguments, pattern,
					test, test_config, job, &state);
			if (ret)
				return ret;
		}
	}

	/* Make sure all our peers are done before shutting down. */
	job->barrier();

	/*
	 * OFI docs are unclear about proper order of closing memory region
	 * and counter that are bound to each other.
	 */
	if (state.rx_mr != NULL && test->rx_destroy_mr != NULL) {
		ret = test->rx_destroy_mr(arguments->test_arguments, state.rx_mr);
		if (ret) {
			hpcs_error("unable to release rx memory region\n");
			return -FI_EFAULT;
		}
	}

	return 0;
}

static int multinode_exchange_keys()
{
	uint64_t my_key;

	my_key = fi_mr_key(mr);
	job->allgather(&my_key, keys, sizeof(uint64_t), job);

	return -FI_ENOSYS;
}

int multinode_run_tests()
{
	int i, ret;

	ret = multinode_init_fabric();
	if (ret)
		return ret;

	/* TODO allocate msg buffers */

	ret = multinode_exchange_keys();
	if (ret)
		goto err;
	/* TODO cycle through pattern list */

	ret = multinode_init_state();
	if (ret)
		goto err;

	/* run tests with each pattern */
	ret = multinode_run_test(all2all_ops);
	if (ret)
		goto err;

	return FI_SUCCESS;
err2:
	multinode_fini_state();
err1:
	multinode_close_fabric();
}
