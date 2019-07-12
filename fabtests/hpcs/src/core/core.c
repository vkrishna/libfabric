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

#include <core/user.h>
#include <pattern/user.h>
#include <test/user.h>

/* size of buffer to store fi_getname() result */
#define NAMELEN 256

/* buffer size for storing hostnames */
#define HOSTLEN 256

static int verbose = 0;

/*
 * Struct which tracks a single domain and the resources created within its
 * scope, including endpoints, completion objects, and data objects.  The
 * lengths of the object arrays depend on the window size or the sharing
 * configuration requested for that kind of object.
 */
struct domain_state {
	struct fid_domain *domain;
	struct fid_ep *endpoint;
	struct fid_av *av;

	/* Will contain only one completion object if
	 * COMPLETION_OBJECT_PER_DOMAIN const was specified. */
	struct fid_cntr *tx_cntr;
	struct fid_cntr *rx_cntr;
	struct fid_cq *tx_cq;
	struct fid_cq *rx_cq;

	/* array indexed by rank */
	fi_addr_t *addresses;
};

struct ofi_state {
	struct fid_fabric *fabric;
	struct domain_state *domain_state;
};

enum callback_order {
	CALLBACK_ORDER_NONE,
	CALLBACK_ORDER_EXPECTED,
	CALLBACK_ORDER_UNEXPECTED
};

struct arguments {
	char				*prov_name;
	size_t				window_size;
	size_t				buffer_size;
	enum callback_order		callback_order;
	size_t				iterations;

	struct pattern_api		pattern_api;
	struct test_api			test_api;

	struct pattern_arguments	*pattern_arguments;
	struct test_arguments		*test_arguments;
};

#define DEFAULT_WINDOW_SIZE 10
#define DEFAULT_CALLBACK_ORDER CALLBACK_ORDER_NONE

static int init_cntrs(
		const size_t num,
		struct fid_domain *domain,
		struct fid_cntr *cntrs[])
{
	size_t i;
	int ret = 0;

	struct fi_cntr_attr cntr_attr = {0};
	cntr_attr.events = FI_CNTR_EVENTS_COMP;
	cntr_attr.wait_obj = FI_WAIT_UNSPEC;

	for (i = 0; i < num && ret == 0; i++)
		ret = fi_cntr_open(domain, &cntr_attr, cntrs + i, NULL);

	return ret;
}

static int init_cqs(
		const size_t num,
		const size_t cq_size,
		struct fid_domain *domain,
		struct fid_cq **cqs)
{
	size_t i;
	int ret = 0;

	struct fi_cq_attr cq_attr = {0};
	cq_attr.size = cq_size;
	cq_attr.format = FI_CQ_FORMAT_TAGGED;
	cq_attr.wait_obj = FI_WAIT_UNSPEC;

	for (i = 0; i < num && ret == 0; i++)
		ret = fi_cq_open(domain, &cq_attr, cqs + i, NULL);

	return ret;
}

static int init_completion(
		const struct arguments *arguments,
		const struct test_config *test_config,
		struct domain_state *domain_state,
		size_t cq_size)
{
	int ret;

	if (test_config->tx_use_cntr) {
		ret = init_cntrs(1, domain_state->domain, &domain_state->tx_cntr);
		if (ret) {
			hpcs_error("error initializing tx counters, ret=%d\n", ret);
			return ret;
		}
	}

	if (test_config->rx_use_cntr) {
		ret = init_cntrs(1, domain_state->domain, &domain_state->rx_cntr);
		if (ret) {
			hpcs_error("error initializing rx counters, ret=%d\n", ret);
			return ret;
		}
	}

	ret = init_cqs(1, cq_size, domain_state->domain, &domain_state->tx_cq);
	if (ret) {
		hpcs_error("initializing ofi tx cq failed\n");
		return ret;
	}

	ret = init_cqs(1, arguments->window_size, domain_state->domain,
			&domain_state->rx_cq);
	if (ret) {
		hpcs_error("initializing ofi rx cq failed\n");
		return ret;
	}

	return 0;
}


/*
 * Binds a domain's completion objects to an endpoint.  Does not have a
 * corresponding unbind function, since completion objects are implicitly
 * unbound when they are freed.
 */
static int bind_endpoint_completion(const struct test_config *test_config,
		struct domain_state *domain_state)
{
	int ret;

	if (domain_state->tx_cq) {
		uint64_t flags =
				test_config->tx_use_cq
					? FI_TRANSMIT
					: FI_TRANSMIT | FI_SELECTIVE_COMPLETION;

		ret = fi_ep_bind(domain_state->endpoint,
				&domain_state->tx_cq->fid, flags);
		if (ret) {
			hpcs_error("binding tx cq to ep failed\n");
			return ret;
		}
	}

	if (domain_state->rx_cq) {
		uint64_t flags =
				test_config->rx_use_cq
					? FI_RECV
					: FI_RECV | FI_SELECTIVE_COMPLETION;
		ret = fi_ep_bind(domain_state->endpoint,
				&domain_state->rx_cq->fid, flags);
		if (ret) {
			hpcs_error("binding rx cq to ep failed\n");
			return ret;
		}
	}

	if (domain_state->tx_cntr) {
		ret = fi_ep_bind(domain_state->endpoint,
				&domain_state->tx_cntr->fid,
				FI_SEND | FI_READ | FI_WRITE);
		if (ret) {
			hpcs_error("binding tx counter to ep failed\n");
			return ret;
		}
	}

	/*
	 * Tests that bind counters to memory regions for rx notification
	 * shouldn't also bind the counter to the EP.
	 */
	if (domain_state->rx_cntr && !test_config->rx_use_mr) {
		ret = fi_ep_bind(domain_state->endpoint,
				&domain_state->rx_cntr->fid, FI_RECV);
		if (ret) {
			hpcs_error("binding rx counter to ep failed\n");
			return ret;
		}
	}

	return 0;
}


static int init_endpoint(struct fi_info *info,
		struct domain_state *domain_state,
		struct fid_ep **endpoint)
{
	int ret;

	ret = fi_endpoint(domain_state->domain, info, endpoint, NULL);
	if (ret) {
		hpcs_error("fi_endpoint failed\n");
		return ret;
	}

	return 0;
}

static int init_domain(const struct arguments *arguments,
		const struct test_config *test_config,
		struct fid_fabric *fabric,
		struct fi_info *info,
		struct domain_state *domain_state,
		struct pm_job_info *job)
{
	int ret;
	int i;
	uint8_t *names = NULL;
	uint8_t our_name[NAMELEN];
	void *context = NULL;
	size_t len = NAMELEN;

	size_t cq_size = arguments->window_size * job->ranks *
			(test_config->tx_context_count + test_config->rx_context_count);

	struct fi_av_attr av_attr = (struct fi_av_attr) {
		.type = FI_AV_MAP,
		.count = job->ranks,
		.name = NULL
	};

	ret = fi_domain(fabric, info, &domain_state->domain, context);
	if (ret) {
		hpcs_error("fi_domain failed\n");
		goto err;
	}

	ret = init_endpoint(info, domain_state, &domain_state->endpoint);
	if (ret) {
		hpcs_error( "init_endpoint failed\n");
		goto err;
	}

	ret = init_completion(arguments, test_config, domain_state, cq_size);
	if (ret) {
		hpcs_error("init_completion failed\n");
		goto err;
	}

	ret = bind_endpoint_completion(test_config, domain_state);
	if (ret) {
		hpcs_error("bind_endpoint_completion failed\n");
		goto err;
	}

	ret = fi_av_open(domain_state->domain, &av_attr, &domain_state->av, NULL);
	if (ret) {
		hpcs_error("unable to open address vector\n");
		goto err;
	}

	ret = fi_ep_bind(domain_state->endpoint, &domain_state->av->fid, 0);

	ret = fi_enable(domain_state->endpoint);
	if (ret) {
		hpcs_error("error enabling endpoint\n");
		goto err;
	}

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

	if(verbose){
		hpcs_verbose("Rank %d peer addresses: ", job->rank);
		for (i = 0; i < job->ranks; i++)
			printf("%d:%lx ", i, (uint64_t)(domain_state->addresses[i]));
		printf("\n");
	}


err:
	free (names);
	return ret;
}

/*
 * Initializes OFI resources.
 */
static int init_ofi(
		const struct arguments *arguments,
		const void *test_arguments,
		const struct test_config *test_config,
		struct ofi_state *ofi_state,
		struct pm_job_info *job)
{
	int ret;
	struct fi_info *hints;
	struct fi_info *info;
	const char *node = NULL;
	const char *service = "2042";
	const uint64_t flags = 0;
	void *context = NULL;

	hints = fi_allocinfo();
	if (!hints)
		return -FI_ENOMEM;

	hints->fabric_attr->prov_name = arguments->prov_name;
	hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
	hints->domain_attr->mr_mode = FI_MR_RMA_EVENT;
	hints->domain_attr->mr_key_size = 4;
	hints->caps = test_config->minimum_caps |
			(arguments->pattern_api.enable_triggered ? FI_TRIGGER : 0);
	hints->mode = FI_CONTEXT2;
	hints->ep_attr->type = FI_EP_RDM;
	hints->tx_attr->op_flags = FI_DELIVERY_COMPLETE;

	ret = fi_getinfo(FI_VERSION(1,6), node, service, flags, hints, &info);
	if (ret)
		goto err_getinfo;

	ret = fi_fabric(info->fabric_attr, &ofi_state->fabric, context);
	if (ret) {
		hpcs_error("fi_fabric failed\n");
		goto err_fabric;
	}

	ret = init_domain(arguments, test_config, ofi_state->fabric, info,
			ofi_state->domain_state, job);
	if (ret) {
		hpcs_error("init_domain failed\n");
		goto err_domain;
	} else {
		hpcs_verbose("init_domain complete, Using %s provider\n",
			     info->fabric_attr->name);
	}

	return 0;

err_domain:
	fi_close(&ofi_state->fabric->fid);

err_fabric:
	fi_freeinfo(info);

err_getinfo:
	fi_freeinfo(hints);

	return ret;
}

static int fini_completion(struct domain_state *domain_state)
{
	int ret;

	if (domain_state->tx_cntr != NULL) {
		ret = fi_close(&domain_state->tx_cntr->fid);
		if (ret) {
			hpcs_error("unable to close tx counter\n");
			return -1;
		}
		domain_state->tx_cntr = NULL;
	}

	if (domain_state->rx_cntr != NULL) {
		ret = fi_close(&domain_state->rx_cntr->fid);
		if (ret) {
			hpcs_error("unable to close rx counter\n");
			return -1;
		}
		domain_state->rx_cntr = NULL;
	}

	if (domain_state->tx_cq != NULL) {
		ret = fi_close(&domain_state->tx_cq->fid);
		if (ret) {
			hpcs_error("unable to close tx cq\n");
			return -1;
		}
		domain_state->tx_cq = NULL;
	}

	if (domain_state->rx_cq != NULL) {
		ret = fi_close(&domain_state->rx_cq->fid);
		if (ret) {
			hpcs_error("unable to close rx cq\n");
			return -1;
		}
		domain_state->rx_cq = NULL;
	}

	return ret;
}

static int fini_domain(struct domain_state *domain_state)
{
	int ret = 0;

	ret = fi_close(&domain_state->endpoint->fid);
	if (ret) {
		hpcs_error("unable to close endpoint\n");
		return ret;
	}
	domain_state->endpoint = NULL;

	ret = fi_close(&domain_state->av->fid);
	if (ret) {
		hpcs_error("unable to close address vector\n");
		return ret;
	}

	ret = fini_completion(domain_state);
	if (ret)
		return ret;

	ret = fi_close(&domain_state->domain->fid);
	if (ret) {
		hpcs_error("unable to close domain\n");
		return ret;
	}
	domain_state->domain = NULL;

	return 0;
}

/*
 * Finalizes OFI.  Safely cleans up resources created by init_ofi.  Takes a
 * "best effort" approach - goes as far as it can and returns the first error
 * encountered.
 */
int fini_ofi(struct ofi_state *ofi_state)
{
	int ret;

	ret = fini_domain(ofi_state->domain_state);
	if (ret)
		return ret;

	ofi_state->domain_state = NULL;

	ret = fi_close(&ofi_state->fabric->fid);
	if (ret) {
		hpcs_error("unable to close fabric\n");
		return ret;
	}

	return 0;
}

/*
 * HPCS uses groups of arguments separated by a "-" or "--" (which are treated
 * as special by getopt, and cause it to stop parsing arguments).
 *
 * This function updates argc and argv to start at the next group of args,
 * with argv[0] pointing to the separator.
 */
static void next_args(int *argc, char * const**argv)
{
	int i;
	static char* empty = "--";

	/* 0th element is either binary name or previous separator. */
	for (i=1; i<*argc; i++) {
		if (strcmp((*argv)[i], "-") == 0 || strcmp((*argv)[i], "--") == 0)
			break;
	}

	if (i < *argc) {
		*argc = *argc - i;
		*argv = &(*argv)[i];
	} else {
		*argc = 1;
		*argv = &empty;
	}

	/* Current option index global variable must be reset. */
	optind = 1;
}

static int parse_arguments(int argc, char * const* argv,
		struct arguments **arguments)
{
	int longopt_idx, op, ret = 0;
	struct option longopt[] = {
		{"prov", required_argument, 0, 'p'},
		{"window", required_argument, 0, 'w'},
		{"order", required_argument, 0, 'o'},
		{"pattern", required_argument, 0, 'a'},
		{"iterations", required_argument, 0, 'n'},
		{"verbose", no_argument, &verbose, 1},
		{"help", no_argument, 0, 'h'},
		{0}
	};

	struct arguments *args = calloc(sizeof (struct arguments), 1);
	int have_pattern = 0;

	if (args == NULL)
		return -FI_ENOMEM;

	*args = (struct arguments) {
		.prov_name = NULL,
		.window_size = DEFAULT_WINDOW_SIZE,
		.callback_order = DEFAULT_CALLBACK_ORDER,
		.pattern_api = {0},
		.iterations = 1
	};

	while ((op = getopt_long(argc, argv, "vp:w:o:a:n:h", longopt, &longopt_idx)) != -1) {
		switch (op) {
		case 0:
			if (longopt[longopt_idx].flag != 0)
				printf("verbose mode enabled\n");
			break;
		case 'p':
			args->prov_name = calloc(1, 128);
			if (args->prov_name == NULL)
				return -FI_ENOMEM;
			if (sscanf(optarg, "%127s", args->prov_name) != 1)
				return -FI_EINVAL;
			break;
		case 'w':
			if (sscanf(optarg, "%zu", &args->window_size) != 1)
				return -FI_EINVAL;
			break;
		case 'o':
			if (strcmp(optarg, "none") == 0)
				args->callback_order = CALLBACK_ORDER_NONE;
			else if (strcmp(optarg, "expected") == 0)
				args->callback_order = CALLBACK_ORDER_EXPECTED;
			else if (strcmp(optarg, "unexpected") == 0)
				args->callback_order = CALLBACK_ORDER_UNEXPECTED;
			else {
				hpcs_error("failed to parse ordering\n");
				return -FI_EINVAL;
			}
			break;
		case 'a':
			if ((!strcmp(optarg, "alltoall")) || (!strcmp(optarg, "a2a")))
				args->pattern_api = a2a_pattern_api();
			else if (!strcmp(optarg, "self"))
				args->pattern_api = self_pattern_api();
			else if (!strcmp(optarg, "alltoone"))
				args->pattern_api = alltoone_pattern_api();
			else if (!strcmp(optarg, "ring"))
				args->pattern_api = ring_pattern_api();
			else {
				hpcs_error("unknown pattern\n");
				return -FI_EINVAL;
			}
			have_pattern = 1;
			break;
		case 'n':
			if (sscanf(optarg, "%zu", &args->iterations) != 1)
				return -FI_EINVAL;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
		default:
			hpcs_error("usage: %s [core-args] -- [pattern args] -- [test-args]\n", argv[0]);
			hpcs_error("[core-args] := "
				   "\t[-p | --prov=<provider name>]\n"
				   "\t[-w | --window=<size>]\n"
				   "\t[-o | --order=<expected|unexpected|none>]\n"
				   "\t[-n | --iterations=<n>]\n"
				   "\t -a | --pattern=<self|alltoall|alltoone>\n"
				   "\t[-h | --help]\n");
			return -1;
		}
	}

	/*
	 * Onsided tests create memory region before any data movement happens,
	 * but core doesn't initialize the buffer until it posts receives.
	 *
	 * In non-expected ordering, the buffer could be initialized after the
	 * payload is received, which isn't what we want.
	 */
	if (strstr(argv[0], "onesided") != NULL &&
			args->callback_order != CALLBACK_ORDER_EXPECTED) {
		hpcs_error("onsided test requires expected ording (\"--order=expected\")\n");
		return -FI_EINVAL;
	}

	if (!have_pattern) {
		hpcs_error("you must specify a pattern\n");
		return -FI_EINVAL;
	}

	args->test_api = test_api();

	next_args(&argc, &argv);

	ret = args->pattern_api.parse_arguments(argc, argv,
			&args->pattern_arguments);

	if (ret) {
		hpcs_error("failed to parse pattern arguments\n");
		return ret;
	}

	next_args(&argc, &argv);

	ret = args->test_api.parse_arguments(argc, argv,
			&args->test_arguments, &args->buffer_size);

	if (ret) {
		hpcs_error("failed to parse test arguments\n");
		return ret;
	}

	*arguments = args;

	return 0;
}

static void free_arguments (struct arguments *arguments)
{
	struct pattern_api _pattern_api = arguments->pattern_api;

	struct test_api _test_api = test_api ();

	_pattern_api.free_arguments (arguments->pattern_arguments);
	_test_api.free_arguments (arguments->test_arguments);

	free(arguments->prov_name);

	free(arguments);
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

/* Core loop progress information and context state. */
struct core_state {
	/* iteration counter (sometimes useful for debug messages) */
	size_t			iteration;

	/* allocated and pre-initialized memory resources */
	uint8_t			*rx_buf;
	uint8_t			*tx_buf;
	struct op_context	*tx_context;
	struct op_context	*rx_context;
	uint64_t		*keys;
	struct fid_mr		*rx_mr;

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
	int			cur_sender_rx_threshold;
	int			cur_receiver_tx_threshold;

	/* current iteration is complete when all three are true */
	bool			all_recvs_done;
	bool			all_sends_done;
	bool			all_completions_done;

	/* options */
	uint64_t		tx_flags;
	uint64_t		rx_flags;
};


#define DATA_BUF(base, counter) \
		((base) + ((counter % arguments->window_size) * arguments->buffer_size))

#define CONTEXT(base, counter) (&base[counter % arguments->window_size])

/*
 * Initiate as many rx transfers as our window allows, within
 * a single iteration of test/pattern.
 *
 * Return 0 unless an error occurs.
 */
static int core_initiate_rx(struct domain_state *domain_state,
		struct arguments *arguments,
		struct pattern_api *pattern,
		struct test_api *test,
		struct test_config *test_config,
		struct pm_job_info *job,
		struct core_state *state)
{
	int ret, prev, prev_threshold;
	struct op_context* op_context;
	enum callback_order order = arguments->callback_order;

	/* post receives */
	while (!state->all_recvs_done) {
		if (order == CALLBACK_ORDER_UNEXPECTED && !state->all_sends_done)
			break;

		prev = state->cur_sender;
		prev_threshold = state->cur_sender_rx_threshold;

		ret = pattern->next_sender(arguments->pattern_arguments,
				job->rank, job->ranks, &state->cur_sender,
				&state->cur_sender_rx_threshold);

		if (ret == -ENODATA) {
			state->all_recvs_done = true;
			if (order == CALLBACK_ORDER_EXPECTED)
				job->barrier();
			break;
		} else if (ret < 0) {
			hpcs_error("next_sender failed\n");
			return ret;
		}

		/*
		 * Doing window check after calling next_sender allows us to
		 * mark receives as done if our window is zero but there are
		 * no more senders.
		 */
		if (state->rx_window == 0) {
			state->cur_sender = prev;
			state->cur_sender_rx_threshold = prev_threshold;
			break;
		}

		op_context = CONTEXT(state->rx_context, state->recvs_posted);
		if (op_context->state != OP_DONE) {
			state->cur_sender = prev;
			state->cur_sender_rx_threshold = prev_threshold;
			break;
		}

		test->rx_init_buffer(arguments->test_arguments, DATA_BUF(state->rx_buf, state->recvs_posted),
				test_config->rx_buffer_size);

		op_context->buf = DATA_BUF(state->rx_buf, state->recvs_posted);

		/*
		 * cur_sender_rx_threshold is currently ignored, but we could enable
		 * triggered receives in the future if we have a good reason to do so.
		 */

		ret = test->rx_transfer(arguments->test_arguments,
				state->cur_sender, 1,
				domain_state->addresses[state->cur_sender],
				domain_state->endpoint,
				op_context, op_context->buf,
				NULL, state->rx_flags);

		if (ret == -FI_EAGAIN) {
			state->cur_sender = prev;
			state->cur_sender_rx_threshold = prev_threshold;
			break;
		}

		hpcs_verbose("rx_transfer initiated: ctx %p "
			     "from rank %ld\n",
			     op_context, state->cur_sender);

		if (ret) {
			hpcs_error("test receive failed, ret=%d\n", ret);
			return ret;
		}

		op_context->state = OP_PENDING;
		op_context->core_context = state->recvs_posted;

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

static int core_initiate_tx(struct domain_state *domain_state,
		struct arguments *arguments,
		struct pattern_api *pattern,
		struct test_api *test,
		struct test_config *test_config,
		struct pm_job_info *job,
		struct core_state *state)
{
	int ret, i, prev, prev_threshold;
	struct op_context* op_context;
	enum callback_order order = arguments->callback_order;

	struct fid_mr* mr;
	void *mr_desc;

	/* post send(s) */
	while (!state->all_sends_done) {
		if (order == CALLBACK_ORDER_EXPECTED && !state->all_recvs_done)
			break;

		prev = state->cur_receiver;
		prev_threshold = state->cur_receiver_tx_threshold;

		ret = pattern->next_receiver(arguments->pattern_arguments,
				job->rank, job->ranks, &state->cur_receiver,
				&state->cur_receiver_tx_threshold);
		if (ret == -ENODATA) {
			if (order == CALLBACK_ORDER_UNEXPECTED)
				job->barrier();
			state->all_sends_done = true;
			break;
		} else if (ret < 0) {
			hpcs_error("next_receiver failed\n");
			return ret;
		}

		if (state->tx_window == 0) {
			state->cur_receiver = prev;
			state->cur_receiver_tx_threshold = prev_threshold;
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

		if (pattern->enable_triggered) {
			for (i=0; i < test_config->tx_context_count; i++) {
				op_context->ctxinfo[i].fi_trig_context.event_type = FI_TRIGGER_THRESHOLD;
				op_context->ctxinfo[i].fi_trig_context.trigger.threshold =
					(struct fi_trigger_threshold) {
						.threshold =
							state->recvs_done_prev +
							(state->cur_receiver_tx_threshold * test_config->tx_context_count),
						.cntr = domain_state->rx_cntr
					};
			}

			op_context->tx_cntr = domain_state->tx_cntr;
			op_context->domain = domain_state->domain;
		}

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

static int core_completion(struct domain_state *domain_state,
		struct arguments *arguments,
		struct pattern_api *pattern,
		struct test_api *test,
		struct test_config *test_config,
		struct pm_job_info *job,
		struct core_state *state)
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

static int core_inner(struct domain_state *domain_state,
		struct arguments *arguments,
		struct pattern_api *pattern,
		struct test_api *test,
		struct test_config *test_config,
		struct pm_job_info *job)
{
	int ret;
	size_t i, j;
	size_t window = arguments->window_size;
	size_t iterations = arguments->iterations;

	struct op_context tx_context [window];
	struct op_context rx_context [window];

	struct core_state state = (struct core_state) {
		.tx_context = tx_context,
		.rx_context = rx_context,
		.tx_window = window,
		.rx_window = window,

		.cur_sender = PATTERN_NO_CURRENT,
		.cur_receiver = PATTERN_NO_CURRENT,
		.cur_sender_rx_threshold = 0,
		.cur_receiver_tx_threshold = 0,

		.all_sends_done = false,
		.all_recvs_done = false,
		.all_completions_done =	false,

		.tx_flags = pattern->enable_triggered ? FI_TRIGGER : 0,
		.rx_flags = 0,
	};

	enum callback_order order = arguments->callback_order;

	state.tx_buf = calloc(window, test_config->tx_buffer_size);
	if (state.tx_buf == NULL)
		return -FI_ENOMEM;

	state.rx_buf = calloc(window, test_config->rx_buffer_size);
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

	hpcs_verbose("Beginning test: buffer_size=%ld window=%ld iterations=%ld %s%s%s\n",
			test_config->tx_buffer_size, window, iterations,
			order == CALLBACK_ORDER_UNEXPECTED ? "unexpected" : "",
			order == CALLBACK_ORDER_EXPECTED ? "expected" : "",
			order == CALLBACK_ORDER_NONE ? "undefined order" : "");

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
			ret = core_initiate_rx(domain_state, arguments, pattern,
					test, test_config, job, &state);
			if (ret)
				return ret;

			ret = core_initiate_tx(domain_state, arguments, pattern,
					test, test_config, job, &state);
			if (ret)
				return ret;

			ret = core_completion(domain_state, arguments, pattern,
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

int core(const int argc, char * const *argv,
	 struct pm_job_info *job)
{
	int ret, cleanup_ret;

	struct arguments *arguments = NULL;
	struct test_api test = test_api ();
	struct test_config test_config = {0};
	struct ofi_state ofi_state = {0};
	struct domain_state domain_state = {0};
	struct pattern_api pattern = {0};

	fi_addr_t addresses[job->ranks];

	ret = parse_arguments(argc, argv, &arguments);

	if (ret < 0)
		return -FI_EINVAL;

	pattern = arguments->pattern_api;

	test_config = test.config(arguments->test_arguments);

	if (pattern.enable_triggered && !test_config.rx_use_cntr) {
		hpcs_error("patterns that use triggered ops may only be used with tests that use rx counters\n");
		return -FI_EINVAL;
	}

	hpcs_verbose("Initializing ofi resources\n");

	domain_state.addresses = &addresses[0];

	ofi_state.domain_state = &domain_state;

	ret = init_ofi(arguments, arguments->test_arguments, &test_config,
			&ofi_state, job);
	if (ret) {
		hpcs_error("Init_ofi failed, ret=%d\n", ret);
		return -1;
	} else {
		hpcs_verbose("OFI resource initialization successful\n");
	}

	ret = core_inner(&domain_state, arguments, &pattern, &test,
			&test_config, job);

	if (ret)
		hpcs_error("Test failed, ret=%d (%s)\n", ret, fi_strerror(-ret));

	cleanup_ret = fini_ofi(&ofi_state);
	if (cleanup_ret) {
		hpcs_error("Resource cleanup failed, ret=%d\n", ret);
		return -1;
	}

	free_arguments(arguments);

	return ret;
}



void hpcs_error(const char* format, ...)
{
	char hostname[HOSTLEN];

        gethostname(hostname, HOSTLEN);
	hostname[HOSTLEN-1]='\0';

	va_list args;
	fprintf(stderr, "%s: ", hostname);
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end (args);

}

void hpcs_verbose(const char* format, ...)
{
	char hostname[HOSTLEN];

	if(!verbose)
		return;

        gethostname(hostname, HOSTLEN);
	hostname[HOSTLEN-1]='\0';

	va_list args;
	fprintf(stdout, "%s: ", hostname);
        va_start(args, format);
        vfprintf(stdout, format, args);
        va_end (args);

}
