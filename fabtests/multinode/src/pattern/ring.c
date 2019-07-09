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

/*
 * The ring pattern creates a chain of rx-triggered sends, such that rank
 * R sends a message to rank (R+1)%N after receiving from rank (N-1)%N.
 *
 * The pattern assigns one rank as the leader (rank 0 by default), and the
 * final message in the chain is receied by the leader, forming a ring.
 *
 * (Explicitly setting the leader as -1 is allowed, in which case there
 * is no leader.  This is expected to deadlock, which is a way to verify
 * that triggered ops aren't firing prematurely.)
 *
 * The pattern may execute up to N rings simultaneously.  Each ring has a
 * different leader, chosen sequentially.  The --multi-ring argument
 * simply runs N rings, with every rank being the leader of a single ring.
 *
 * The pattern does not allow any rank to be the leader of more than one
 * ring.
 */

#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <rdma/fi_errno.h>

#include <pattern.h>
#include <core.h>

/*
 * Note: this does not handle the case where rings > num_ranks.
 */
static inline int ring_pattern_next(int is_sender,
		const struct pattern_arguments *arguments,
		int my_rank,
		int num_ranks,
		int *cur,
		int *threshold)
{
	int leader = arguments->leader;
	int rings = arguments->rings < 0
			? num_ranks
			: arguments->rings;
	int is_leader, max_threshold;

	/*
	 * Current node is a leader of some ring if it's within the
	 * first N ranks beginning with the leader (wrapping around),
	 * where N is the total number of rings.
	 */

	if (leader < 0)
		is_leader = 0;
	else if (leader + rings <= num_ranks)
		is_leader = my_rank >= leader && my_rank < leader + rings;
	else
		is_leader = my_rank >= leader || my_rank < (leader + rings) - num_ranks;

	max_threshold = is_leader ? rings - 1 : rings;

	if (rings > num_ranks) {
		hpcs_error("Ring pattern does not support a number of rings that exceeds number of ranks.\n");
		return -EINVAL;
	}

	if (arguments->verbose) {
		printf("%d ring_pattern_next_%s(... %d, %d) leader:%d rings:%d is_leader:%d max_threshold:%d\n",
				my_rank,
				is_sender ? "sender" : "receiver",
				*cur, *threshold,
				leader, rings, is_leader, max_threshold);
	}

	if (*cur == PATTERN_NO_CURRENT) {
		int peer_rank = (my_rank + (is_sender ? num_ranks - 1 : 1)) % num_ranks;

		*cur = peer_rank % num_ranks;
		*threshold = is_leader ? 0 : 1;
	} else if (*threshold < max_threshold) {
		*threshold = *threshold + 1;
	} else {
		if (arguments->verbose)
			printf("\t-> done\n");
		return -ENODATA;
	}

	if (arguments->verbose)
		printf("\t-> cur:%d, threshold:%d\n", *cur, *threshold);
	return 0;
}

static int ring_pattern_next_sender(
		const struct pattern_arguments *arguments,
		int my_rank,
		int num_ranks,
		int *cur,
		int *threshold)
{
	return ring_pattern_next(1, arguments, my_rank, num_ranks, cur, threshold);
}


static int ring_pattern_next_receiver(
		const struct pattern_arguments *arguments,
		int my_rank,
		int num_ranks,
		int *cur,
		int *threshold)
{
	return ring_pattern_next(0, arguments, my_rank, num_ranks, cur, threshold);
}


struct pattern_api ring_ops = {
	.name = "ring";
	.next_sender = &ring_pattern_next_sender,
	.next_receiver = &ring_pattern_next_receiver,
};
