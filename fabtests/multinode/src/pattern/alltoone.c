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

#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <rdma/fi_errno.h>

#include <pattern.h>

#define PATTERN_API_VERSION_MAJOR 0
#define PATTERN_API_VERSION_MINOR 0

static int ato_pattern_next_sender(
		const struct pattern_arguments *arguments,
		int my_rank,
		int num_ranks,
		int *cur,
		int *threshold)
{
	if (my_rank == arguments->target_rank){
		int next = *cur + 1;

		if (next >= num_ranks)
			return -ENODATA;

		*cur = next;
		return 0;
	} else {
		return -ENODATA;
	}
}

static int ato_pattern_next_receiver(
		const struct pattern_arguments *arguments,
		int my_rank,
		int num_ranks,
		int *cur,
		int *threshold)
{
	if (*cur == PATTERN_NO_CURRENT) {
		*cur = arguments->target_rank;
		return 0;
	}

	return -ENODATA;
}


struct pattern_ops all2one_ops = {
	.name = "alltoone";
	.next_sender = ato_pattern_next_sender;
	.next_receiver = ato_pattern_next_receiver
};
