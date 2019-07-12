/*
 * Copyright (c) 2019 Intel Corporation. All rights reserved.
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
#include <errno.h>
#include <shared.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <core.h>
struct pm_job_info pm_job;

static inline ssize_t socket_send(int sock, void *buf, size_t len, int flags)
{
	ssize_t ret;
	size_t m = 0;
	uint8_t *ptr = (uint8_t *) buf;

	do {
		ret = send(sock, (void *) &ptr[m], len-m, flags);
		if (ret < 0)
			return ret;

		m += ret;
	} while (m != len);

	return len;
}

static inline int socket_recv(int sock, void *buf, size_t len, int flags)
{
	ssize_t ret;
	size_t m = 0;
	uint8_t *ptr = (uint8_t *) buf;

	do {
		ret = recv(sock, (void *) &ptr[m], len-m, flags);
		if (ret <= 0)
			return -1;

		m += ret;
	} while (m < len);

	return len;
}

static int pm_allgather(void *my_item, void *items, int item_size)

{
	int i, ret;
	uint8_t *offset;

	/* pm_job->addrs = calloc(pm_job->ranks, item_size); */
	/* if (!pm_job->addrs) */
	/* 	return -FI_ENOMEM; */

	/* client */
	if (!pm_job.clients) {
		ret = socket_send(pm_job.sock, my_item, item_size, 0);
		if (ret < 0)
			return errno == EPIPE ? -FI_ENOTCONN : -errno;

		ret = socket_recv(pm_job.sock, items,
				  pm_job.ranks*item_size, 0);
		if (ret <= 0)
			return (ret)? -errno : -FI_ENOTCONN;

		return 0;
	}

	/* server */
	memcpy(items, my_item, item_size);

	for (i = 0; i < pm_job.ranks-1; i++) {
		offset = (uint8_t *)items + item_size * (i+1);

		ret = socket_recv(pm_job.clients[i], (void *)offset,
				  item_size, 0);
		if (ret <= 0)
			return ret;
	}

	for (i = 0; i < pm_job.ranks-1; i++) {
		ret = socket_send(pm_job.clients[i], items,
				  pm_job.ranks*item_size, 0);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static void pm_barrier()
{
	char ch;
	char chs[pm_job.ranks];

	pm_job->allgather(&ch, chs, 1);
}

static int server_init()
{
	int new_sock;
	int ret, i = 0;

	ret = listen(pm_job.sock, pm_job.ranks);
	if (ret)
		return ret;

	pm_job.clients = calloc(pm_job.ranks, sizeof(int));
	if (!pm_job.clients)
		return -FI_ENOMEM;

	while (i < pm_job.ranks-1 &&
	       (new_sock = accept(pm_job.sock, NULL, NULL))) {
		if (new_sock < 0) {
			fprintf(stderr, "error during server init\n");
			goto err;
		}
		pm_job.clients[i] = new_sock;
		i++;
		fprintf(stderr,"connection established\n");
	}

	close(pm_job.sock);
	return 0;
err:
	free(pm_job.clients);
	return new_sock;
}

static inline int client_init()
{
	return  connect(pm_job.sock, pm_job.oob_server_addr,
			sizeof(*pm_job.oob_server_addr));
}

static int pm_conn_setup()
{
	int sock,  ret;
	int optval = 1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	pm_job.sock = sock;

	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &optval,
			 sizeof(optval));
	if (ret) {
		fprintf(stderr, "error setting socket options\n");
		return ret;
	}

	ret = bind(sock, pm_job.oob_server_addr,
		   sizeof(*pm_job.oob_server_addr));
	if (ret == 0) {
		ret = server_init();
	} else {
		ret = client_init();
	}
	if (ret)
		return ret;

	return 0;
}

static void pm_finalize()
{
	int i;

	if (!pm_job.clients) {
		close(pm_job.sock);
		return;
	}

	for (i = 0; i < pm_job.ranks; i++) {
		close(pm_job.clients[i]);
	}
	free(pm_job.clients);
}

int main(const int argc, char * const *argv)
{
	struct sockaddr_in sock_addr;
	extern char *optarg;
	int c, ret;

	pm_job = {
		.allgather = pm_allgather,
		.barrier = pm_barrier,
		.oob_server_addr = (struct sockaddr *) &sock_addr,
	};

	while ((c = getopt(argc, argv, "s:n:b:")) != -1) {
		switch (c) {
		case 's':
			sock_addr.sin_family = AF_INET;
			if (inet_pton(AF_INET, optarg,
				      (void *) &sock_addr.sin_addr) != 1)
				return -1;
			break;
		case 'n':
			pm_job.ranks = atoi(optarg);
			break;
		case 'b':
			sock_addr.sin_port = atoi(optarg);
		}
	}

	ret = pm_conn_setup();
	if (ret)
		goto err;

	ret = multinode_run_tests();
	if (ret) {
		fprintf(stderr, "TEST FAILED\n");
		goto err;
	}
	fprintf(stderr, "TEST PASSED\n");
err:
	pm_finalize();
	return FI_SUCCESS;
}
