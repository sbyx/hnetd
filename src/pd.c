/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include "pd.h"
#include "hnetd.h"
#include "prefix_utils.h"

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/ustream.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

struct pd {
	struct uloop_fd fd;
	struct pa_pd *pa_pd;
	struct list_head handles;
};


struct pd_handle {
	struct list_head head;
	struct ustream_fd fd;
	bool established;
	bool prepared;
	// todo: add timeout?
	struct pa_pd_lease lease;
	struct pd *pd;
};


// TCP transmission has ended, either because of success or timeout or other error
static void pd_handle_done(struct ustream *s)
{
	struct pd_handle *c = container_of(s, struct pd_handle, fd.stream);

	if (c->established)
		pa_pd_lease_term(c->pd->pa_pd, &c->lease);

	close(c->fd.fd.fd);
	ustream_free(&c->fd.stream);
	list_del(&c->head);
	free(c);
}


// Update
static void pd_handle_update(struct pa_pd_lease *lease)
{
	struct pd_handle *c = container_of(lease, struct pd_handle, lease);
	struct pa_cpd *cpd;
	hnetd_time_t now = hnetd_time();

	bool keep = false;
	bool applied = false;
	pa_pd_for_each_cpd(cpd, &c->lease) {
		if (cpd->cp.applied || !c->prepared) {
			char buf[PREFIX_MAXBUFFLEN];
			hnetd_time_t valid = 0;
			hnetd_time_t preferred = 0;

			if (cpd->cp.dp) {
				if (cpd->cp.dp->valid_until > now)
					valid = (cpd->cp.dp->valid_until - now) / HNETD_TIME_PER_SECOND;

				if (cpd->cp.dp->preferred_until > now)
					preferred = (cpd->cp.dp->preferred_until - now) / HNETD_TIME_PER_SECOND;
			}

			if (valid > UINT32_MAX)
				valid = UINT32_MAX;

			if (preferred > UINT32_MAX)
				preferred = UINT32_MAX;

			if (!cpd->cp.applied) {
				valid = 60;
				preferred = 60;
			}

			ustream_printf(&c->fd.stream, "%s,%"PRId64",%"PRId64"\n",
					prefix_ntop(buf, sizeof(buf), &cpd->cp.prefix, false),
					preferred, valid);

			applied = true;

			if (valid > 0)
				keep = true;
		} else {
			keep = true;
		}
	}

	if (applied) {
		ustream_write(&c->fd.stream, "\n", 1, false);
		ustream_write_pending(&c->fd.stream);
		c->prepared = true;
	}

	if (!keep)
		pd_handle_done(&c->fd.stream);
}


// More data was received from TCP connection
static void pd_handle_data(struct ustream *s, __unused int bytes_new)
{
	struct pd_handle *c = container_of(s, struct pd_handle, fd.stream);
	int pending;
	char *data = ustream_get_read_buf(s, &pending);
	char *end = memmem(data, pending, "\n\n", 2);

	uint8_t hint = 62;

	if (!c->established && end) {
		end += 2;
		end[-1] = 0;

		char *saveptr, *line;
		char *seed = strtok_r(data, "\n", &saveptr);
		// We don't care about the first line

		if ((line = strtok_r(NULL, "\n", &saveptr)) &&
				(line = strtok_r(NULL, "/", &saveptr)) &&
				(line = strtok_r(NULL, ",", &saveptr))) {
			hint = atoi(line);
		}

		if (hint > 64)
			hint = 64;

		c->lease.update_cb = pd_handle_update;
		pa_pd_lease_init(c->pd->pa_pd, &c->lease, seed, hint, 64);
		c->established = true;
	}
}


static void pd_accept(struct uloop_fd *fd, __unused unsigned int events)
{
	struct pd *pd = container_of(fd, struct pd, fd);
	for (;;) {
		int sock = accept(fd->fd, NULL, 0);
		if (sock < 0) {
			if (errno == EWOULDBLOCK)
				break;
			else
				continue;
		}

		struct pd_handle *handle = calloc(1, sizeof(*handle));
		handle->pd = pd;

		handle->fd.stream.notify_read = pd_handle_data;
		handle->fd.stream.notify_state = pd_handle_done;

		ustream_fd_init(&handle->fd, sock);
		list_add(&handle->head, &pd->handles);
	}
}


struct pd* pd_create(struct pa_pd *pa_pd, const char *path)
{
	unlink(path);
	int sock = usock(USOCK_TCP | USOCK_SERVER | USOCK_UNIX, path, NULL);
	if (sock < 0)
		return NULL;

	struct pd *pd = calloc(1, sizeof(*pd));
	INIT_LIST_HEAD(&pd->handles);
	pd->pa_pd = pa_pd;
	pd->fd.fd = sock;
	pd->fd.cb = pd_accept;

	uloop_fd_add(&pd->fd, ULOOP_READ | ULOOP_EDGE_TRIGGER);

	return pd;
}


void pd_destroy(struct pd *pd)
{
	while (!list_empty(&pd->handles))
		pd_handle_done(&list_first_entry(&pd->handles, struct pd_handle, head)->fd.stream);

	close(pd->fd.fd);
	free(pd);
}
