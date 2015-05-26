/*
 * $Id: udp46.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu May 15 12:16:06 2014 mstenber
 * Last modified: Thu May 15 13:55:33 2014 mstenber
 * Edit time:     22 min
 *
 */

#ifndef UDP46_H
#define UDP46_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 *
 * As dual-stack IPv6 (listening) UDP sockets are broken on many
 * platforms, this module provides an abstraction of a socket that is
 * actually _two_ sockets underneath: IPv4-only one, and IPv6-only
 * one, with convenience APIs for sending and receiving packets.
 *
 * All structures coming in and out are sockaddr_in6's. sockaddr_in
 * (and in_addr) are hidden.
 */

typedef struct udp46_t *udp46;

/**
 * Create/open a new socket.
 *
 * Effectively combination of socket(), bind().
 *
 * Port is the port it is bound to, or 0 if left up to library.  (The
 * library will get same port # for both IPv4 and IPv6 sockets it
 * creates underneath).
 */
udp46 udp46_create(uint16_t port);

/**
 * Get the socket fds.
 */
void udp46_get_fds(udp46 s, int *fd1, int *fd2);

/**
 * Receive a packet.
 *
 * Equivalent of socket type specific recvmsg() + magic to handle
 * source and destination addresses. -1 is returned if no packet
 * available. src and dst are optional.
 */
ssize_t udp46_recv(udp46 s,
                   struct sockaddr_in6 *src,
                   struct sockaddr_in6 *dst,
                   void *buf, size_t buf_size);

/**
 * Send a packet.
 *
 * Equivalent of socket type specific sendmsg() + magic to handle
 * source and destination addresses.
 **/
int udp46_send_iovec(udp46 s,
                     const struct sockaddr_in6 *src,
                     const struct sockaddr_in6 *dst,
                     struct iovec *iov, int iov_len);

/**
 * Destroy/close a socket.
 */
void udp46_destroy(udp46 s);

#endif /* UDP46_H */
