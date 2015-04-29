/*
Copyright (c) 2010-2015 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/
#ifndef _NET_MOSQ_H_
#define _NET_MOSQ_H_

#ifndef WIN32
#include <unistd.h>
#else
#include <winsock2.h>
typedef int ssize_t;
#endif

#include "mosquitto_internal.h"
#include "mosquitto.h"

#ifdef WITH_BROKER
struct mosquitto_db;
#endif

#ifdef WIN32
#  define COMPAT_CLOSE(a) closesocket(a)
#  define COMPAT_ECONNRESET WSAECONNRESET
#  define COMPAT_EWOULDBLOCK WSAEWOULDBLOCK
#else
#  define COMPAT_CLOSE(a) close(a)
#  define COMPAT_ECONNRESET ECONNRESET
#  define COMPAT_EWOULDBLOCK EWOULDBLOCK
#endif

/* For when not using winsock libraries. */
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

/* Macros for accessing the MSB and LSB of a uint16_t */
#define MOSQ_MSB(A) (uint8_t)((A & 0xFF00) >> 8)
#define MOSQ_LSB(A) (uint8_t)(A & 0x00FF)

void mosquitto__net_init(void);
void mosquitto__net_cleanup(void);

int mosquitto__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking);
#ifdef WITH_BROKER
int mosquitto__socket_close(struct mosquitto_db *db, struct mosquitto *mosq);
#else
int mosquitto__socket_close(struct mosquitto *mosq);
#endif
int mosquitto__try_connect(struct mosquitto *mosq, const char *host, uint16_t port, int *sock, const char *bind_address, bool blocking);
int mosquitto__socket_nonblock(int sock);
int mosquitto__socketpair(int *sp1, int *sp2);

ssize_t mosquitto__net_read(struct mosquitto *mosq, void *buf, size_t count);
ssize_t mosquitto__net_write(struct mosquitto *mosq, void *buf, size_t count);

#ifdef WITH_TLS
int mosquitto__socket_apply_tls(struct mosquitto *mosq);
int mosquitto__socket_connect_tls(struct mosquitto *mosq);
#endif

#endif
