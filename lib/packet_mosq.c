/*
Copyright (c) 2009-2015 Roger Light <roger@atchoo.org>

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

#if 0
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef __ANDROID__
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/endian.h>
#endif

#ifdef __FreeBSD__
#  include <netinet/in.h>
#endif

#ifdef __SYMBIAN32__
#include <netinet/in.h>
#endif

#ifdef __QNX__
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0
#endif
#include <net/netbyte.h>
#include <netinet/in.h>
#endif

#ifdef WITH_TLS
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <tls_mosq.h>
#endif

#ifdef WITH_BROKER
#  include <mosquitto_broker.h>
#  ifdef WITH_SYS_TREE
   extern uint64_t g_bytes_received;
   extern uint64_t g_bytes_sent;
   extern unsigned long g_msgs_received;
   extern unsigned long g_msgs_sent;
   extern unsigned long g_pub_msgs_received;
   extern unsigned long g_pub_msgs_sent;
#  endif
#  ifdef WITH_WEBSOCKETS
#    include <libwebsockets.h>
#  endif
#else
#  include <read_handle.h>
#endif

#include <logging_mosq.h>
#include <time_mosq.h>
#include <util_mosq.h>
#endif

#include <assert.h>
#include <errno.h>

#ifdef WITH_BROKER
#  include <mosquitto_broker.h>
#  ifdef WITH_SYS_TREE
   extern uint64_t g_bytes_received;
   extern uint64_t g_bytes_sent;
   extern unsigned long g_msgs_received;
   extern unsigned long g_msgs_sent;
   extern unsigned long g_pub_msgs_received;
   extern unsigned long g_pub_msgs_sent;
#  endif
#  ifdef WITH_WEBSOCKETS
#    include <libwebsockets.h>
#  endif
#else
#  include <read_handle.h>
#endif


#include "memory_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"

void mosquitto__packet_cleanup(struct mosquitto__packet *packet)
{
	if(!packet) return;

	/* Free data and reset values */
	packet->command = 0;
	packet->remaining_count = 0;
	packet->remaining_mult = 1;
	packet->remaining_length = 0;
	if(packet->payload) mosquitto__free(packet->payload);
	packet->payload = NULL;
	packet->to_process = 0;
	packet->pos = 0;
}

int mosquitto__packet_queue(struct mosquitto *mosq, struct mosquitto__packet *packet)
{
#ifndef WITH_BROKER
	char sockpair_data = 0;
#endif
	assert(mosq);
	assert(packet);

	packet->pos = 0;
	packet->to_process = packet->packet_length;

	packet->next = NULL;
	pthread_mutex_lock(&mosq->out_packet_mutex);
	if(mosq->out_packet){
		mosq->out_packet_last->next = packet;
	}else{
		mosq->out_packet = packet;
	}
	mosq->out_packet_last = packet;
	pthread_mutex_unlock(&mosq->out_packet_mutex);
#ifdef WITH_BROKER
#  ifdef WITH_WEBSOCKETS
	if(mosq->wsi){
		libwebsocket_callback_on_writable(mosq->ws_context, mosq->wsi);
		return 0;
	}else{
		return mosquitto__packet_write(mosq);
	}
#  else
	return mosquitto__packet_write(mosq);
#  endif
#else

	/* Write a single byte to sockpairW (connected to sockpairR) to break out
	 * of select() if in threaded mode. */
	if(mosq->sockpairW != INVALID_SOCKET){
#ifndef WIN32
		if(write(mosq->sockpairW, &sockpair_data, 1)){
		}
#else
		send(mosq->sockpairW, &sockpair_data, 1, 0);
#endif
	}

	if(mosq->in_callback == false && mosq->threaded == false){
		return mosquitto__packet_write(mosq);
	}else{
		return MOSQ_ERR_SUCCESS;
	}
#endif
}


int mosquitto__read_byte(struct mosquitto__packet *packet, uint8_t *byte)
{
	assert(packet);
	if(packet->pos+1 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	*byte = packet->payload[packet->pos];
	packet->pos++;

	return MOSQ_ERR_SUCCESS;
}


void mosquitto__write_byte(struct mosquitto__packet *packet, uint8_t byte)
{
	assert(packet);
	assert(packet->pos+1 <= packet->packet_length);

	packet->payload[packet->pos] = byte;
	packet->pos++;
}


int mosquitto__read_bytes(struct mosquitto__packet *packet, void *bytes, uint32_t count)
{
	assert(packet);
	if(packet->pos+count > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	memcpy(bytes, &(packet->payload[packet->pos]), count);
	packet->pos += count;

	return MOSQ_ERR_SUCCESS;
}


void mosquitto__write_bytes(struct mosquitto__packet *packet, const void *bytes, uint32_t count)
{
	assert(packet);
	assert(packet->pos+count <= packet->packet_length);

	memcpy(&(packet->payload[packet->pos]), bytes, count);
	packet->pos += count;
}


int mosquitto__read_string(struct mosquitto__packet *packet, char **str)
{
	uint16_t len;
	int rc;

	assert(packet);
	rc = mosquitto__read_uint16(packet, &len);
	if(rc) return rc;

	if(packet->pos+len > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	*str = mosquitto__malloc(len+1);
	if(*str){
		memcpy(*str, &(packet->payload[packet->pos]), len);
		(*str)[len] = '\0';
		packet->pos += len;
	}else{
		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}


void mosquitto__write_string(struct mosquitto__packet *packet, const char *str, uint16_t length)
{
	assert(packet);
	mosquitto__write_uint16(packet, length);
	mosquitto__write_bytes(packet, str, length);
}


int mosquitto__read_uint16(struct mosquitto__packet *packet, uint16_t *word)
{
	uint8_t msb, lsb;

	assert(packet);
	if(packet->pos+2 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	msb = packet->payload[packet->pos];
	packet->pos++;
	lsb = packet->payload[packet->pos];
	packet->pos++;

	*word = (msb<<8) + lsb;

	return MOSQ_ERR_SUCCESS;
}


void mosquitto__write_uint16(struct mosquitto__packet *packet, uint16_t word)
{
	mosquitto__write_byte(packet, MOSQ_MSB(word));
	mosquitto__write_byte(packet, MOSQ_LSB(word));
}


int mosquitto__packet_write(struct mosquitto *mosq)
{
	ssize_t write_length;
	struct mosquitto__packet *packet;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	pthread_mutex_lock(&mosq->current_out_packet_mutex);
	pthread_mutex_lock(&mosq->out_packet_mutex);
	if(mosq->out_packet && !mosq->current_out_packet){
		mosq->current_out_packet = mosq->out_packet;
		mosq->out_packet = mosq->out_packet->next;
		if(!mosq->out_packet){
			mosq->out_packet_last = NULL;
		}
	}
	pthread_mutex_unlock(&mosq->out_packet_mutex);

	if(mosq->state == mosq_cs_connect_pending){
		pthread_mutex_unlock(&mosq->current_out_packet_mutex);
		return MOSQ_ERR_SUCCESS;
	}

	while(mosq->current_out_packet){
		packet = mosq->current_out_packet;

		while(packet->to_process > 0){
			write_length = mosquitto__net_write(mosq, &(packet->payload[packet->pos]), packet->to_process);
			if(write_length > 0){
#if defined(WITH_BROKER) && defined(WITH_SYS_TREE)
				g_bytes_sent += write_length;
#endif
				packet->to_process -= write_length;
				packet->pos += write_length;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					pthread_mutex_unlock(&mosq->current_out_packet_mutex);
					return MOSQ_ERR_SUCCESS;
				}else{
					pthread_mutex_unlock(&mosq->current_out_packet_mutex);
					switch(errno){
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}

#ifdef WITH_BROKER
#  ifdef WITH_SYS_TREE
		g_msgs_sent++;
		if(((packet->command)&0xF6) == PUBLISH){
			g_pub_msgs_sent++;
		}
#  endif
#else
		if(((packet->command)&0xF6) == PUBLISH){
			pthread_mutex_lock(&mosq->callback_mutex);
			if(mosq->on_publish){
				/* This is a QoS=0 message */
				mosq->in_callback = true;
				mosq->on_publish(mosq, mosq->userdata, packet->mid);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
		}else if(((packet->command)&0xF0) == DISCONNECT){
			/* FIXME what cleanup needs doing here? 
			 * incoming/outgoing messages? */
			mosquitto__socket_close(mosq);

			/* Start of duplicate, possibly unnecessary code.
			 * This does leave things in a consistent state at least. */
			/* Free data and reset values */
			pthread_mutex_lock(&mosq->out_packet_mutex);
			mosq->current_out_packet = mosq->out_packet;
			if(mosq->out_packet){
				mosq->out_packet = mosq->out_packet->next;
				if(!mosq->out_packet){
					mosq->out_packet_last = NULL;
				}
			}
			pthread_mutex_unlock(&mosq->out_packet_mutex);

			mosquitto__packet_cleanup(packet);
			mosquitto__free(packet);

			pthread_mutex_lock(&mosq->msgtime_mutex);
			mosq->last_msg_out = mosquitto_time();
			pthread_mutex_unlock(&mosq->msgtime_mutex);
			/* End of duplicate, possibly unnecessary code */

			pthread_mutex_lock(&mosq->callback_mutex);
			if(mosq->on_disconnect){
				mosq->in_callback = true;
				mosq->on_disconnect(mosq, mosq->userdata, 0);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
			pthread_mutex_unlock(&mosq->current_out_packet_mutex);
			return MOSQ_ERR_SUCCESS;
		}
#endif

		/* Free data and reset values */
		pthread_mutex_lock(&mosq->out_packet_mutex);
		mosq->current_out_packet = mosq->out_packet;
		if(mosq->out_packet){
			mosq->out_packet = mosq->out_packet->next;
			if(!mosq->out_packet){
				mosq->out_packet_last = NULL;
			}
		}
		pthread_mutex_unlock(&mosq->out_packet_mutex);

		mosquitto__packet_cleanup(packet);
		mosquitto__free(packet);

		pthread_mutex_lock(&mosq->msgtime_mutex);
		mosq->last_msg_out = mosquitto_time();
		pthread_mutex_unlock(&mosq->msgtime_mutex);
	}
	pthread_mutex_unlock(&mosq->current_out_packet_mutex);
	return MOSQ_ERR_SUCCESS;
}


#ifdef WITH_BROKER
int mosquitto__packet_read(struct mosquitto_db *db, struct mosquitto *mosq)
#else
int mosquitto__packet_read(struct mosquitto *mosq)
#endif
{
	uint8_t byte;
	ssize_t read_length;
	int rc = 0;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;
	if(mosq->state == mosq_cs_connect_pending){
		return MOSQ_ERR_SUCCESS;
	}

	/* This gets called if pselect() indicates that there is network data
	 * available - ie. at least one byte.  What we do depends on what data we
	 * already have.
	 * If we've not got a command, attempt to read one and save it. This should
	 * always work because it's only a single byte.
	 * Then try to read the remaining length. This may fail because it is may
	 * be more than one byte - will need to save data pending next read if it
	 * does fail.
	 * Then try to read the remaining payload, where 'payload' here means the
	 * combined variable header and actual payload. This is the most likely to
	 * fail due to longer length, so save current data and current position.
	 * After all data is read, send to mosquitto__handle_packet() to deal with.
	 * Finally, free the memory and reset everything to starting conditions.
	 */
	if(!mosq->in_packet.command){
		read_length = mosquitto__net_read(mosq, &byte, 1);
		if(read_length == 1){
			mosq->in_packet.command = byte;
#ifdef WITH_BROKER
#  ifdef WITH_SYS_TREE
			g_bytes_received++;
#  endif
			/* Clients must send CONNECT as their first command. */
			if(!(mosq->bridge) && mosq->state == mosq_cs_new && (byte&0xF0) != CONNECT) return MOSQ_ERR_PROTOCOL;
#endif
		}else{
			if(read_length == 0) return MOSQ_ERR_CONN_LOST; /* EOF */
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
				return MOSQ_ERR_SUCCESS;
			}else{
				switch(errno){
					case COMPAT_ECONNRESET:
						return MOSQ_ERR_CONN_LOST;
					default:
						return MOSQ_ERR_ERRNO;
				}
			}
		}
	}
	/* remaining_count is the number of bytes that the remaining_length
	 * parameter occupied in this incoming packet. We don't use it here as such
	 * (it is used when allocating an outgoing packet), but we must be able to
	 * determine whether all of the remaining_length parameter has been read.
	 * remaining_count has three states here:
	 *   0 means that we haven't read any remaining_length bytes
	 *   <0 means we have read some remaining_length bytes but haven't finished
	 *   >0 means we have finished reading the remaining_length bytes.
	 */
	if(mosq->in_packet.remaining_count <= 0){
		do{
			read_length = mosquitto__net_read(mosq, &byte, 1);
			if(read_length == 1){
				mosq->in_packet.remaining_count--;
				/* Max 4 bytes length for remaining length as defined by protocol.
				 * Anything more likely means a broken/malicious client.
				 */
				if(mosq->in_packet.remaining_count < -4) return MOSQ_ERR_PROTOCOL;

#if defined(WITH_BROKER) && defined(WITH_SYS_TREE)
				g_bytes_received++;
#endif
				mosq->in_packet.remaining_length += (byte & 127) * mosq->in_packet.remaining_mult;
				mosq->in_packet.remaining_mult *= 128;
			}else{
				if(read_length == 0) return MOSQ_ERR_CONN_LOST; /* EOF */
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					switch(errno){
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}while((byte & 128) != 0);
		/* We have finished reading remaining_length, so make remaining_count
		 * positive. */
		mosq->in_packet.remaining_count *= -1;

		if(mosq->in_packet.remaining_length > 0){
			mosq->in_packet.payload = mosquitto__malloc(mosq->in_packet.remaining_length*sizeof(uint8_t));
			if(!mosq->in_packet.payload) return MOSQ_ERR_NOMEM;
			mosq->in_packet.to_process = mosq->in_packet.remaining_length;
		}
	}
	while(mosq->in_packet.to_process>0){
		read_length = mosquitto__net_read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
		if(read_length > 0){
#if defined(WITH_BROKER) && defined(WITH_SYS_TREE)
			g_bytes_received += read_length;
#endif
			mosq->in_packet.to_process -= read_length;
			mosq->in_packet.pos += read_length;
		}else{
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
				if(mosq->in_packet.to_process > 1000){
					/* Update last_msg_in time if more than 1000 bytes left to
					 * receive. Helps when receiving large messages.
					 * This is an arbitrary limit, but with some consideration.
					 * If a client can't send 1000 bytes in a second it
					 * probably shouldn't be using a 1 second keep alive. */
					pthread_mutex_lock(&mosq->msgtime_mutex);
					mosq->last_msg_in = mosquitto_time();
					pthread_mutex_unlock(&mosq->msgtime_mutex);
				}
				return MOSQ_ERR_SUCCESS;
			}else{
				switch(errno){
					case COMPAT_ECONNRESET:
						return MOSQ_ERR_CONN_LOST;
					default:
						return MOSQ_ERR_ERRNO;
				}
			}
		}
	}

	/* All data for this packet is read. */
	mosq->in_packet.pos = 0;
#ifdef WITH_BROKER
#  ifdef WITH_SYS_TREE
	g_msgs_received++;
	if(((mosq->in_packet.command)&0xF5) == PUBLISH){
		g_pub_msgs_received++;
	}
#  endif
	rc = mqtt3_packet_handle(db, mosq);
#else
	rc = mosquitto__packet_handle(mosq);
#endif

	/* Free data and reset values */
	mosquitto__packet_cleanup(&mosq->in_packet);

	pthread_mutex_lock(&mosq->msgtime_mutex);
	mosq->last_msg_in = mosquitto_time();
	pthread_mutex_unlock(&mosq->msgtime_mutex);
	return rc;
}

