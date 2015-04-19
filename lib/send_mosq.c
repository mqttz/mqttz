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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_internal.h>
#include <logging_mosq.h>
#include <mqtt3_protocol.h>
#include <memory_mosq.h>
#include <net_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <util_mosq.h>

#ifdef WITH_BROKER
#include <mosquitto_broker.h>
#  ifdef WITH_SYS_TREE
extern uint64_t g_pub_bytes_sent;
#  endif
#endif

int mosquitto__send_pingreq(struct mosquitto *mosq)
{
	int rc;
	assert(mosq);
#ifdef WITH_BROKER
	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PINGREQ to %s", mosq->id);
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PINGREQ", mosq->id);
#endif
	rc = mosquitto__send_simple_command(mosq, PINGREQ);
	if(rc == MOSQ_ERR_SUCCESS){
		mosq->ping_t = mosquitto_time();
	}
	return rc;
}

int mosquitto__send_pingresp(struct mosquitto *mosq)
{
#ifdef WITH_BROKER
	if(mosq) mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PINGRESP to %s", mosq->id);
#else
	if(mosq) mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PINGRESP", mosq->id);
#endif
	return mosquitto__send_simple_command(mosq, PINGRESP);
}

int mosquitto__send_puback(struct mosquitto *mosq, uint16_t mid)
{
#ifdef WITH_BROKER
	if(mosq) mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBACK to %s (Mid: %d)", mosq->id, mid);
#else
	if(mosq) mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBACK (Mid: %d)", mosq->id, mid);
#endif
	return mosquitto__send_command_with_mid(mosq, PUBACK, mid, false);
}

int mosquitto__send_pubcomp(struct mosquitto *mosq, uint16_t mid)
{
#ifdef WITH_BROKER
	if(mosq) mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBCOMP to %s (Mid: %d)", mosq->id, mid);
#else
	if(mosq) mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBCOMP (Mid: %d)", mosq->id, mid);
#endif
	return mosquitto__send_command_with_mid(mosq, PUBCOMP, mid, false);
}

int mosquitto__send_publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, int qos, bool retain, bool dup)
{
#ifdef WITH_BROKER
	size_t len;
#ifdef WITH_BRIDGE
	int i;
	struct mqtt3__bridge_topic *cur_topic;
	bool match;
	int rc;
	char *mapped_topic = NULL;
	char *topic_temp = NULL;
#endif
#endif
	assert(mosq);
	assert(topic);

#if defined(WITH_BROKER) && defined(WITH_WEBSOCKETS)
	if(mosq->sock == INVALID_SOCKET && !mosq->wsi) return MOSQ_ERR_NO_CONN;
#else
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;
#endif

#ifdef WITH_BROKER
	if(mosq->listener && mosq->listener->mount_point){
		len = strlen(mosq->listener->mount_point);
		if(len < strlen(topic)){
			topic += len;
		}else{
			/* Invalid topic string. Should never happen, but silently swallow the message anyway. */
			return MOSQ_ERR_SUCCESS;
		}
	}
#ifdef WITH_BRIDGE
	if(mosq->bridge && mosq->bridge->topics && mosq->bridge->topic_remapping){
		for(i=0; i<mosq->bridge->topic_count; i++){
			cur_topic = &mosq->bridge->topics[i];
			if((cur_topic->direction == bd_both || cur_topic->direction == bd_out) 
					&& (cur_topic->remote_prefix || cur_topic->local_prefix)){
				/* Topic mapping required on this topic if the message matches */

				rc = mosquitto_topic_matches_sub(cur_topic->local_topic, topic, &match);
				if(rc){
					return rc;
				}
				if(match){
					mapped_topic = mosquitto__strdup(topic);
					if(!mapped_topic) return MOSQ_ERR_NOMEM;
					if(cur_topic->local_prefix){
						/* This prefix needs removing. */
						if(!strncmp(cur_topic->local_prefix, mapped_topic, strlen(cur_topic->local_prefix))){
							topic_temp = mosquitto__strdup(mapped_topic+strlen(cur_topic->local_prefix));
							mosquitto__free(mapped_topic);
							if(!topic_temp){
								return MOSQ_ERR_NOMEM;
							}
							mapped_topic = topic_temp;
						}
					}

					if(cur_topic->remote_prefix){
						/* This prefix needs adding. */
						len = strlen(mapped_topic) + strlen(cur_topic->remote_prefix)+1;
						topic_temp = mosquitto__malloc(len+1);
						if(!topic_temp){
							mosquitto__free(mapped_topic);
							return MOSQ_ERR_NOMEM;
						}
						snprintf(topic_temp, len, "%s%s", cur_topic->remote_prefix, mapped_topic);
						topic_temp[len] = '\0';
						mosquitto__free(mapped_topic);
						mapped_topic = topic_temp;
					}
					mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBLISH to %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", mosq->id, dup, qos, retain, mid, mapped_topic, (long)payloadlen);
#ifdef WITH_SYS_TREE
					g_pub_bytes_sent += payloadlen;
#endif
					rc =  mosquitto__send_real_publish(mosq, mid, mapped_topic, payloadlen, payload, qos, retain, dup);
					mosquitto__free(mapped_topic);
					return rc;
				}
			}
		}
	}
#endif
	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBLISH to %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", mosq->id, dup, qos, retain, mid, topic, (long)payloadlen);
#  ifdef WITH_SYS_TREE
	g_pub_bytes_sent += payloadlen;
#  endif
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBLISH (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", mosq->id, dup, qos, retain, mid, topic, (long)payloadlen);
#endif

	return mosquitto__send_real_publish(mosq, mid, topic, payloadlen, payload, qos, retain, dup);
}

int mosquitto__send_pubrec(struct mosquitto *mosq, uint16_t mid)
{
#ifdef WITH_BROKER
	if(mosq) mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBREC to %s (Mid: %d)", mosq->id, mid);
#else
	if(mosq) mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBREC (Mid: %d)", mosq->id, mid);
#endif
	return mosquitto__send_command_with_mid(mosq, PUBREC, mid, false);
}

int mosquitto__send_pubrel(struct mosquitto *mosq, uint16_t mid)
{
#ifdef WITH_BROKER
	if(mosq) mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBREL to %s (Mid: %d)", mosq->id, mid);
#else
	if(mosq) mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBREL (Mid: %d)", mosq->id, mid);
#endif
	return mosquitto__send_command_with_mid(mosq, PUBREL|2, mid, false);
}

/* For PUBACK, PUBCOMP, PUBREC, and PUBREL */
int mosquitto__send_command_with_mid(struct mosquitto *mosq, uint8_t command, uint16_t mid, bool dup)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	assert(mosq);
	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = command;
	if(dup){
		packet->command |= 8;
	}
	packet->remaining_length = 2;
	rc = mosquitto__packet_alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}

	packet->payload[packet->pos+0] = MOSQ_MSB(mid);
	packet->payload[packet->pos+1] = MOSQ_LSB(mid);

	return mosquitto__packet_queue(mosq, packet);
}

/* For DISCONNECT, PINGREQ and PINGRESP */
int mosquitto__send_simple_command(struct mosquitto *mosq, uint8_t command)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	assert(mosq);
	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = command;
	packet->remaining_length = 0;

	rc = mosquitto__packet_alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}

	return mosquitto__packet_queue(mosq, packet);
}

int mosquitto__send_real_publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, int qos, bool retain, bool dup)
{
	struct mosquitto__packet *packet = NULL;
	int packetlen;
	int rc;

	assert(mosq);
	assert(topic);

	packetlen = 2+strlen(topic) + payloadlen;
	if(qos > 0) packetlen += 2; /* For message id */
	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->mid = mid;
	packet->command = PUBLISH | ((dup&0x1)<<3) | (qos<<1) | retain;
	packet->remaining_length = packetlen;
	rc = mosquitto__packet_alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}
	/* Variable header (topic string) */
	mosquitto__write_string(packet, topic, strlen(topic));
	if(qos > 0){
		mosquitto__write_uint16(packet, mid);
	}

	/* Payload */
	if(payloadlen){
		mosquitto__write_bytes(packet, payload, payloadlen);
	}

	return mosquitto__packet_queue(mosq, packet);
}
