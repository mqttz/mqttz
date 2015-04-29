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
#include <string.h>

#include <mosquitto.h>
#include <logging_mosq.h>
#include <memory_mosq.h>
#include <mqtt3_protocol.h>
#include <net_mosq.h>
#include <packet_mosq.h>
#include <send_mosq.h>
#include <util_mosq.h>

#ifdef WITH_BROKER
#include <mosquitto_broker.h>
#endif

int mosquitto__send_connect(struct mosquitto *mosq, uint16_t keepalive, bool clean_session)
{
	struct mosquitto__packet *packet = NULL;
	int payloadlen;
	uint8_t will = 0;
	uint8_t byte;
	int rc;
	uint8_t version;
	char *clientid, *username, *password;
	int headerlen;

	assert(mosq);
	assert(mosq->id);

#if defined(WITH_BROKER) && defined(WITH_BRIDGE)
	if(mosq->bridge){
		clientid = mosq->bridge->remote_clientid;
		username = mosq->bridge->remote_username;
		password = mosq->bridge->remote_password;
	}else{
		clientid = mosq->id;
		username = mosq->username;
		password = mosq->password;
	}
#else
	clientid = mosq->id;
	username = mosq->username;
	password = mosq->password;
#endif

	if(mosq->protocol == mosq_p_mqtt31){
		version = MQTT_PROTOCOL_V31;
		headerlen = 12;
	}else if(mosq->protocol == mosq_p_mqtt311){
		version = MQTT_PROTOCOL_V311;
		headerlen = 10;
	}else{
		return MOSQ_ERR_INVAL;
	}

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	payloadlen = 2+strlen(clientid);
	if(mosq->will){
		will = 1;
		assert(mosq->will->topic);

		payloadlen += 2+strlen(mosq->will->topic) + 2+mosq->will->payloadlen;
	}
	if(username){
		payloadlen += 2+strlen(username);
		if(password){
			payloadlen += 2+strlen(password);
		}
	}

	packet->command = CONNECT;
	packet->remaining_length = headerlen+payloadlen;
	rc = mosquitto__packet_alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}

	/* Variable header */
	if(version == MQTT_PROTOCOL_V31){
		mosquitto__write_string(packet, PROTOCOL_NAME_v31, strlen(PROTOCOL_NAME_v31));
	}else if(version == MQTT_PROTOCOL_V311){
		mosquitto__write_string(packet, PROTOCOL_NAME_v311, strlen(PROTOCOL_NAME_v311));
	}else{
		mosquitto__free(packet);
		return MOSQ_ERR_INVAL;
	}
#if defined(WITH_BROKER) && defined(WITH_BRIDGE)
	if(mosq->bridge && mosq->bridge->try_private && mosq->bridge->try_private_accepted){
		version |= 0x80;
	}else{
	}
#endif
	mosquitto__write_byte(packet, version);
	byte = (clean_session&0x1)<<1;
	if(will){
		byte = byte | ((mosq->will->retain&0x1)<<5) | ((mosq->will->qos&0x3)<<3) | ((will&0x1)<<2);
	}
	if(username){
		byte = byte | 0x1<<7;
		if(mosq->password){
			byte = byte | 0x1<<6;
		}
	}
	mosquitto__write_byte(packet, byte);
	mosquitto__write_uint16(packet, keepalive);

	/* Payload */
	mosquitto__write_string(packet, clientid, strlen(clientid));
	if(will){
		mosquitto__write_string(packet, mosq->will->topic, strlen(mosq->will->topic));
		mosquitto__write_string(packet, (const char *)mosq->will->payload, mosq->will->payloadlen);
	}
	if(username){
		mosquitto__write_string(packet, username, strlen(username));
		if(password){
			mosquitto__write_string(packet, password, strlen(password));
		}
	}

	mosq->keepalive = keepalive;
#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Bridge %s sending CONNECT", clientid);
# endif
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending CONNECT", clientid);
#endif
	return mosquitto__packet_queue(mosq, packet);
}

int mosquitto__send_disconnect(struct mosquitto *mosq)
{
	assert(mosq);
#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Bridge %s sending DISCONNECT", mosq->id);
# endif
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending DISCONNECT", mosq->id);
#endif
	return mosquitto__send_simple_command(mosq, DISCONNECT);
}

int mosquitto__send_subscribe(struct mosquitto *mosq, int *mid, const char *topic, uint8_t topic_qos)
{
	/* FIXME - only deals with a single topic */
	struct mosquitto__packet *packet = NULL;
	uint32_t packetlen;
	uint16_t local_mid;
	int rc;

	assert(mosq);
	assert(topic);

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packetlen = 2 + 2+strlen(topic) + 1;

	packet->command = SUBSCRIBE | (1<<1);
	packet->remaining_length = packetlen;
	rc = mosquitto__packet_alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}

	/* Variable header */
	local_mid = mosquitto__mid_generate(mosq);
	if(mid) *mid = (int)local_mid;
	mosquitto__write_uint16(packet, local_mid);

	/* Payload */
	mosquitto__write_string(packet, topic, strlen(topic));
	mosquitto__write_byte(packet, topic_qos);

#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Bridge %s sending SUBSCRIBE (Mid: %d, Topic: %s, QoS: %d)", mosq->id, local_mid, topic, topic_qos);
# endif
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending SUBSCRIBE (Mid: %d, Topic: %s, QoS: %d)", mosq->id, local_mid, topic, topic_qos);
#endif

	return mosquitto__packet_queue(mosq, packet);
}


int mosquitto__send_unsubscribe(struct mosquitto *mosq, int *mid, const char *topic)
{
	/* FIXME - only deals with a single topic */
	struct mosquitto__packet *packet = NULL;
	uint32_t packetlen;
	uint16_t local_mid;
	int rc;

	assert(mosq);
	assert(topic);

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packetlen = 2 + 2+strlen(topic);

	packet->command = UNSUBSCRIBE | (1<<1);
	packet->remaining_length = packetlen;
	rc = mosquitto__packet_alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}

	/* Variable header */
	local_mid = mosquitto__mid_generate(mosq);
	if(mid) *mid = (int)local_mid;
	mosquitto__write_uint16(packet, local_mid);

	/* Payload */
	mosquitto__write_string(packet, topic, strlen(topic));

#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Bridge %s sending UNSUBSCRIBE (Mid: %d, Topic: %s)", mosq->id, local_mid, topic);
# endif
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending UNSUBSCRIBE (Mid: %d, Topic: %s)", mosq->id, local_mid, topic);
#endif
	return mosquitto__packet_queue(mosq, packet);
}

