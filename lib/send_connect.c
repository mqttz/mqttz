/*
Copyright (c) 2009-2018 Roger Light <roger@atchoo.org>

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

#include "config.h"

#include <assert.h>
#include <string.h>

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#endif

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "mqtt_protocol.h"
#include "packet_mosq.h"
#include "property_mosq.h"

int send__connect(struct mosquitto *mosq, uint16_t keepalive, bool clean_session, const struct mqtt5__property *properties)
{
	struct mosquitto__packet *packet = NULL;
	int payloadlen;
	uint8_t will = 0;
	uint8_t byte;
	int rc;
	uint8_t version;
	char *clientid, *username, *password;
	int headerlen;
	int proplen, varbytes;

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

	if(mosq->protocol == mosq_p_mqtt5){
		version = MQTT_PROTOCOL_V5;
		headerlen = 10;
		proplen = property__get_length_all(properties);
		varbytes = packet__varint_bytes(proplen);
		headerlen += proplen + varbytes;
	}else if(mosq->protocol == mosq_p_mqtt311){
		version = MQTT_PROTOCOL_V311;
		headerlen = 10;
	}else if(mosq->protocol == mosq_p_mqtt31){
		version = MQTT_PROTOCOL_V31;
		headerlen = 12;
	}else{
		return MOSQ_ERR_INVAL;
	}

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	payloadlen = 2+strlen(clientid);
	if(mosq->will){
		will = 1;
		assert(mosq->will->msg.topic);

		payloadlen += 2+strlen(mosq->will->msg.topic) + 2+mosq->will->msg.payloadlen;
		if(mosq->protocol == mosq_p_mqtt5){
			proplen = property__get_length_all(mosq->will->properties);
			varbytes = packet__varint_bytes(proplen);
			payloadlen += proplen + varbytes;
		}
	}
	if(username){
		payloadlen += 2+strlen(username);
		if(password){
			payloadlen += 2+strlen(password);
		}
	}

	packet->command = CMD_CONNECT;
	packet->remaining_length = headerlen + payloadlen;
	rc = packet__alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}

	/* Variable header */
	if(version == MQTT_PROTOCOL_V31){
		packet__write_string(packet, PROTOCOL_NAME_v31, strlen(PROTOCOL_NAME_v31));
	}else{
		packet__write_string(packet, PROTOCOL_NAME, strlen(PROTOCOL_NAME));
	}
#if defined(WITH_BROKER) && defined(WITH_BRIDGE)
	if(mosq->bridge && mosq->bridge->try_private && mosq->bridge->try_private_accepted){
		version |= 0x80;
	}else{
	}
#endif
	packet__write_byte(packet, version);
	byte = (clean_session&0x1)<<1;
	if(will){
		byte = byte | ((mosq->will->msg.retain&0x1)<<5) | ((mosq->will->msg.qos&0x3)<<3) | ((will&0x1)<<2);
	}
	if(username){
		byte = byte | 0x1<<7;
		if(mosq->password){
			byte = byte | 0x1<<6;
		}
	}
	packet__write_byte(packet, byte);
	packet__write_uint16(packet, keepalive);

	if(mosq->protocol == mosq_p_mqtt5){
		/* Write properties */
		property__write_all(packet, properties);
	}

	/* Payload */
	packet__write_string(packet, clientid, strlen(clientid));
	if(will){
		if(mosq->protocol == mosq_p_mqtt5){
			/* Write will properties */
			property__write_all(packet, mosq->will->properties);
		}
		packet__write_string(packet, mosq->will->msg.topic, strlen(mosq->will->msg.topic));
		packet__write_string(packet, (const char *)mosq->will->msg.payload, mosq->will->msg.payloadlen);
	}
	if(username){
		packet__write_string(packet, username, strlen(username));
		if(password){
			packet__write_string(packet, password, strlen(password));
		}
	}

	mosq->keepalive = keepalive;
#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	log__printf(mosq, MOSQ_LOG_DEBUG, "Bridge %s sending CONNECT", clientid);
# endif
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending CONNECT", clientid);
#endif
	return packet__queue(mosq, packet);
}

