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

#include "config.h"

#include "mosquitto_broker.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "util_mosq.h"

int mosquitto__send_connack(struct mosquitto *context, int ack, int result)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	if(context){
		if(context->id){
			mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending CONNACK to %s (%d, %d)", context->id, ack, result);
		}else{
			mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending CONNACK to %s (%d, %d)", context->address, ack, result);
		}
	}

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = CONNACK;
	packet->remaining_length = 2;
	rc = mosquitto__packet_alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}
	packet->payload[packet->pos+0] = ack;
	packet->payload[packet->pos+1] = result;

	return mosquitto__packet_queue(context, packet);
}

int mosquitto__send_suback(struct mosquitto *context, uint16_t mid, uint32_t payloadlen, const void *payload)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Sending SUBACK to %s", context->id);

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = SUBACK;
	packet->remaining_length = 2+payloadlen;
	rc = mosquitto__packet_alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}
	mosquitto__write_uint16(packet, mid);
	if(payloadlen){
		mosquitto__write_bytes(packet, payload, payloadlen);
	}

	return mosquitto__packet_queue(context, packet);
}
