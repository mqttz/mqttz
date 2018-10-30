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

#include "mosquitto.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "read_handle.h"

int handle__connack(struct mosquitto *mosq)
{
	uint8_t connect_flags;
	uint8_t reason_code;
	int rc;
	struct mqtt5__property *properties = NULL;

	assert(mosq);
	rc = packet__read_byte(&mosq->in_packet, &connect_flags);
	if(rc) return rc;
	rc = packet__read_byte(&mosq->in_packet, &reason_code);
	if(rc) return rc;

	if(mosq->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_CONNACK, &mosq->in_packet, &properties);
		if(rc) return rc;
		mosquitto_property_free_all(&properties);
	}
	mosquitto_property_free_all(&properties); /* FIXME - TEMPORARY UNTIL PROPERTIES PROCESSED */

	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received CONNACK (%d)", mosq->id, reason_code);
	pthread_mutex_lock(&mosq->callback_mutex);
	if(mosq->on_connect){
		mosq->in_callback = true;
		mosq->on_connect(mosq, mosq->userdata, reason_code);
		mosq->in_callback = false;
	}
	if(mosq->on_connect_with_flags){
		mosq->in_callback = true;
		mosq->on_connect_with_flags(mosq, mosq->userdata, reason_code, connect_flags);
		mosq->in_callback = false;
	}
	pthread_mutex_unlock(&mosq->callback_mutex);
	switch(reason_code){
		case 0:
			if(mosq->state != mosq_cs_disconnecting){
				mosq->state = mosq_cs_connected;
			}
			message__retry_check(mosq);
			return MOSQ_ERR_SUCCESS;
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
			return MOSQ_ERR_CONN_REFUSED;
		default:
			return MOSQ_ERR_PROTOCOL;
	}
}

