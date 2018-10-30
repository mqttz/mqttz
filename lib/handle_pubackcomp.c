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
#include <stdio.h>
#include <string.h>

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#endif

#include "mosquitto.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"


#ifdef WITH_BROKER
int handle__pubackcomp(struct mosquitto_db *db, struct mosquitto *mosq, const char *type)
#else
int handle__pubackcomp(struct mosquitto *mosq, const char *type)
#endif
{
	uint16_t mid;
	int rc;
	struct mqtt5__property *properties = NULL;

	assert(mosq);
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
	if(mid == 0) return MOSQ_ERR_PROTOCOL;

	if(mosq->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_PUBACK, &mosq->in_packet, &properties);
		if(rc) return rc;
		/* Immediately free, we don't do anything with Reason String or User Property at the moment */
		mosquitto_property_free_all(&properties);
	}

#ifdef WITH_BROKER
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received %s from %s (Mid: %d)", type, mosq->id, mid);

	if(mid){
		rc = db__message_delete(db, mosq, mid, mosq_md_out);
		if(rc == MOSQ_ERR_NOT_FOUND){
			log__printf(mosq, MOSQ_LOG_WARNING, "Warning: Received %s from %s for an unknown packet identifier %d.", type, mosq->id, mid);
			return MOSQ_ERR_SUCCESS;
		}else{
			return rc;
		}
	}
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received %s (Mid: %d)", mosq->id, type, mid);

	if(!message__delete(mosq, mid, mosq_md_out)){
		/* Only inform the client the message has been sent once. */
		pthread_mutex_lock(&mosq->callback_mutex);
		if(mosq->on_publish){
			mosq->in_callback = true;
			mosq->on_publish(mosq, mosq->userdata, mid);
			mosq->in_callback = false;
		}
		pthread_mutex_unlock(&mosq->callback_mutex);
	}
#endif

	return MOSQ_ERR_SUCCESS;
}

