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

#include "mosquitto.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"
#ifdef WITH_BROKER
#include "mosquitto_broker.h"
#endif

int mosquitto__handle_pingreq(struct mosquitto *mosq)
{
	assert(mosq);
#ifdef WITH_BROKER
	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Received PINGREQ from %s", mosq->id);
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PINGREQ", mosq->id);
#endif
	return send__pingresp(mosq);
}

int mosquitto__handle_pingresp(struct mosquitto *mosq)
{
	assert(mosq);
	mosq->ping_t = 0; /* No longer waiting for a PINGRESP. */
#ifdef WITH_BROKER
	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Received PINGRESP from %s", mosq->id);
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PINGRESP", mosq->id);
#endif
	return MOSQ_ERR_SUCCESS;
}

#ifdef WITH_BROKER
int mosquitto__handle_pubackcomp(struct mosquitto_db *db, struct mosquitto *mosq, const char *type)
#else
int mosquitto__handle_pubackcomp(struct mosquitto *mosq, const char *type)
#endif
{
	uint16_t mid;
	int rc;

	assert(mosq);
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
#ifdef WITH_BROKER
	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Received %s from %s (Mid: %d)", type, mosq->id, mid);

	if(mid){
		rc = db__message_delete(db, mosq, mid, mosq_md_out);
		if(rc) return rc;
	}
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received %s (Mid: %d)", mosq->id, type, mid);

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

int mosquitto__handle_pubrec(struct mosquitto *mosq)
{
	uint16_t mid;
	int rc;

	assert(mosq);
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
#ifdef WITH_BROKER
	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Received PUBREC from %s (Mid: %d)", mosq->id, mid);

	rc = db__message_update(mosq, mid, mosq_md_out, mosq_ms_wait_for_pubcomp);
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PUBREC (Mid: %d)", mosq->id, mid);

	rc = message__out_update(mosq, mid, mosq_ms_wait_for_pubcomp);
#endif
	if(rc) return rc;
	rc = send__pubrel(mosq, mid);
	if(rc) return rc;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto__handle_pubrel(struct mosquitto_db *db, struct mosquitto *mosq)
{
	uint16_t mid;
#ifndef WITH_BROKER
	struct mosquitto_message_all *message = NULL;
#endif
	int rc;

	assert(mosq);
	if(mosq->protocol == mosq_p_mqtt311){
		if((mosq->in_packet.command&0x0F) != 0x02){
			return MOSQ_ERR_PROTOCOL;
		}
	}
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
#ifdef WITH_BROKER
	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Received PUBREL from %s (Mid: %d)", mosq->id, mid);

	if(db__message_release(db, mosq, mid, mosq_md_in)){
		/* Message not found. Still send a PUBCOMP anyway because this could be
		 * due to a repeated PUBREL after a client has reconnected. */
	}
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PUBREL (Mid: %d)", mosq->id, mid);

	if(!message__remove(mosq, mid, mosq_md_in, &message)){
		/* Only pass the message on if we have removed it from the queue - this
		 * prevents multiple callbacks for the same message. */
		pthread_mutex_lock(&mosq->callback_mutex);
		if(mosq->on_message){
			mosq->in_callback = true;
			mosq->on_message(mosq, mosq->userdata, &message->msg);
			mosq->in_callback = false;
		}
		pthread_mutex_unlock(&mosq->callback_mutex);
		message__cleanup(&message);
	}
#endif
	rc = send__pubcomp(mosq, mid);
	if(rc) return rc;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto__handle_suback(struct mosquitto *mosq)
{
	uint16_t mid;
	uint8_t qos;
	int *granted_qos;
	int qos_count;
	int i = 0;
	int rc;

	assert(mosq);
#ifdef WITH_BROKER
	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Received SUBACK from %s", mosq->id);
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received SUBACK", mosq->id);
#endif
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;

	qos_count = mosq->in_packet.remaining_length - mosq->in_packet.pos;
	granted_qos = mosquitto__malloc(qos_count*sizeof(int));
	if(!granted_qos) return MOSQ_ERR_NOMEM;
	while(mosq->in_packet.pos < mosq->in_packet.remaining_length){
		rc = packet__read_byte(&mosq->in_packet, &qos);
		if(rc){
			mosquitto__free(granted_qos);
			return rc;
		}
		granted_qos[i] = (int)qos;
		i++;
	}
#ifndef WITH_BROKER
	pthread_mutex_lock(&mosq->callback_mutex);
	if(mosq->on_subscribe){
		mosq->in_callback = true;
		mosq->on_subscribe(mosq, mosq->userdata, mid, qos_count, granted_qos);
		mosq->in_callback = false;
	}
	pthread_mutex_unlock(&mosq->callback_mutex);
#endif
	mosquitto__free(granted_qos);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto__handle_unsuback(struct mosquitto *mosq)
{
	uint16_t mid;
	int rc;

	assert(mosq);
#ifdef WITH_BROKER
	mosquitto__log_printf(NULL, MOSQ_LOG_DEBUG, "Received UNSUBACK from %s", mosq->id);
#else
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received UNSUBACK", mosq->id);
#endif
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
#ifndef WITH_BROKER
	pthread_mutex_lock(&mosq->callback_mutex);
	if(mosq->on_unsubscribe){
		mosq->in_callback = true;
	   	mosq->on_unsubscribe(mosq, mosq->userdata, mid);
		mosq->in_callback = false;
	}
	pthread_mutex_unlock(&mosq->callback_mutex);
#endif

	return MOSQ_ERR_SUCCESS;
}

