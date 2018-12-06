/*
Copyright (c) 2010-2018 Roger Light <roger@atchoo.org>

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

#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "send_mosq.h"
#include "util_mosq.h"


int mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	return mosquitto_publish_v5(mosq, mid, topic, payloadlen, payload, qos, retain, NULL);
}

int mosquitto_publish_v5(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain, const mosquitto_property *properties)
{
	struct mosquitto_message_all *message;
	uint16_t local_mid;
	int queue_status;
	const mosquitto_property *p;
	const mosquitto_property *outgoing_properties = NULL;
	mosquitto_property local_property;
	bool have_topic_alias;
	int rc;

	if(!mosq || qos<0 || qos>2) return MOSQ_ERR_INVAL;
	if(mosq->protocol != mosq_p_mqtt5 && properties) return MOSQ_ERR_NOT_SUPPORTED;

	if(properties){
		if(properties->client_generated){
			outgoing_properties = properties;
		}else{
			memcpy(&local_property, properties, sizeof(mosquitto_property));
			local_property.client_generated = true;
			local_property.next = NULL;
			outgoing_properties = &local_property;
		}
		rc = mosquitto_property_check_all(CMD_PUBLISH, outgoing_properties);
		if(rc) return rc;
	}

	if(!topic || STREMPTY(topic)){
		if(topic) topic = NULL;

		if(mosq->protocol == mosq_p_mqtt5){
			p = outgoing_properties;
			have_topic_alias = false;
			while(p){
				if(p->identifier == MQTT_PROP_TOPIC_ALIAS){
					have_topic_alias = true;
					break;
				}
				p = p->next;
			}
			if(have_topic_alias == false){
				return MOSQ_ERR_INVAL;
			}
		}else{
			return MOSQ_ERR_INVAL;
		}
	}else{
		if(mosquitto_validate_utf8(topic, strlen(topic))) return MOSQ_ERR_MALFORMED_UTF8;
		if(payloadlen < 0 || payloadlen > MQTT_MAX_PAYLOAD) return MOSQ_ERR_PAYLOAD_SIZE;
		if(mosquitto_pub_topic_check(topic) != MOSQ_ERR_SUCCESS){
			return MOSQ_ERR_INVAL;
		}
	}

	local_mid = mosquitto__mid_generate(mosq);
	if(mid){
		*mid = local_mid;
	}

	if(qos == 0){
		return send__publish(mosq, local_mid, topic, payloadlen, payload, qos, retain, false, outgoing_properties);
	}else{
		message = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
		if(!message) return MOSQ_ERR_NOMEM;

		message->next = NULL;
		message->timestamp = mosquitto_time();
		message->msg.mid = local_mid;
		if(topic){
			message->msg.topic = mosquitto__strdup(topic);
			if(!message->msg.topic){
				message__cleanup(&message);
				return MOSQ_ERR_NOMEM;
			}
		}
		if(payloadlen){
			message->msg.payloadlen = payloadlen;
			message->msg.payload = mosquitto__malloc(payloadlen*sizeof(uint8_t));
			if(!message->msg.payload){
				message__cleanup(&message);
				return MOSQ_ERR_NOMEM;
			}
			memcpy(message->msg.payload, payload, payloadlen*sizeof(uint8_t));
		}else{
			message->msg.payloadlen = 0;
			message->msg.payload = NULL;
		}
		message->msg.qos = qos;
		message->msg.retain = retain;
		message->dup = false;

		pthread_mutex_lock(&mosq->out_message_mutex);
		queue_status = message__queue(mosq, message, mosq_md_out);
		if(queue_status == 0){
			if(qos == 1){
				message->state = mosq_ms_wait_for_puback;
			}else if(qos == 2){
				message->state = mosq_ms_wait_for_pubrec;
			}
			pthread_mutex_unlock(&mosq->out_message_mutex);
			return send__publish(mosq, message->msg.mid, message->msg.topic, message->msg.payloadlen, message->msg.payload, message->msg.qos, message->msg.retain, message->dup, outgoing_properties);
		}else{
			message->state = mosq_ms_invalid;
			pthread_mutex_unlock(&mosq->out_message_mutex);
			return MOSQ_ERR_SUCCESS;
		}
	}
}


int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos)
{
	return mosquitto_subscribe_v5(mosq, mid, sub, qos, NULL);
}

int mosquitto_subscribe_v5(struct mosquitto *mosq, int *mid, const char *sub, int qos, const mosquitto_property *properties)
{
	const mosquitto_property *outgoing_properties = NULL;
	mosquitto_property local_property;

	int rc;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->protocol != mosq_p_mqtt5 && properties) return MOSQ_ERR_NOT_SUPPORTED;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	if(mosquitto_sub_topic_check(sub)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(sub, strlen(sub))) return MOSQ_ERR_MALFORMED_UTF8;

	if(properties){
		if(properties->client_generated){
			outgoing_properties = properties;
		}else{
			memcpy(&local_property, properties, sizeof(mosquitto_property));
			local_property.client_generated = true;
			local_property.next = NULL;
			outgoing_properties = &local_property;
		}
		rc = mosquitto_property_check_all(CMD_SUBSCRIBE, outgoing_properties);
		if(rc) return rc;
	}

	return send__subscribe(mosq, mid, 1, (char *const *const)&sub, qos, outgoing_properties);
}


int mosquitto_subscribe_multiple(struct mosquitto *mosq, int *mid, int sub_count, char *const *const sub, int qos, const mosquitto_property *properties)
{
	const mosquitto_property *outgoing_properties = NULL;
	mosquitto_property local_property;
	int i;
	int rc;

	if(!mosq || !sub_count || !sub) return MOSQ_ERR_INVAL;
	if(mosq->protocol != mosq_p_mqtt5 && properties) return MOSQ_ERR_NOT_SUPPORTED;
	if(qos < 0 || qos > 2) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	if(properties){
		if(properties->client_generated){
			outgoing_properties = properties;
		}else{
			memcpy(&local_property, properties, sizeof(mosquitto_property));
			local_property.client_generated = true;
			local_property.next = NULL;
			outgoing_properties = &local_property;
		}
		rc = mosquitto_property_check_all(CMD_SUBSCRIBE, outgoing_properties);
		if(rc) return rc;
	}

	for(i=0; i<sub_count; i++){
		if(mosquitto_sub_topic_check(sub[i])) return MOSQ_ERR_INVAL;
		if(mosquitto_validate_utf8(sub[i], strlen(sub[i]))) return MOSQ_ERR_MALFORMED_UTF8;
	}

	return send__subscribe(mosq, mid, sub_count, sub, qos, properties);
}


int mosquitto_unsubscribe(struct mosquitto *mosq, int *mid, const char *sub)
{
	return mosquitto_unsubscribe_v5(mosq, mid, sub, NULL);
}

int mosquitto_unsubscribe_v5(struct mosquitto *mosq, int *mid, const char *sub, const mosquitto_property *properties)
{
	const mosquitto_property *outgoing_properties = NULL;
	mosquitto_property local_property;
	int rc;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->protocol != mosq_p_mqtt5 && properties) return MOSQ_ERR_NOT_SUPPORTED;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	if(mosquitto_sub_topic_check(sub)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(sub, strlen(sub))) return MOSQ_ERR_MALFORMED_UTF8;

	if(properties){
		if(properties->client_generated){
			outgoing_properties = properties;
		}else{
			memcpy(&local_property, properties, sizeof(mosquitto_property));
			local_property.client_generated = true;
			local_property.next = NULL;
			outgoing_properties = &local_property;
		}
		rc = mosquitto_property_check_all(CMD_UNSUBSCRIBE, outgoing_properties);
		if(rc) return rc;
	}

	return send__unsubscribe(mosq, mid, sub, outgoing_properties);
}

