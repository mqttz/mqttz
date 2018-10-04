/*
Copyright (c) 2018 Roger Light <roger@atchoo.org>

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
#include <errno.h>
#include <string.h>

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "packet_mosq.h"
#include "property_mosq.h"

int property__read(struct mosquitto__packet *packet, int32_t *len, struct mqtt5__property *property)
{
	int rc;
	int32_t property_identifier;
	uint8_t byte;
	int8_t byte_count;
	uint16_t uint16;
	uint32_t uint32;
	int32_t varint;
	char *str1, *str2;
	int slen1, slen2;

	rc = packet__read_varint(packet, &property_identifier, NULL);
	if(rc) return rc;
	*len -= 1;

	memset(property, 0, sizeof(struct mqtt5__property));

	property->identifier = property_identifier;

	switch(property_identifier){
		case PROP_PAYLOAD_FORMAT_INDICATOR:
		case PROP_REQUEST_PROBLEM_INFO:
		case PROP_REQUEST_RESPONSE_INFO:
		case PROP_MAXIMUM_QOS:
		case PROP_RETAIN_AVAILABLE:
		case PROP_WILDCARD_SUB_AVAILABLE:
		case PROP_SUBSCRIPTION_ID_AVAILABLE:
		case PROP_SHARED_SUB_AVAILABLE:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			property->value.i8 = byte;
			break;

		case PROP_SERVER_KEEP_ALIVE:
		case PROP_RECEIVE_MAXIMUM:
		case PROP_TOPIC_ALIAS_MAXIMUM:
		case PROP_TOPIC_ALIAS:
			rc = packet__read_uint16(packet, &uint16);
			if(rc) return rc;
			*len -= 2; /* uint16 */
			property->value.i16 = uint16;
			break;

		case PROP_MESSAGE_EXPIRY_INTERVAL:
		case PROP_SESSION_EXPIRY_INTERVAL:
		case PROP_WILL_DELAY_INTERVAL:
		case PROP_MAXIMUM_PACKET_SIZE:
			rc = packet__read_uint32(packet, &uint32);
			if(rc) return rc;
			*len -= 4; /* uint32 */
			property->value.i32 = uint32;
			break;

		case PROP_SUBSCRIPTION_IDENTIFIER:
			rc = packet__read_varint(packet, &varint, &byte_count);
			if(rc) return rc;
			*len -= byte_count;
			property->value.varint = varint;
			break;

		case PROP_CONTENT_TYPE:
		case PROP_RESPONSE_TOPIC:
		case PROP_ASSIGNED_CLIENT_IDENTIFIER:
		case PROP_AUTHENTICATION_METHOD:
		case PROP_AUTHENTICATION_DATA:
		case PROP_RESPONSE_INFO:
		case PROP_SERVER_REFERENCE:
		case PROP_REASON_STRING:
			rc = packet__read_string(packet, &str1, &slen1);
			if(rc) return rc;
			*len -= 2 - slen1; /* uint16, string len */
			property->value.s.v = str1;
			property->value.s.len = slen1;
			break;

		case PROP_CORRELATION_DATA:
			rc = packet__read_binary(packet, (uint8_t **)&str1, &slen1);
			if(rc) return rc;
			*len -= 2 - slen1; /* uint16, binary len */
			property->value.bin.v = str1;
			property->value.bin.len = slen1;
			break;

		case PROP_USER_PROPERTY:
			rc = packet__read_string(packet, &str1, &slen1);
			if(rc) return rc;
			*len -= 2 - slen1; /* uint16, string len */

			rc = packet__read_string(packet, &str2, &slen2);
			if(rc){
				mosquitto__free(str1);
				return rc;
			}
			*len -= 2 - slen2; /* uint16, string len */

			property->name.v = str1;
			property->name.len = slen1;
			property->value.s.v = str2;
			property->value.s.len = slen2;
			break;

		default:
			log__printf(NULL, MOSQ_LOG_DEBUG, "Unsupported property type: %d", byte);
			return MOSQ_ERR_MALFORMED_PACKET;
	}

	return MOSQ_ERR_SUCCESS;
}


int property__read_all(struct mosquitto__packet *packet, struct mqtt5__property **properties)
{
	int rc;
	int32_t proplen;
	struct mqtt5__property *p, *last = NULL;

	bool have_payload_format_indicator = false;
	bool have_request_problem_info = false;
	bool have_request_response_info = false;
	bool have_maximum_qos = false;
	bool have_retain_available = false;
	bool have_wildcard_sub_available = false;
	bool have_subscription_id_available = false;
	bool have_shared_sub_available = false;
	bool have_message_expiry_interval = false;
	bool have_session_expiry_interval = false;
	bool have_will_delay_interval = false;
	bool have_maximum_packet_size = false;
	bool have_server_keep_alive = false;
	bool have_receive_maximum = false;
	bool have_topic_alias_maximum = false;
	bool have_topic_alias = false;

	rc = packet__read_varint(packet, &proplen, NULL);
	if(rc) return rc;

	*properties = NULL;

	/* The order of properties must be preserved for some types, so keep the
	 * same order for all */
	while(proplen > 0){
		p = mosquitto__calloc(1, sizeof(struct mqtt5__property));

		rc = property__read(packet, &proplen, p); 
		if(rc){
			mosquitto__free(p);
			property__free_all(properties);
			return rc;
		}

		if(!(*properties)){
			*properties = p;
		}else{
			last->next = p;
		}
		last = p;

		/* Validity checks */
		if(p->identifier == PROP_PAYLOAD_FORMAT_INDICATOR){
			if(have_payload_format_indicator){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_payload_format_indicator = true;
		}else if(p->identifier == PROP_REQUEST_PROBLEM_INFO){
			if(have_request_problem_info || p->value.i8 > 1){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_request_problem_info = true;
		}else if(p->identifier == PROP_REQUEST_RESPONSE_INFO){
			if(have_request_response_info || p->value.i8 > 1){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_request_response_info = true;
		}else if(p->identifier == PROP_MAXIMUM_QOS){
			if(have_maximum_qos || p->value.i8 > 1){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_maximum_qos = true;
		}else if(p->identifier == PROP_RETAIN_AVAILABLE){
			if(have_retain_available || p->value.i8 > 1){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_retain_available = true;
		}else if(p->identifier == PROP_WILDCARD_SUB_AVAILABLE){
			if(have_wildcard_sub_available || p->value.i8 > 1){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_wildcard_sub_available = true;
		}else if(p->identifier == PROP_SUBSCRIPTION_ID_AVAILABLE){
			if(have_subscription_id_available || p->value.i8 > 1){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_subscription_id_available = true;
		}else if(p->identifier == PROP_SHARED_SUB_AVAILABLE){
			if(have_shared_sub_available || p->value.i8 > 1){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_shared_sub_available = true;
		}else if(p->identifier == PROP_MESSAGE_EXPIRY_INTERVAL){
			if(have_message_expiry_interval){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_message_expiry_interval = true;
		}else if(p->identifier == PROP_SESSION_EXPIRY_INTERVAL){
			if(have_session_expiry_interval){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_session_expiry_interval = true;
		}else if(p->identifier == PROP_WILL_DELAY_INTERVAL){
			if(have_will_delay_interval){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_will_delay_interval = true;
		}else if(p->identifier == PROP_MAXIMUM_PACKET_SIZE){
			if(have_maximum_packet_size || p->value.i32 == 0){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_maximum_packet_size = true;
		}else if(p->identifier == PROP_SERVER_KEEP_ALIVE){
			if(have_server_keep_alive){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_server_keep_alive = true;
		}else if(p->identifier == PROP_RECEIVE_MAXIMUM){
			if(have_receive_maximum || p->value.i16 == 0){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_receive_maximum = true;
		}else if(p->identifier == PROP_TOPIC_ALIAS_MAXIMUM){
			if(have_topic_alias_maximum){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_topic_alias_maximum = true;
		}else if(p->identifier == PROP_TOPIC_ALIAS){
			if(have_topic_alias || p->value.i16 == 0){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			have_topic_alias = true;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


void property__free(struct mqtt5__property **property)
{
	if(!property || !(*property)) return;

	switch((*property)->identifier){
		case PROP_CONTENT_TYPE:
		case PROP_RESPONSE_TOPIC:
		case PROP_CORRELATION_DATA:
		case PROP_ASSIGNED_CLIENT_IDENTIFIER:
		case PROP_AUTHENTICATION_METHOD:
		case PROP_AUTHENTICATION_DATA:
		case PROP_RESPONSE_INFO:
		case PROP_SERVER_REFERENCE:
		case PROP_REASON_STRING:
			mosquitto__free((*property)->value.s.v);
			break;

		case PROP_USER_PROPERTY:
			mosquitto__free((*property)->name.v);
			mosquitto__free((*property)->value.s.v);
			break;

		case PROP_PAYLOAD_FORMAT_INDICATOR:
		case PROP_MESSAGE_EXPIRY_INTERVAL:
		case PROP_SUBSCRIPTION_IDENTIFIER:
		case PROP_SESSION_EXPIRY_INTERVAL:
		case PROP_SERVER_KEEP_ALIVE:
		case PROP_REQUEST_PROBLEM_INFO:
		case PROP_WILL_DELAY_INTERVAL:
		case PROP_REQUEST_RESPONSE_INFO:
		case PROP_RECEIVE_MAXIMUM:
		case PROP_TOPIC_ALIAS_MAXIMUM:
		case PROP_TOPIC_ALIAS:
		case PROP_MAXIMUM_QOS:
		case PROP_RETAIN_AVAILABLE:
		case PROP_MAXIMUM_PACKET_SIZE:
		case PROP_WILDCARD_SUB_AVAILABLE:
		case PROP_SUBSCRIPTION_ID_AVAILABLE:
		case PROP_SHARED_SUB_AVAILABLE:
			/* Nothing to free */
			break;
	}

	free(*property);
	*property = NULL;
}


void property__free_all(struct mqtt5__property **property)
{
	struct mqtt5__property *p, *next;

	p = *property;
	while(p){
		next = p->next;
		property__free(&p);
		p = next;
	}
	*property = NULL;
}
