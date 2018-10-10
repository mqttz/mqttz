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
		case PROP_RESPONSE_INFO:
		case PROP_SERVER_REFERENCE:
		case PROP_REASON_STRING:
			rc = packet__read_string(packet, &str1, &slen1);
			if(rc) return rc;
			*len = (*len) - 2 - slen1; /* uint16, string len */
			property->value.s.v = str1;
			property->value.s.len = slen1;
			break;

		case PROP_AUTHENTICATION_DATA:
		case PROP_CORRELATION_DATA:
			rc = packet__read_binary(packet, (uint8_t **)&str1, &slen1);
			if(rc) return rc;
			*len = (*len) - 2 - slen1; /* uint16, binary len */
			property->value.bin.v = str1;
			property->value.bin.len = slen1;
			break;

		case PROP_USER_PROPERTY:
			rc = packet__read_string(packet, &str1, &slen1);
			if(rc) return rc;
			*len = (*len) - 2 - slen1; /* uint16, string len */

			rc = packet__read_string(packet, &str2, &slen2);
			if(rc){
				mosquitto__free(str1);
				return rc;
			}
			*len = (*len) - 2 - slen2; /* uint16, string len */

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
	struct mqtt5__property *p, *tail = NULL;
	struct mqtt5__property *current;

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
			tail->next = p;
		}
		tail = p;

		/* Validity checks */
		if(p->identifier == PROP_REQUEST_PROBLEM_INFO
				|| p->identifier == PROP_REQUEST_RESPONSE_INFO
				|| p->identifier == PROP_MAXIMUM_QOS
				|| p->identifier == PROP_RETAIN_AVAILABLE
				|| p->identifier == PROP_WILDCARD_SUB_AVAILABLE
				|| p->identifier == PROP_SUBSCRIPTION_ID_AVAILABLE
				|| p->identifier == PROP_SHARED_SUB_AVAILABLE){

			if(p->value.i8 > 1){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
		}else if(p->identifier == PROP_MAXIMUM_PACKET_SIZE){
			if( p->value.i32 == 0){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
		}else if(p->identifier == PROP_RECEIVE_MAXIMUM
				|| p->identifier == PROP_TOPIC_ALIAS){

			if(p->value.i16 == 0){
				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
		}
	}

	current = *properties;
	while(current){
		tail = current->next;
		while(tail){
			if(current->identifier == tail->identifier
					&& current->identifier != PROP_USER_PROPERTY){

				property__free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			tail = tail->next;
		}
		current = current->next;
	}

	return MOSQ_ERR_SUCCESS;
}


void property__free(struct mqtt5__property **property)
{
	if(!property || !(*property)) return;

	switch((*property)->identifier){
		case PROP_CONTENT_TYPE:
		case PROP_RESPONSE_TOPIC:
		case PROP_ASSIGNED_CLIENT_IDENTIFIER:
		case PROP_AUTHENTICATION_METHOD:
		case PROP_RESPONSE_INFO:
		case PROP_SERVER_REFERENCE:
		case PROP_REASON_STRING:
			mosquitto__free((*property)->value.s.v);
			break;

		case PROP_AUTHENTICATION_DATA:
		case PROP_CORRELATION_DATA:
			mosquitto__free((*property)->value.bin.v);
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


int property__get_length(struct mqtt5__property *property)
{
	if(!property) return 0;

	switch(property->identifier){
		case PROP_PAYLOAD_FORMAT_INDICATOR:
		case PROP_REQUEST_PROBLEM_INFO:
		case PROP_REQUEST_RESPONSE_INFO:
		case PROP_MAXIMUM_QOS:
		case PROP_RETAIN_AVAILABLE:
		case PROP_WILDCARD_SUB_AVAILABLE:
		case PROP_SUBSCRIPTION_ID_AVAILABLE:
		case PROP_SHARED_SUB_AVAILABLE:
			return 2; /* 1 (identifier) + 1 byte */

		case PROP_SERVER_KEEP_ALIVE:
		case PROP_RECEIVE_MAXIMUM:
		case PROP_TOPIC_ALIAS_MAXIMUM:
		case PROP_TOPIC_ALIAS:
			return 3; /* 1 (identifier) + 2 bytes */

		case PROP_MESSAGE_EXPIRY_INTERVAL:
		case PROP_WILL_DELAY_INTERVAL:
		case PROP_MAXIMUM_PACKET_SIZE:
		case PROP_SESSION_EXPIRY_INTERVAL:
			return 5; /* 1 (identifier) + 5 bytes */

		case PROP_SUBSCRIPTION_IDENTIFIER:
			if(property->value.varint < 128){
				return 1;
			}else if(property->value.varint < 16384){
				return 2;
			}else if(property->value.varint < 2097152){
				return 3;
			}else if(property->value.varint < 268435456){
				return 4;
			}else{
				return 0;
			}

		case PROP_CORRELATION_DATA:
		case PROP_AUTHENTICATION_DATA:
			return 3 + property->value.bin.len; /* 1 + 2 bytes (len) + X bytes (payload) */

		case PROP_CONTENT_TYPE:
		case PROP_RESPONSE_TOPIC:
		case PROP_ASSIGNED_CLIENT_IDENTIFIER:
		case PROP_AUTHENTICATION_METHOD:
		case PROP_RESPONSE_INFO:
		case PROP_SERVER_REFERENCE:
		case PROP_REASON_STRING:
			return 3 + property->value.s.len; /* 1 + 2 bytes (len) + X bytes (string) */

		case PROP_USER_PROPERTY:
			return 5 + property->value.s.len + property->name.len; /* 1 + 2*(2 bytes (len) + X bytes (string))*/

		default:
			return 0;
	}
	return 0;
}


int property__get_length_all(struct mqtt5__property *property)
{
	struct mqtt5__property *p;
	int len = 0;

	p = property;
	while(p){
		len += property__get_length(p);
		p = p->next;
	}
	return len;
}


int property__write_all(struct mosquitto__packet *packet, struct mqtt5__property **property)
{
	packet__write_byte(packet, 0);
	return MOSQ_ERR_SUCCESS;
}

