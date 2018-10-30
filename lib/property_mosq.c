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

static int property__command_check(int command, struct mqtt5__property *properties);


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
		case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
		case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
		case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
		case MQTT_PROP_MAXIMUM_QOS:
		case MQTT_PROP_RETAIN_AVAILABLE:
		case MQTT_PROP_WILDCARD_SUB_AVAILABLE:
		case MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE:
		case MQTT_PROP_SHARED_SUB_AVAILABLE:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			property->value.i8 = byte;
			break;

		case MQTT_PROP_SERVER_KEEP_ALIVE:
		case MQTT_PROP_RECEIVE_MAXIMUM:
		case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
		case MQTT_PROP_TOPIC_ALIAS:
			rc = packet__read_uint16(packet, &uint16);
			if(rc) return rc;
			*len -= 2; /* uint16 */
			property->value.i16 = uint16;
			break;

		case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
		case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
		case MQTT_PROP_WILL_DELAY_INTERVAL:
		case MQTT_PROP_MAXIMUM_PACKET_SIZE:
			rc = packet__read_uint32(packet, &uint32);
			if(rc) return rc;
			*len -= 4; /* uint32 */
			property->value.i32 = uint32;
			break;

		case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
			rc = packet__read_varint(packet, &varint, &byte_count);
			if(rc) return rc;
			*len -= byte_count;
			property->value.varint = varint;
			break;

		case MQTT_PROP_CONTENT_TYPE:
		case MQTT_PROP_RESPONSE_TOPIC:
		case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
		case MQTT_PROP_AUTHENTICATION_METHOD:
		case MQTT_PROP_RESPONSE_INFORMATION:
		case MQTT_PROP_SERVER_REFERENCE:
		case MQTT_PROP_REASON_STRING:
			rc = packet__read_string(packet, &str1, &slen1);
			if(rc) return rc;
			*len = (*len) - 2 - slen1; /* uint16, string len */
			property->value.s.v = str1;
			property->value.s.len = slen1;
			break;

		case MQTT_PROP_AUTHENTICATION_DATA:
		case MQTT_PROP_CORRELATION_DATA:
			rc = packet__read_binary(packet, (uint8_t **)&str1, &slen1);
			if(rc) return rc;
			*len = (*len) - 2 - slen1; /* uint16, binary len */
			property->value.bin.v = str1;
			property->value.bin.len = slen1;
			break;

		case MQTT_PROP_USER_PROPERTY:
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


int property__read_all(int command, struct mosquitto__packet *packet, struct mqtt5__property **properties)
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
			mosquitto_property_free_all(properties);
			return rc;
		}

		if(!(*properties)){
			*properties = p;
		}else{
			tail->next = p;
		}
		tail = p;

		/* Validity checks */
		if(p->identifier == MQTT_PROP_REQUEST_PROBLEM_INFORMATION
				|| p->identifier == MQTT_PROP_REQUEST_RESPONSE_INFORMATION
				|| p->identifier == MQTT_PROP_MAXIMUM_QOS
				|| p->identifier == MQTT_PROP_RETAIN_AVAILABLE
				|| p->identifier == MQTT_PROP_WILDCARD_SUB_AVAILABLE
				|| p->identifier == MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE
				|| p->identifier == MQTT_PROP_SHARED_SUB_AVAILABLE){

			if(p->value.i8 > 1){
				mosquitto_property_free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
		}else if(p->identifier == MQTT_PROP_MAXIMUM_PACKET_SIZE){
			if( p->value.i32 == 0){
				mosquitto_property_free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
		}else if(p->identifier == MQTT_PROP_RECEIVE_MAXIMUM
				|| p->identifier == MQTT_PROP_TOPIC_ALIAS){

			if(p->value.i16 == 0){
				mosquitto_property_free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
		}
	}

	/* Check for duplicates */
	current = *properties;
	while(current){
		tail = current->next;
		while(tail){
			if(current->identifier == tail->identifier
					&& current->identifier != MQTT_PROP_USER_PROPERTY){

				mosquitto_property_free_all(properties);
				return MOSQ_ERR_PROTOCOL;
			}
			tail = tail->next;
		}
		current = current->next;
	}

	/* Check for properties on incorrect commands */
	if(property__command_check(command, *properties)){
		mosquitto_property_free_all(properties);
		return MOSQ_ERR_PROTOCOL;
	}
	return MOSQ_ERR_SUCCESS;
}


void property__free(struct mqtt5__property **property)
{
	if(!property || !(*property)) return;

	switch((*property)->identifier){
		case MQTT_PROP_CONTENT_TYPE:
		case MQTT_PROP_RESPONSE_TOPIC:
		case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
		case MQTT_PROP_AUTHENTICATION_METHOD:
		case MQTT_PROP_RESPONSE_INFORMATION:
		case MQTT_PROP_SERVER_REFERENCE:
		case MQTT_PROP_REASON_STRING:
			mosquitto__free((*property)->value.s.v);
			break;

		case MQTT_PROP_AUTHENTICATION_DATA:
		case MQTT_PROP_CORRELATION_DATA:
			mosquitto__free((*property)->value.bin.v);
			break;

		case MQTT_PROP_USER_PROPERTY:
			mosquitto__free((*property)->name.v);
			mosquitto__free((*property)->value.s.v);
			break;

		case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
		case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
		case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
		case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
		case MQTT_PROP_SERVER_KEEP_ALIVE:
		case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
		case MQTT_PROP_WILL_DELAY_INTERVAL:
		case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
		case MQTT_PROP_RECEIVE_MAXIMUM:
		case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
		case MQTT_PROP_TOPIC_ALIAS:
		case MQTT_PROP_MAXIMUM_QOS:
		case MQTT_PROP_RETAIN_AVAILABLE:
		case MQTT_PROP_MAXIMUM_PACKET_SIZE:
		case MQTT_PROP_WILDCARD_SUB_AVAILABLE:
		case MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE:
		case MQTT_PROP_SHARED_SUB_AVAILABLE:
			/* Nothing to free */
			break;
	}

	free(*property);
	*property = NULL;
}


void mosquitto_property_free_all(struct mqtt5__property **property)
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
		case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
		case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
		case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
		case MQTT_PROP_MAXIMUM_QOS:
		case MQTT_PROP_RETAIN_AVAILABLE:
		case MQTT_PROP_WILDCARD_SUB_AVAILABLE:
		case MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE:
		case MQTT_PROP_SHARED_SUB_AVAILABLE:
			return 2; /* 1 (identifier) + 1 byte */

		case MQTT_PROP_SERVER_KEEP_ALIVE:
		case MQTT_PROP_RECEIVE_MAXIMUM:
		case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
		case MQTT_PROP_TOPIC_ALIAS:
			return 3; /* 1 (identifier) + 2 bytes */

		case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
		case MQTT_PROP_WILL_DELAY_INTERVAL:
		case MQTT_PROP_MAXIMUM_PACKET_SIZE:
		case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
			return 5; /* 1 (identifier) + 5 bytes */

		case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
			if(property->value.varint < 128){
				return 2;
			}else if(property->value.varint < 16384){
				return 3;
			}else if(property->value.varint < 2097152){
				return 4;
			}else if(property->value.varint < 268435456){
				return 5;
			}else{
				return 0;
			}

		case MQTT_PROP_CORRELATION_DATA:
		case MQTT_PROP_AUTHENTICATION_DATA:
			return 3 + property->value.bin.len; /* 1 + 2 bytes (len) + X bytes (payload) */

		case MQTT_PROP_CONTENT_TYPE:
		case MQTT_PROP_RESPONSE_TOPIC:
		case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
		case MQTT_PROP_AUTHENTICATION_METHOD:
		case MQTT_PROP_RESPONSE_INFORMATION:
		case MQTT_PROP_SERVER_REFERENCE:
		case MQTT_PROP_REASON_STRING:
			return 3 + property->value.s.len; /* 1 + 2 bytes (len) + X bytes (string) */

		case MQTT_PROP_USER_PROPERTY:
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


int property__write(struct mosquitto__packet *packet, struct mqtt5__property *property)
{
	int rc;

	rc = packet__write_varint(packet, property->identifier);
	if(rc) return rc;

	switch(property->identifier){
		case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
		case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
		case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
		case MQTT_PROP_MAXIMUM_QOS:
		case MQTT_PROP_RETAIN_AVAILABLE:
		case MQTT_PROP_WILDCARD_SUB_AVAILABLE:
		case MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE:
		case MQTT_PROP_SHARED_SUB_AVAILABLE:
			packet__write_byte(packet, property->value.i8);
			break;

		case MQTT_PROP_SERVER_KEEP_ALIVE:
		case MQTT_PROP_RECEIVE_MAXIMUM:
		case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
		case MQTT_PROP_TOPIC_ALIAS:
			packet__write_uint16(packet, property->value.i16);
			break;

		case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
		case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
		case MQTT_PROP_WILL_DELAY_INTERVAL:
		case MQTT_PROP_MAXIMUM_PACKET_SIZE:
			packet__write_uint32(packet, property->value.i32);
			break;

		case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
			return packet__write_varint(packet, property->value.varint);

		case MQTT_PROP_CONTENT_TYPE:
		case MQTT_PROP_RESPONSE_TOPIC:
		case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
		case MQTT_PROP_AUTHENTICATION_METHOD:
		case MQTT_PROP_RESPONSE_INFORMATION:
		case MQTT_PROP_SERVER_REFERENCE:
		case MQTT_PROP_REASON_STRING:
			packet__write_string(packet, property->value.s.v, property->value.s.len);
			break;

		case MQTT_PROP_AUTHENTICATION_DATA:
		case MQTT_PROP_CORRELATION_DATA:
			packet__write_uint16(packet, property->value.bin.len);
			packet__write_bytes(packet, property->value.bin.v, property->value.bin.len);

		case MQTT_PROP_USER_PROPERTY:
			packet__write_string(packet, property->name.v, property->name.len);
			packet__write_string(packet, property->value.s.v, property->value.s.len);
			break;

		default:
			log__printf(NULL, MOSQ_LOG_DEBUG, "Unsupported property type: %d", property->identifier);
			return MOSQ_ERR_INVAL;
	}

	return MOSQ_ERR_SUCCESS;
}


int property__write_all(struct mosquitto__packet *packet, struct mqtt5__property *properties)
{
	int rc;
	struct mqtt5__property *p;

	rc = packet__write_varint(packet, property__get_length_all(properties));
	if(rc) return rc;

	p = properties;
	while(p){
		rc = property__write(packet, p);
		if(rc) return rc;
		p = p->next;
	}

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_property_command_check(int command, int identifier)
{
	switch(identifier){
		case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
		case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
		case MQTT_PROP_CONTENT_TYPE:
		case MQTT_PROP_RESPONSE_TOPIC:
		case MQTT_PROP_CORRELATION_DATA:
			if(command != CMD_PUBLISH && command != CMD_WILL){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
			if(command != CMD_PUBLISH && command != CMD_SUBSCRIBE){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
			if(command != CMD_CONNECT && command != CMD_CONNACK && command != CMD_DISCONNECT){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_AUTHENTICATION_METHOD:
		case MQTT_PROP_AUTHENTICATION_DATA:
			if(command != CMD_CONNECT && command != CMD_CONNACK && command != CMD_AUTH){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
		case MQTT_PROP_SERVER_KEEP_ALIVE:
		case MQTT_PROP_RESPONSE_INFORMATION:
		case MQTT_PROP_MAXIMUM_QOS:
		case MQTT_PROP_RETAIN_AVAILABLE:
		case MQTT_PROP_WILDCARD_SUB_AVAILABLE:
		case MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE:
		case MQTT_PROP_SHARED_SUB_AVAILABLE:
			if(command != CMD_CONNACK){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_WILL_DELAY_INTERVAL:
			if(command != CMD_WILL){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
		case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
			if(command != CMD_CONNECT){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_SERVER_REFERENCE:
			if(command != CMD_CONNACK && command != CMD_DISCONNECT){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_REASON_STRING:
			if(command == CMD_CONNECT || command == CMD_PUBLISH || command == CMD_SUBSCRIBE || command == CMD_UNSUBSCRIBE){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_RECEIVE_MAXIMUM:
		case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
		case MQTT_PROP_MAXIMUM_PACKET_SIZE:
			if(command != CMD_CONNECT && command != CMD_CONNACK){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_TOPIC_ALIAS:
			if(command != CMD_PUBLISH){
				return MOSQ_ERR_PROTOCOL;
			}
			break;

		case MQTT_PROP_USER_PROPERTY:
			break;

		default:
			return MOSQ_ERR_PROTOCOL;
	}
	return MOSQ_ERR_SUCCESS;
}

static int property__command_check(int command, struct mqtt5__property *properties)
{
	struct mqtt5__property *p;
	int rc;

	p = properties;
	while(p){
		rc = mosquitto_property_command_check(command, p->identifier);
		if(rc) return rc;

		p = p->next;
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_string_to_property_info(const char *propname, int *identifier, int *type)
{
	if(!strcasecmp(propname, "payload-format-indicator")){
		*identifier = MQTT_PROP_PAYLOAD_FORMAT_INDICATOR;
		*type = MQTT_PROP_TYPE_BYTE;
	}else if(!strcasecmp(propname, "message-expiry-interval")){
		*identifier = MQTT_PROP_MESSAGE_EXPIRY_INTERVAL;
		*type = MQTT_PROP_TYPE_INT32;
	}else if(!strcasecmp(propname, "content-type")){
		*identifier = MQTT_PROP_CONTENT_TYPE;
		*type = MQTT_PROP_TYPE_STRING;
	}else if(!strcasecmp(propname, "response-topic")){
		*identifier = MQTT_PROP_RESPONSE_TOPIC;
		*type = MQTT_PROP_TYPE_STRING;
	}else if(!strcasecmp(propname, "correlation-data")){
		*identifier = MQTT_PROP_CORRELATION_DATA;
		*type = MQTT_PROP_TYPE_BINARY;
	}else if(!strcasecmp(propname, "subscription-identifier")){
		*identifier = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
		*type = MQTT_PROP_TYPE_VARINT;
	}else if(!strcasecmp(propname, "session-expiry-interval")){
		*identifier = MQTT_PROP_SESSION_EXPIRY_INTERVAL;
		*type = MQTT_PROP_TYPE_INT32;
	}else if(!strcasecmp(propname, "assigned-client-identifier")){
		*identifier = MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER;
		*type = MQTT_PROP_TYPE_STRING;
	}else if(!strcasecmp(propname, "server-keep-alive")){
		*identifier = MQTT_PROP_SERVER_KEEP_ALIVE;
		*type = MQTT_PROP_TYPE_INT16;
	}else if(!strcasecmp(propname, "authentication-method")){
		*identifier = MQTT_PROP_AUTHENTICATION_METHOD;
		*type = MQTT_PROP_TYPE_STRING;
	}else if(!strcasecmp(propname, "authentication-data")){
		*identifier = MQTT_PROP_AUTHENTICATION_DATA;
		*type = MQTT_PROP_TYPE_BINARY;
	}else if(!strcasecmp(propname, "request-problem-information")){
		*identifier = MQTT_PROP_REQUEST_PROBLEM_INFORMATION;
		*type = MQTT_PROP_TYPE_BYTE;
	}else if(!strcasecmp(propname, "will-delay-interval")){
		*identifier = MQTT_PROP_WILL_DELAY_INTERVAL;
		*type = MQTT_PROP_TYPE_INT32;
	}else if(!strcasecmp(propname, "request-response-information")){
		*identifier = MQTT_PROP_REQUEST_RESPONSE_INFORMATION;
		*type = MQTT_PROP_TYPE_BYTE;
	}else if(!strcasecmp(propname, "response-information")){
		*identifier = MQTT_PROP_RESPONSE_INFORMATION;
		*type = MQTT_PROP_TYPE_STRING;
	}else if(!strcasecmp(propname, "server-reference")){
		*identifier = MQTT_PROP_SERVER_REFERENCE;
		*type = MQTT_PROP_TYPE_STRING;
	}else if(!strcasecmp(propname, "reason-string")){
		*identifier = MQTT_PROP_REASON_STRING;
		*type = MQTT_PROP_TYPE_STRING;
	}else if(!strcasecmp(propname, "receive-maximum")){
		*identifier = MQTT_PROP_RECEIVE_MAXIMUM;
		*type = MQTT_PROP_TYPE_INT16;
	}else if(!strcasecmp(propname, "topic-alias-maximum")){
		*identifier = MQTT_PROP_TOPIC_ALIAS_MAXIMUM;
		*type = MQTT_PROP_TYPE_INT16;
	}else if(!strcasecmp(propname, "topic-alias")){
		*identifier = MQTT_PROP_TOPIC_ALIAS;
		*type = MQTT_PROP_TYPE_INT16;
	}else if(!strcasecmp(propname, "maximum-qos")){
		*identifier = MQTT_PROP_MAXIMUM_QOS;
		*type = MQTT_PROP_TYPE_BYTE;
	}else if(!strcasecmp(propname, "retain-available")){
		*identifier = MQTT_PROP_RETAIN_AVAILABLE;
		*type = MQTT_PROP_TYPE_BYTE;
	}else if(!strcasecmp(propname, "user-property")){
		*identifier = MQTT_PROP_USER_PROPERTY;
		*type = MQTT_PROP_TYPE_STRING_PAIR;
	}else if(!strcasecmp(propname, "maximum-packet-size")){
		*identifier = MQTT_PROP_MAXIMUM_PACKET_SIZE;
		*type = MQTT_PROP_TYPE_INT32;
	}else if(!strcasecmp(propname, "wildcard-subscription-available")){
		*identifier = MQTT_PROP_WILDCARD_SUB_AVAILABLE;
		*type = MQTT_PROP_TYPE_BYTE;
	}else if(!strcasecmp(propname, "subscription-identifier-available")){
		*identifier = MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE;
		*type = MQTT_PROP_TYPE_BYTE;
	}else if(!strcasecmp(propname, "shared-subscription-available")){
		*identifier = MQTT_PROP_SHARED_SUB_AVAILABLE;
		*type = MQTT_PROP_TYPE_BYTE;
	}else{
		return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}
