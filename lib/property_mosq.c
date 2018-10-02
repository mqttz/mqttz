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

int property__read(struct mosquitto__packet *packet, uint32_t *len)
{
	int rc;
	uint8_t byte;
	uint16_t int16;
	uint32_t int32;
	char *str;
	int slen;
	*len -= 14;

	rc = packet__read_byte(packet, &byte);
	if(rc) return rc;
	*len -= 1;

	switch(byte){
		case PROP_PAYLOAD_FORMAT_INDICATOR:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Payload format indicator: %d", byte);
			break;

		case PROP_MESSAGE_EXPIRY_INTERVAL:
			rc = packet__read_uint32(packet, &int32);
			if(rc) return rc;
			*len -= 4; /* uint32 */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Message expiry: %d", int32);
			break;

		case PROP_CONTENT_TYPE:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Content type: %s", str);
			break;

		case PROP_RESPONSE_TOPIC:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Response topic: %s", str);
			break;

		case PROP_CORRELATION_DATA:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Correlation data: %s", str);
			break;

		case PROP_SUBSCRIPTION_IDENTIFIER:
			rc = packet__read_varint(packet, &int32, &byte);
			*len -= byte;
			if(rc) return rc;
			log__printf(NULL, MOSQ_LOG_DEBUG, "Subscription identifier: %d", int32);
			break;

		case PROP_SESSION_EXPIRY_INTERVAL:
			rc = packet__read_uint32(packet, &int32);
			if(rc) return rc;
			*len -= 4; /* uint32 */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Session expiry: %d", int32);
			break;

		case PROP_ASSIGNED_CLIENT_IDENTIFIER:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Assigned client identifier: %s", str);
			break;

		case PROP_SERVER_KEEP_ALIVE:
			rc = packet__read_uint16(packet, &int16);
			if(rc) return rc;
			*len -= 2; /* uint16 */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Session expiry: %d", int16);
			break;

		case PROP_AUTHENTICATION_METHOD:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Authentication method: %s", str);
			break;

		case PROP_AUTHENTICATION_DATA:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Authentication data: %s", str);
			break;

		case PROP_REQUEST_PROBLEM_INFO:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Request problem information: %d", byte);
			break;

		case PROP_WILL_DELAY_INTERVAL:
			rc = packet__read_uint32(packet, &int32);
			if(rc) return rc;
			*len -= 4; /* uint32 */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Will delay interval: %d", int32);
			break;

		case PROP_REQUEST_RESPONSE_INFO:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Request response information: %d", byte);
			break;

		case PROP_RESPONSE_INFO:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Response information: %s", str);
			break;

		case PROP_SERVER_REFERENCE:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Server reference: %s", str);
			break;

		case PROP_REASON_STRING:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Reason string: %s", str);
			break;

		case PROP_RECEIVE_MAXIMUM:
			rc = packet__read_uint16(packet, &int16);
			if(rc) return rc;
			*len -= 2; /* uint16 */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Receive maximum: %d", int16);
			break;

		case PROP_TOPIC_ALIAS_MAXIMUM:
			rc = packet__read_uint16(packet, &int16);
			if(rc) return rc;
			*len -= 2; /* uint16 */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Topic alias maximum: %d", int16);
			break;

		case PROP_TOPIC_ALIAS:
			rc = packet__read_uint16(packet, &int16);
			if(rc) return rc;
			*len -= 2; /* uint16 */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Topic alias: %d", int16);
			break;

		case PROP_MAXIMUM_QOS:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Maximum QoS: %d", byte);
			break;

		case PROP_RETAIN_AVAILABLE:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Retain available: %d", byte);
			break;

		case PROP_USER_PROPERTY:
			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "User property name: %s", str);

			rc = packet__read_string(packet, &str, &slen);
			if(rc) return rc;
			*len -= 2 - slen; /* int16, string len */
			log__printf(NULL, MOSQ_LOG_DEBUG, "User property value: %s", str);
			break;

		case PROP_MAXIMUM_PACKET_SIZE:
			rc = packet__read_uint32(packet, &int32);
			if(rc) return rc;
			*len -= 4; /* uint32 */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Maximum packet size: %d", int32);
			break;

		case PROP_WILDCARD_SUB_AVAILABLE:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Wildcard subscription available: %d", byte);
			break;

		case PROP_SUBSCRIPTION_ID_AVAILABLE:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Subscription identifier available: %d", byte);
			break;

		case PROP_SHARED_SUB_AVAILABLE:
			rc = packet__read_byte(packet, &byte);
			if(rc) return rc;
			*len -= 1; /* byte */
			log__printf(NULL, MOSQ_LOG_DEBUG, "Shared subscription available: %d", byte);
			break;

		default:
			log__printf(NULL, MOSQ_LOG_DEBUG, "Unsupported property type: %d", byte);
			return 1;
	}

	return MOSQ_ERR_SUCCESS;
}


int property__read_all(struct mosquitto__packet *packet)
{
	int rc;
	int32_t proplen;

	rc = packet__read_varint(packet, &proplen, NULL);
	if(rc) return rc;

	while(proplen > 0){
		rc = property__read(packet, &proplen);
		if(rc) return rc;
	}

	return MOSQ_ERR_SUCCESS;
}
