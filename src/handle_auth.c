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

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"


int handle__auth(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc = 0;
	uint8_t reason_code = 0;
	mosquitto_property *properties = NULL;

	if(!context) return MOSQ_ERR_INVAL;
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received AUTH from %s", context->id);

	if(context->protocol != mosq_p_mqtt5){
		return MOSQ_ERR_PROTOCOL;
	}

	if(context->in_packet.remaining_length > 0){
		if(packet__read_byte(&context->in_packet, &reason_code)) return 1;

		rc = property__read_all(CMD_AUTH, &context->in_packet, &properties);
		if(rc) return rc;
		mosquitto_property_free_all(&properties); /* FIXME - TEMPORARY UNTIL PROPERTIES PROCESSED */
	}

	/* FIXME - Extended auth not currently supported */
	send__disconnect(context, MQTT_RC_NOT_AUTHORIZED, NULL);
	return 1;
}
