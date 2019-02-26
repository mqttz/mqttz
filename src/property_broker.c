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
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
#include "property_mosq.h"

/* Process the incoming properties, we should be able to assume that only valid
 * properties for CONNECT are present here. */
int property__process_connect(struct mosquitto *context, mosquitto_property *props)
{
	mosquitto_property *p;

	p = props;

	while(p){
		if(p->identifier == MQTT_PROP_SESSION_EXPIRY_INTERVAL){
			context->session_expiry_interval = p->value.i32;
		}else if(p->identifier == MQTT_PROP_RECEIVE_MAXIMUM){
			if(p->value.i16 == 0){
				return MOSQ_ERR_PROTOCOL;
			}

			context->send_maximum = p->value.i16;
			context->send_quota = context->send_maximum;
		}else if(p->identifier == MQTT_PROP_MAXIMUM_PACKET_SIZE){
			if(p->value.i32 == 0){
				return MOSQ_ERR_PROTOCOL;
			}
			context->maximum_packet_size = p->value.i32;
		}
		p = p->next;
	}

	return MOSQ_ERR_SUCCESS;
}

/* Process the incoming properties, we should be able to assume that only valid
 * properties for DISCONNECT are present here. */
int property__process_disconnect(struct mosquitto *context, mosquitto_property *props)
{
	mosquitto_property *p;

	p = props;

	while(p){
		if(p->identifier == MQTT_PROP_SESSION_EXPIRY_INTERVAL){
			if(context->session_expiry_interval == 0 && p->value.i32 != 0){
				return MOSQ_ERR_PROTOCOL;
			}
			context->session_expiry_interval = p->value.i32;
		}
		p = p->next;
	}
	return MOSQ_ERR_SUCCESS;
}

