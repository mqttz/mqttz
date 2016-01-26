/*
Copyright (c) 2016 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#include <stdbool.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"

struct subscribe__userdata {
	const char *topic;
	struct mosquitto_message *messages;
	int max_msg_count;
	int message_count;
	int qos;
	int rc;
	bool retained;
};


void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	struct subscribe__userdata *userdata = obj;

	mosquitto_subscribe(mosq, NULL, userdata->topic, userdata->qos);
}


void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	struct subscribe__userdata *userdata = obj;
	int rc;

	if(userdata->max_msg_count == 0){
		return;
	}

	/* Don't process stale retained messages if 'retained' was false */
	if(!userdata->retained && message->retain){
		return;
	}

	userdata->max_msg_count--;

	rc = mosquitto_message_copy(&userdata->messages[userdata->message_count], message);
	if(rc){
		userdata->rc = rc;
		mosquitto_disconnect(mosq);
		return;
	}
	userdata->message_count++;
	if(userdata->max_msg_count == 0){
		mosquitto_disconnect(mosq);
	}
}



libmosq_EXPORT int mosquitto_subscribe_simple(
		struct mosquitto_message **messages,
		int msg_count,
		const char *topic,
		int qos,
		bool retained,
		const char *host,
		int port,
		const char *client_id,
		int keepalive,
		bool clean_session,
		const char *username,
		const char *password,
		const struct libmosquitto_will *will,
		const struct libmosquitto_tls *tls)
{
	struct mosquitto *mosq;
	struct subscribe__userdata userdata;
	int rc;
	int i;

	if(!topic || msg_count < 1 || !messages){
		return MOSQ_ERR_INVAL;
	}

	*messages = NULL;

	userdata.topic = topic;
	userdata.qos = qos;
	userdata.max_msg_count = msg_count;
	userdata.retained = retained;
	userdata.messages = calloc(sizeof(struct mosquitto_message), msg_count);
	userdata.rc = 0;
	if(!userdata.messages){
		return MOSQ_ERR_NOMEM;
	}
	userdata.message_count = 0;

	mosq = mosquitto_new(client_id, clean_session, &userdata);
	if(!mosq){
		free(userdata.messages);
		userdata.messages = NULL;
		return MOSQ_ERR_NOMEM;
	}

	if(will){
		rc = mosquitto_will_set(mosq, will->topic, will->payloadlen, will->payload, will->qos, will->retain);
		if(rc){
			free(userdata.messages);
			userdata.messages = NULL;
			mosquitto_destroy(mosq);
			return rc;
		}
	}
	if(username){
		rc = mosquitto_username_pw_set(mosq, username, password);
		if(rc){
			free(userdata.messages);
			userdata.messages = NULL;
			mosquitto_destroy(mosq);
			return rc;
		}
	}
	if(tls){
		rc = mosquitto_tls_set(mosq, tls->cafile, tls->capath, tls->certfile, tls->keyfile, tls->pw_callback);
		if(rc){
			free(userdata.messages);
			userdata.messages = NULL;
			mosquitto_destroy(mosq);
			return rc;
		}
		rc = mosquitto_tls_opts_set(mosq, tls->cert_reqs, tls->tls_version, tls->ciphers);
		if(rc){
			free(userdata.messages);
			userdata.messages = NULL;
			mosquitto_destroy(mosq);
			return rc;
		}
	}

	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_message_callback_set(mosq, on_message);

	rc = mosquitto_connect(mosq, host, port, keepalive);
	if(rc){
		free(userdata.messages);
		userdata.messages = NULL;
		mosquitto_destroy(mosq);
		return rc;
	}
	rc = mosquitto_loop_forever(mosq, -1, 1);
	mosquitto_destroy(mosq);
	if(userdata.rc){
		rc = userdata.rc;
	}
	if(!rc && userdata.max_msg_count == 0){
		*messages = userdata.messages;
		return MOSQ_ERR_SUCCESS;
	}else{
		for(i=0; i<msg_count; i++){
			mosquitto_message_free_contents(&userdata.messages[i]);
		}
		free(userdata.messages);
		userdata.messages = NULL;
		return rc;
	}
}

