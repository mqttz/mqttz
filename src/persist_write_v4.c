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

#ifdef WITH_PERSISTENCE

#ifndef WIN32
#include <arpa/inet.h>
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "persist.h"
#include "time_mosq.h"
#include "util_mosq.h"

static int persist__write_string(FILE *db_fptr, const char *str, bool nullok);

static int persist__write_string(FILE *db_fptr, const char *str, bool nullok)
{
	uint16_t i16temp, slen;

	if(str){
		slen = strlen(str);
		i16temp = htons(slen);
		write_e(db_fptr, &i16temp, sizeof(uint16_t));
		write_e(db_fptr, str, slen);
	}else if(nullok){
		i16temp = htons(0);
		write_e(db_fptr, &i16temp, sizeof(uint16_t));
	}else{
		return 1;
	}

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


int persist__client_chunk_write_v4(FILE *db_fptr, const struct P_client *chunk)
{
	uint32_t length;
	uint16_t i16temp;
	time_t disconnect_t;

	length = htonl(2+chunk->F.id_len + sizeof(uint16_t) + sizeof(time_t));

	i16temp = htons(DB_CHUNK_CLIENT);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));
	write_e(db_fptr, &length, sizeof(uint32_t));

	if(persist__write_string(db_fptr, chunk->client_id, false)) return 1;

	i16temp = htons(chunk->F.last_mid);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));
	if(chunk->F.disconnect_t){
		disconnect_t = chunk->F.disconnect_t;
	}else{
		disconnect_t = time(NULL);
	}
	write_e(db_fptr, &disconnect_t, sizeof(time_t));

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


int persist__client_msg_chunk_write_v4(FILE *db_fptr, const struct P_client_msg *chunk)
{
	uint32_t length;
	uint16_t i16temp;

	length = htonl(sizeof(dbid_t) + sizeof(uint16_t) + sizeof(uint8_t) +
			sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) +
			sizeof(uint8_t) + 2+chunk->F.id_len);

	i16temp = htons(DB_CHUNK_CLIENT_MSG);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));
	write_e(db_fptr, &length, sizeof(uint32_t));

	if(persist__write_string(db_fptr, chunk->client_id, false)) return 1;

	write_e(db_fptr, &chunk->F.store_id, sizeof(dbid_t));

	i16temp = htons(chunk->F.mid);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));

	write_e(db_fptr, &chunk->F.qos, sizeof(uint8_t));
	write_e(db_fptr, &chunk->F.retain, sizeof(uint8_t));
	write_e(db_fptr, &chunk->F.direction, sizeof(uint8_t));
	write_e(db_fptr, &chunk->F.state, sizeof(uint8_t));
	write_e(db_fptr, &chunk->F.dup, sizeof(uint8_t));

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


int persist__message_store_chunk_write_v4(FILE *db_fptr, const struct P_msg_store *chunk)
{
	uint32_t length;
	uint32_t i32temp;
	uint16_t i16temp;

	length = htonl(sizeof(dbid_t) + sizeof(uint16_t) +
			sizeof(uint16_t) + sizeof(uint16_t) +
			2+chunk->F.topic_len + sizeof(uint32_t) +
			chunk->F.payloadlen + sizeof(uint8_t) + sizeof(uint8_t)
			+ 2*sizeof(uint16_t) + chunk->F.source_id_len + chunk->F.source_username_len);

	i16temp = htons(DB_CHUNK_MSG_STORE);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));
	write_e(db_fptr, &length, sizeof(uint32_t));

	write_e(db_fptr, &chunk->F.store_id, sizeof(dbid_t));

	if(persist__write_string(db_fptr, chunk->source.id, false)) return 1;
	if(persist__write_string(db_fptr, chunk->source.username, true)) return 1;

	i16temp = htons(chunk->F.source_port);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));

	i16temp = htons(chunk->F.source_mid);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));

	i16temp = htons(chunk->F.mid);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));

	if(persist__write_string(db_fptr, chunk->topic, true)) return 1;

	write_e(db_fptr, &chunk->F.qos, sizeof(uint8_t));
	write_e(db_fptr, &chunk->F.retain, sizeof(uint8_t));

	i32temp = htonl(chunk->F.payloadlen);
	write_e(db_fptr, &i32temp, sizeof(uint32_t));
	if(chunk->F.payloadlen){
		write_e(db_fptr, UHPA_ACCESS(chunk->payload, chunk->F.payloadlen), (unsigned int)chunk->F.payloadlen);
	}

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


int persist__retain_chunk_write_v4(FILE *db_fptr, const struct P_retain *chunk)
{
	uint32_t length;
	uint16_t i16temp;

	length = htonl(sizeof(dbid_t));

	i16temp = htons(DB_CHUNK_RETAIN);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));
	write_e(db_fptr, &length, sizeof(uint32_t));

	write_e(db_fptr, &chunk->F.store_id, sizeof(dbid_t));

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


int persist__sub_chunk_write_v4(FILE *db_fptr, const struct P_sub *chunk)
{
	uint32_t length;
	uint16_t i16temp;

	length = htonl(2+chunk->F.id_len + 2+chunk->F.topic_len + sizeof(uint8_t));

	i16temp = htons(DB_CHUNK_SUB);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));
	write_e(db_fptr, &length, sizeof(uint32_t));

	if(persist__write_string(db_fptr, chunk->client_id, false)) return 1;
	if(persist__write_string(db_fptr, chunk->topic, false)) return 1;

	write_e(db_fptr, &chunk->F.qos, sizeof(uint8_t));

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}
#endif
