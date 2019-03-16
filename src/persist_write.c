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


static int persist__client_messages_write(struct mosquitto_db *db, FILE *db_fptr, struct mosquitto *context, struct mosquitto_client_msg *queue)
{
	uint32_t length;
	dbid_t i64temp;
	uint16_t i16temp, slen;
	uint8_t i8temp;
	struct mosquitto_client_msg *cmsg;

	assert(db);
	assert(db_fptr);
	assert(context);

	cmsg = queue;
	while(cmsg){
		if(!strncmp(cmsg->store->topic, "$SYS", 4)
				&& cmsg->store->ref_count <= 1
				&& cmsg->store->dest_id_count == 0){

			/* This $SYS message won't have been persisted, so we can't persist
			 * this client message. */
			cmsg = cmsg->next;
			continue;
		}

		slen = strlen(context->id);

		length = htonl(sizeof(dbid_t) + sizeof(uint16_t) + sizeof(uint8_t) +
				sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) +
				sizeof(uint8_t) + 2+slen);

		i16temp = htons(DB_CHUNK_CLIENT_MSG);
		write_e(db_fptr, &i16temp, sizeof(uint16_t));
		write_e(db_fptr, &length, sizeof(uint32_t));

		i16temp = htons(slen);
		write_e(db_fptr, &i16temp, sizeof(uint16_t));
		write_e(db_fptr, context->id, slen);

		i64temp = cmsg->store->db_id;
		write_e(db_fptr, &i64temp, sizeof(dbid_t));

		i16temp = htons(cmsg->mid);
		write_e(db_fptr, &i16temp, sizeof(uint16_t));

		i8temp = (uint8_t )cmsg->qos;
		write_e(db_fptr, &i8temp, sizeof(uint8_t));

		i8temp = (uint8_t )cmsg->retain;
		write_e(db_fptr, &i8temp, sizeof(uint8_t));

		i8temp = (uint8_t )cmsg->direction;
		write_e(db_fptr, &i8temp, sizeof(uint8_t));

		i8temp = (uint8_t )cmsg->state;
		write_e(db_fptr, &i8temp, sizeof(uint8_t));

		i8temp = (uint8_t )cmsg->dup;
		write_e(db_fptr, &i8temp, sizeof(uint8_t));

		cmsg = cmsg->next;
	}

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


static int persist__message_store_write(struct mosquitto_db *db, FILE *db_fptr)
{
	uint32_t length;
	dbid_t i64temp;
	uint32_t i32temp;
	uint16_t i16temp, tlen;
	uint8_t i8temp;
	struct mosquitto_msg_store *stored;
	bool force_no_retain;

	assert(db);
	assert(db_fptr);

	stored = db->msg_store;
	while(stored){
		if(stored->ref_count < 1){
			stored = stored->next;
			continue;
		}

		if(stored->topic && !strncmp(stored->topic, "$SYS", 4)){
			if(stored->ref_count <= 1 && stored->dest_id_count == 0){
				/* $SYS messages that are only retained shouldn't be persisted. */
				stored = stored->next;
				continue;
			}
			/* Don't save $SYS messages as retained otherwise they can give
			 * misleading information when reloaded. They should still be saved
			 * because a disconnected durable client may have them in their
			 * queue. */
			force_no_retain = true;
		}else{
			force_no_retain = false;
		}
		if(stored->topic){
			tlen = strlen(stored->topic);
		}else{
			tlen = 0;
		}
		length = sizeof(dbid_t) + sizeof(uint16_t) +
				sizeof(uint16_t) + sizeof(uint16_t) +
				2+tlen + sizeof(uint32_t) +
				stored->payloadlen + sizeof(uint8_t) + sizeof(uint8_t)
				+ 2*sizeof(uint16_t);

		if(stored->source_id){
			length += strlen(stored->source_id);
		}
		if(stored->source_username){
			length += strlen(stored->source_username);
		}
		length = htonl(length);

		i16temp = htons(DB_CHUNK_MSG_STORE);
		write_e(db_fptr, &i16temp, sizeof(uint16_t));
		write_e(db_fptr, &length, sizeof(uint32_t));

		i64temp = stored->db_id;
		write_e(db_fptr, &i64temp, sizeof(dbid_t));

		if(persist__write_string(db_fptr, stored->source_id, false)) return 1;
		if(persist__write_string(db_fptr, stored->source_username, true)) return 1;
		if(stored->source_listener){
			i16temp = htons(stored->source_listener->port);
		}else{
			i16temp = 0;
		}
		write_e(db_fptr, &i16temp, sizeof(uint16_t));


		i16temp = htons(stored->source_mid);
		write_e(db_fptr, &i16temp, sizeof(uint16_t));

		i16temp = htons(stored->mid);
		write_e(db_fptr, &i16temp, sizeof(uint16_t));

		i16temp = htons(tlen);
		write_e(db_fptr, &i16temp, sizeof(uint16_t));
		if(tlen){
			write_e(db_fptr, stored->topic, tlen);
		}

		i8temp = (uint8_t )stored->qos;
		write_e(db_fptr, &i8temp, sizeof(uint8_t));

		if(force_no_retain == false){
			i8temp = (uint8_t )stored->retain;
		}else{
			i8temp = 0;
		}
		write_e(db_fptr, &i8temp, sizeof(uint8_t));

		i32temp = htonl(stored->payloadlen);
		write_e(db_fptr, &i32temp, sizeof(uint32_t));
		if(stored->payloadlen){
			write_e(db_fptr, UHPA_ACCESS_PAYLOAD(stored), (unsigned int)stored->payloadlen);
		}

		stored = stored->next;
	}

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}

static int persist__client_write(struct mosquitto_db *db, FILE *db_fptr)
{
	struct mosquitto *context, *ctxt_tmp;
	uint16_t i16temp, slen;
	uint32_t length;
	time_t disconnect_t;

	assert(db);
	assert(db_fptr);

	HASH_ITER(hh_id, db->contexts_by_id, context, ctxt_tmp){
		if(context && context->clean_start == false){
			length = htonl(2+strlen(context->id) + sizeof(uint16_t) + sizeof(time_t));

			i16temp = htons(DB_CHUNK_CLIENT);
			write_e(db_fptr, &i16temp, sizeof(uint16_t));
			write_e(db_fptr, &length, sizeof(uint32_t));

			slen = strlen(context->id);
			i16temp = htons(slen);
			write_e(db_fptr, &i16temp, sizeof(uint16_t));
			write_e(db_fptr, context->id, slen);
			i16temp = htons(context->last_mid);
			write_e(db_fptr, &i16temp, sizeof(uint16_t));
			if(context->disconnect_t){
				disconnect_t = context->disconnect_t;
			}else{
				disconnect_t = time(NULL);
			}
			write_e(db_fptr, &disconnect_t, sizeof(time_t));

			if(persist__client_messages_write(db, db_fptr, context, context->inflight_msgs)) return 1;
			if(persist__client_messages_write(db, db_fptr, context, context->queued_msgs)) return 1;
		}
	}

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


static int persist__subs_retain_write(struct mosquitto_db *db, FILE *db_fptr, struct mosquitto__subhier *node, const char *topic, int level)
{
	struct mosquitto__subhier *subhier, *subhier_tmp;
	struct mosquitto__subleaf *sub;
	char *thistopic;
	uint32_t length;
	uint16_t i16temp;
	uint8_t i8temp;
	dbid_t i64temp;
	size_t slen;

	slen = strlen(topic) + node->topic_len + 2;
	thistopic = mosquitto__malloc(sizeof(char)*slen);
	if(!thistopic) return MOSQ_ERR_NOMEM;
	if(level > 1 || strlen(topic)){
		snprintf(thistopic, slen, "%s/%s", topic, node->topic);
	}else{
		snprintf(thistopic, slen, "%s", node->topic);
	}

	sub = node->subs;
	while(sub){
		if(sub->context->clean_start == false && sub->context->id){
			length = htonl(2+strlen(sub->context->id) + 2+strlen(thistopic) + sizeof(uint8_t));

			i16temp = htons(DB_CHUNK_SUB);
			write_e(db_fptr, &i16temp, sizeof(uint16_t));
			write_e(db_fptr, &length, sizeof(uint32_t));

			slen = strlen(sub->context->id);
			i16temp = htons(slen);
			write_e(db_fptr, &i16temp, sizeof(uint16_t));
			write_e(db_fptr, sub->context->id, slen);

			slen = strlen(thistopic);
			i16temp = htons(slen);
			write_e(db_fptr, &i16temp, sizeof(uint16_t));
			write_e(db_fptr, thistopic, slen);

			i8temp = (uint8_t )sub->qos;
			write_e(db_fptr, &i8temp, sizeof(uint8_t));
		}
		sub = sub->next;
	}
	if(node->retained){
		if(strncmp(node->retained->topic, "$SYS", 4)){
			/* Don't save $SYS messages. */
			length = htonl(sizeof(dbid_t));

			i16temp = htons(DB_CHUNK_RETAIN);
			write_e(db_fptr, &i16temp, sizeof(uint16_t));
			write_e(db_fptr, &length, sizeof(uint32_t));

			i64temp = node->retained->db_id;
			write_e(db_fptr, &i64temp, sizeof(dbid_t));
		}
	}

	HASH_ITER(hh, node->children, subhier, subhier_tmp){
		persist__subs_retain_write(db, db_fptr, subhier, thistopic, level+1);
	}
	mosquitto__free(thistopic);
	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}

static int persist__subs_retain_write_all(struct mosquitto_db *db, FILE *db_fptr)
{
	struct mosquitto__subhier *subhier, *subhier_tmp;

	HASH_ITER(hh, db->subs, subhier, subhier_tmp){
		if(subhier->children){
			persist__subs_retain_write(db, db_fptr, subhier->children, "", 0);
		}
	}
	
	return MOSQ_ERR_SUCCESS;
}

int persist__backup(struct mosquitto_db *db, bool shutdown)
{
	int rc = 0;
	FILE *db_fptr = NULL;
	uint32_t db_version_w = htonl(MOSQ_DB_VERSION);
	uint32_t crc = htonl(0);
	dbid_t i64temp;
	uint32_t i32temp;
	uint16_t i16temp;
	uint8_t i8temp;
	char *err;
	char *outfile = NULL;
	int len;

	if(!db || !db->config || !db->config->persistence_filepath) return MOSQ_ERR_INVAL;
	log__printf(NULL, MOSQ_LOG_INFO, "Saving in-memory database to %s.", db->config->persistence_filepath);

	len = strlen(db->config->persistence_filepath)+5;
	outfile = mosquitto__malloc(len+1);
	if(!outfile){
		log__printf(NULL, MOSQ_LOG_INFO, "Error saving in-memory database, out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	snprintf(outfile, len, "%s.new", db->config->persistence_filepath);
	outfile[len] = '\0';

#ifndef WIN32
	/**
 	*
	* If a system lost power during the rename operation at the
	* end of this file the filesystem could potentially be left
	* with a directory that looks like this after powerup:
	*
	* 24094 -rw-r--r--    2 root     root          4099 May 30 16:27 mosquitto.db
	* 24094 -rw-r--r--    2 root     root          4099 May 30 16:27 mosquitto.db.new
	*
	* The 24094 shows that mosquitto.db.new is hard-linked to the
	* same file as mosquitto.db.  If fopen(outfile, "wb") is naively
	* called then mosquitto.db will be truncated and the database
	* potentially corrupted.
	*
	* Any existing mosquitto.db.new file must be removed prior to
	* opening to guarantee that it is not hard-linked to
	* mosquitto.db.
	*
	*/
	rc = unlink(outfile);
	if (rc != 0) {
		if (errno != ENOENT) {
			log__printf(NULL, MOSQ_LOG_INFO, "Error saving in-memory database, unable to remove %s.", outfile);
			goto error;
		}
	}
#endif

	db_fptr = mosquitto__fopen(outfile, "wb", true);
	if(db_fptr == NULL){
		log__printf(NULL, MOSQ_LOG_INFO, "Error saving in-memory database, unable to open %s for writing.", outfile);
		goto error;
	}

	/* Header */
	write_e(db_fptr, magic, 15);
	write_e(db_fptr, &crc, sizeof(uint32_t));
	write_e(db_fptr, &db_version_w, sizeof(uint32_t));

	/* DB config */
	i16temp = htons(DB_CHUNK_CFG);
	write_e(db_fptr, &i16temp, sizeof(uint16_t));
	/* chunk length */
	i32temp = htonl(sizeof(dbid_t) + sizeof(uint8_t) + sizeof(uint8_t));
	write_e(db_fptr, &i32temp, sizeof(uint32_t));
	/* db written at broker shutdown or not */
	i8temp = shutdown;
	write_e(db_fptr, &i8temp, sizeof(uint8_t));
	i8temp = sizeof(dbid_t);
	write_e(db_fptr, &i8temp, sizeof(uint8_t));
	/* last db mid */
	i64temp = db->last_db_id;
	write_e(db_fptr, &i64temp, sizeof(dbid_t));

	if(persist__message_store_write(db, db_fptr)){
		goto error;
	}

	persist__client_write(db, db_fptr);
	persist__subs_retain_write_all(db, db_fptr);

#ifndef WIN32
	/**
	*
	* Closing a file does not guarantee that the contents are
	* written to disk.  Need to flush to send data from app to OS
	* buffers, then fsync to deliver data from OS buffers to disk
	* (as well as disk hardware permits).
	* 
	* man close (http://linux.die.net/man/2/close, 2016-06-20):
	* 
	*   "successful close does not guarantee that the data has
	*   been successfully saved to disk, as the kernel defers
	*   writes.  It is not common for a filesystem to flush
	*   the  buffers  when  the stream is closed.  If you need
	*   to be sure that the data is physically stored, use
	*   fsync(2).  (It will depend on the disk hardware at this
	*   point."
	*
	* This guarantees that the new state file will not overwrite
	* the old state file before its contents are valid.
	*
	*/

	fflush(db_fptr);
	fsync(fileno(db_fptr));
#endif
	fclose(db_fptr);

#ifdef WIN32
	if(remove(db->config->persistence_filepath) != 0){
		if(errno != ENOENT){
			goto error;
		}
	}
#endif
	if(rename(outfile, db->config->persistence_filepath) != 0){
		goto error;
	}
	mosquitto__free(outfile);
	outfile = NULL;
	return rc;
error:
	mosquitto__free(outfile);
	err = strerror(errno);
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", err);
	if(db_fptr) fclose(db_fptr);
	return 1;
}


#endif
