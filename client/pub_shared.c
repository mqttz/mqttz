/*
Copyright (c) 2009-2018 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <time.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <mosquitto.h>
#include <mqtt_protocol.h>
#include "client_shared.h"
#include "pub_shared.h"

/* Global variables for use in callbacks. See sub_client.c for an example of
 * using a struct to hold variables for use in callbacks. */
int mid_sent = 0;
int status = STATUS_CONNECTING;
struct mosq_config cfg;

static int last_mid = -1;
static int last_mid_sent = -1;
static bool connected = true;
static bool disconnect_sent = false;
static char *buf = NULL;
static int buf_len = 1024;

void my_disconnect_callback(struct mosquitto *mosq, void *obj, int rc, const mosquitto_property *properties)
{
	connected = false;
}

void my_publish_callback(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
	last_mid_sent = mid;
	if(cfg.pub_mode == MSGMODE_STDIN_LINE){
		if(mid == last_mid){
			mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
			disconnect_sent = true;
		}
	}else if(disconnect_sent == false){
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		disconnect_sent = true;
	}
}

void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

int load_stdin(void)
{
	long pos = 0, rlen;
	char buf[1024];
	char *aux_message = NULL;

	cfg.pub_mode = MSGMODE_STDIN_FILE;

	while(!feof(stdin)){
		rlen = fread(buf, 1, 1024, stdin);
		aux_message = realloc(cfg.message, pos+rlen);
		if(!aux_message){
			if(!cfg.quiet) fprintf(stderr, "Error: Out of memory.\n");
			free(cfg.message);
			return 1;
		} else
		{
			cfg.message = aux_message;
		}
		memcpy(&(cfg.message[pos]), buf, rlen);
		pos += rlen;
	}
	cfg.msglen = pos;

	if(!cfg.msglen){
		if(!cfg.quiet) fprintf(stderr, "Error: Zero length input.\n");
		return 1;
	}

	return 0;
}

int load_file(const char *filename)
{
	long pos, rlen;
	FILE *fptr = NULL;

	fptr = fopen(filename, "rb");
	if(!fptr){
		if(!cfg.quiet) fprintf(stderr, "Error: Unable to open file \"%s\".\n", filename);
		return 1;
	}
	cfg.pub_mode = MSGMODE_FILE;
	fseek(fptr, 0, SEEK_END);
	cfg.msglen = ftell(fptr);
	if(cfg.msglen > 268435455){
		fclose(fptr);
		if(!cfg.quiet) fprintf(stderr, "Error: File \"%s\" is too large (>268,435,455 bytes).\n", filename);
		return 1;
	}else if(cfg.msglen == 0){
		fclose(fptr);
		if(!cfg.quiet) fprintf(stderr, "Error: File \"%s\" is empty.\n", filename);
		return 1;
	}else if(cfg.msglen < 0){
		fclose(fptr);
		if(!cfg.quiet) fprintf(stderr, "Error: Unable to determine size of file \"%s\".\n", filename);
		return 1;
	}
	fseek(fptr, 0, SEEK_SET);
	cfg.message = malloc(cfg.msglen);
	if(!cfg.message){
		fclose(fptr);
		if(!cfg.quiet) fprintf(stderr, "Error: Out of memory.\n");
		return 1;
	}
	pos = 0;
	while(pos < cfg.msglen){
		rlen = fread(&(cfg.message[pos]), sizeof(char), cfg.msglen-pos, fptr);
		pos += rlen;
	}
	fclose(fptr);
	return 0;
}


int pub_shared_init(void)
{
	buf = malloc(buf_len);
	if(!buf){
		fprintf(stderr, "Error: Out of memory.\n");
		return 1;
	}
	return 0;
}


int pub_shared_loop(struct mosquitto *mosq)
{
	int read_len;
	int pos;
	int rc, rc2;
	char *buf2;
	int buf_len_actual;
	int mode;

	mode = cfg.pub_mode;

	if(mode == MSGMODE_STDIN_LINE){
		mosquitto_loop_start(mosq);
	}

	do{
		if(mode == MSGMODE_STDIN_LINE){
			if(status == STATUS_CONNACK_RECVD){
				pos = 0;
				read_len = buf_len;
				while(connected && fgets(&buf[pos], read_len, stdin)){
					buf_len_actual = strlen(buf);
					if(buf[buf_len_actual-1] == '\n'){
						buf[buf_len_actual-1] = '\0';
						rc2 = my_publish(mosq, &mid_sent, cfg.topic, buf_len_actual-1, buf, cfg.qos, cfg.retain);
						if(rc2){
							if(!cfg.quiet) fprintf(stderr, "Error: Publish returned %d, disconnecting.\n", rc2);
							mosquitto_disconnect_v5(mosq, MQTT_RC_DISCONNECT_WITH_WILL_MSG, cfg.disconnect_props);
						}
						break;
					}else{
						buf_len += 1024;
						pos += 1023;
						read_len = 1024;
						buf2 = realloc(buf, buf_len);
						if(!buf2){
							fprintf(stderr, "Error: Out of memory.\n");
							return MOSQ_ERR_NOMEM;
						}
						buf = buf2;
					}
				}
				if(feof(stdin)){
					if(mid_sent == -1){
						/* Empty file */
						mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
						disconnect_sent = true;
						status = STATUS_DISCONNECTING;
					}else{
						last_mid = mid_sent;
						status = STATUS_WAITING;
					}
				}
			}else if(status == STATUS_WAITING){
				if(last_mid_sent == last_mid && disconnect_sent == false){
					mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
					disconnect_sent = true;
				}
#ifdef WIN32
				Sleep(100);
#else
				struct timespec ts;
				ts.tv_sec = 0;
				ts.tv_nsec = 100000000;
				nanosleep(&ts, NULL);
#endif
			}
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = mosquitto_loop(mosq, -1, 1);
		}
	}while(rc == MOSQ_ERR_SUCCESS && connected);

	if(mode == MSGMODE_STDIN_LINE){
		mosquitto_loop_stop(mosq, false);
	}
	return 0;
}


void pub_shared_cleanup(void)
{
	free(buf);
}
