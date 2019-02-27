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

#include <assert.h>
#include <string.h>

#ifdef WIN32
#  include <winsock2.h>
#  include <aclapi.h>
#  include <io.h>
#  include <lmcons.h>
#else
#  include <sys/stat.h>
#endif


#ifdef WITH_BROKER
#include "mosquitto_broker_internal.h"
#endif

#include "mosquitto.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "send_mosq.h"
#include "time_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"

/* Check that a topic used for publishing is valid.
 * Search for + or # in a topic. Return MOSQ_ERR_INVAL if found.
 * Also returns MOSQ_ERR_INVAL if the topic string is too long.
 * Returns MOSQ_ERR_SUCCESS if everything is fine.
 */
int mosquitto_pub_topic_check(const char *str)
{
	int len = 0;
	while(str && str[0]){
		if(str[0] == '+' || str[0] == '#'){
			return MOSQ_ERR_INVAL;
		}
		len++;
		str = &str[1];
	}
	if(len > 65535) return MOSQ_ERR_INVAL;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_pub_topic_check2(const char *str, size_t len)
{
	int i;

	if(len > 65535) return MOSQ_ERR_INVAL;

	for(i=0; i<len; i++){
		if(str[i] == '+' || str[i] == '#'){
			return MOSQ_ERR_INVAL;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

/* Check that a topic used for subscriptions is valid.
 * Search for + or # in a topic, check they aren't in invalid positions such as
 * foo/#/bar, foo/+bar or foo/bar#.
 * Return MOSQ_ERR_INVAL if invalid position found.
 * Also returns MOSQ_ERR_INVAL if the topic string is too long.
 * Returns MOSQ_ERR_SUCCESS if everything is fine.
 */
int mosquitto_sub_topic_check(const char *str)
{
	char c = '\0';
	int len = 0;
	while(str && str[0]){
		if(str[0] == '+'){
			if((c != '\0' && c != '/') || (str[1] != '\0' && str[1] != '/')){
				return MOSQ_ERR_INVAL;
			}
		}else if(str[0] == '#'){
			if((c != '\0' && c != '/')  || str[1] != '\0'){
				return MOSQ_ERR_INVAL;
			}
		}
		len++;
		c = str[0];
		str = &str[1];
	}
	if(len > 65535) return MOSQ_ERR_INVAL;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_sub_topic_check2(const char *str, size_t len)
{
	char c = '\0';
	int i;

	if(len > 65535) return MOSQ_ERR_INVAL;

	for(i=0; i<len; i++){
		if(str[i] == '+'){
			if((c != '\0' && c != '/') || (i<len-1 && str[i+1] != '/')){
				return MOSQ_ERR_INVAL;
			}
		}else if(str[i] == '#'){
			if((c != '\0' && c != '/')  || i<len-1){
				return MOSQ_ERR_INVAL;
			}
		}
		c = str[i];
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_topic_matches_sub(const char *sub, const char *topic, bool *result)
{
	int slen, tlen;

	if(!result) return MOSQ_ERR_INVAL;
	*result = false;

	if(!sub || !topic){
		return MOSQ_ERR_INVAL;
	}

	slen = strlen(sub);
	tlen = strlen(topic);

	return mosquitto_topic_matches_sub2(sub, slen, topic, tlen, result);
}

/* Does a topic match a subscription? */
int mosquitto_topic_matches_sub2(const char *sub, size_t sublen, const char *topic, size_t topiclen, bool *result)
{
	int i;
	int spos, tpos;
	bool multilevel_wildcard = false;

	if(!result) return MOSQ_ERR_INVAL;
	*result = false;

	if(!sub || !topic){
		return MOSQ_ERR_INVAL;
	}

	if(!sublen || !topiclen){
		*result = false;
		return MOSQ_ERR_INVAL;
	}

	if(sublen && topiclen){
		if((sub[0] == '$' && topic[0] != '$')
				|| (topic[0] == '$' && sub[0] != '$')){

			return MOSQ_ERR_SUCCESS;
		}
	}

	spos = 0;
	tpos = 0;

	while(spos < sublen && tpos <= topiclen){
		if(topic[tpos] == '+' || topic[tpos] == '#'){
			return MOSQ_ERR_INVAL;
		}
		if(tpos == topiclen || sub[spos] != topic[tpos]){ /* Check for wildcard matches */
			if(sub[spos] == '+'){
				/* Check for bad "+foo" or "a/+foo" subscription */
				if(spos > 0 && sub[spos-1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				/* Check for bad "foo+" or "foo+/a" subscription */
				if(spos < sublen-1 && sub[spos+1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				spos++;
				while(tpos < topiclen && topic[tpos] != '/'){
					tpos++;
				}
				if(tpos == topiclen && spos == sublen){
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}else if(sub[spos] == '#'){
				/* Check for bad "foo#" subscription */
				if(spos > 0 && sub[spos-1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				/* Check for # not the final character of the sub, e.g. "#foo" */
				if(spos+1 != sublen){
					return MOSQ_ERR_INVAL;
				}else{
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}else{
				/* Check for e.g. foo/bar matching foo/+/# */
				if(spos > 0
						&& spos+2 == sublen
						&& tpos == topiclen
						&& sub[spos-1] == '+'
						&& sub[spos] == '/'
						&& sub[spos+1] == '#')
				{
					*result = true;
					multilevel_wildcard = true;
					return MOSQ_ERR_SUCCESS;
				}

				/* There is no match at this point, but is the sub invalid? */
				for(i=spos; i<sublen; i++){
					if(sub[i] == '#' && i+1 != sublen){
						return MOSQ_ERR_INVAL;
					}
				}

				/* Valid input, but no match */
				return MOSQ_ERR_SUCCESS;
			}
		}else{
			/* sub[spos] == topic[tpos] */
			if(tpos == topiclen-1){
				/* Check for e.g. foo matching foo/# */
				if(spos == sublen-3
						&& sub[spos+1] == '/'
						&& sub[spos+2] == '#'){
					*result = true;
					multilevel_wildcard = true;
					return MOSQ_ERR_SUCCESS;
				}
			}
			spos++;
			tpos++;
			if(spos == sublen && tpos == topiclen){
				*result = true;
				return MOSQ_ERR_SUCCESS;
			}else if(tpos == topiclen && spos == sublen-1 && sub[spos] == '+'){
				if(spos > 0 && sub[spos-1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				spos++;
				*result = true;
				return MOSQ_ERR_SUCCESS;
			}
		}
	}
	if(multilevel_wildcard == false && (tpos < topiclen || spos < sublen)){
		*result = false;
	}

	return MOSQ_ERR_SUCCESS;
}
