/*
Copyright (c) 2012-2016 Roger Light <roger@atchoo.org>

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

#ifndef MOSQUITTO_BROKER_H
#define MOSQUITTO_BROKER_H

struct mosquitto;

struct mosquitto_opt {
	char *key;
	char *value;
};

/* =========================================================================
 *
 * Utility Functions
 *
 * Use these functions from within your plugin.
 *
 * There are also very useful functions in libmosquitto.
 *
 * ========================================================================= */

/*
 * Function: mosquitto_log_printf
 *
 * Write a log message using the broker configured logging.
 *
 * Parameters:
 * 	level -    Log message priority. Can currently be one of:
 *
 *             MOSQ_LOG_INFO
 *             MOSQ_LOG_NOTICE
 *             MOSQ_LOG_WARNING
 *             MOSQ_LOG_ERR
 *             MOSQ_LOG_DEBUG
 *             MOSQ_LOG_SUBSCRIBE (not recommended for use by plugins)
 *             MOSQ_LOG_UNSUBSCRIBE (not recommended for use by plugins)
 *
 *             These values are defined in mosquitto.h.
 *
 *	fmt, ... - printf style format and arguments.
 */
void mosquitto_log_printf(int level, const char *fmt, ...);


/* =========================================================================
 *
 * Client Functions
 *
 * Use these functions to access client information.
 *
 * ========================================================================= */

/*
 * Function: mosquitto_client_username
 *
 * Retrieve the username associated with a client.
 */
const char *mosquitto_client_username(const struct mosquitto *client);

#endif
