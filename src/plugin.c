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

#include "mosquitto_internal.h"
#include "mosquitto_broker_internal.h"

const char *mosquitto_client_username(const struct mosquitto *context)
{
#ifdef WITH_BRIDGE
	if(context->bridge){
		return context->bridge->local_username;
	}else
#endif
	{
		return context->username;
	}
}
