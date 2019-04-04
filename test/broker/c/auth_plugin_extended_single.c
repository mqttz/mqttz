#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

int mosquitto_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, int access, const struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
	return MOSQ_ERR_PLUGIN_DEFER;
}


int mosquitto_auth_start(void *user_data, const struct mosquitto *client, const char *method, const void *data, int data_len)
{
	if(!strcmp(method, "error")){
		return MOSQ_ERR_INVAL;
	}else if(!strcmp(method, "non-matching")){
		return MOSQ_ERR_NOT_SUPPORTED;
	}else if(!strcmp(method, "single")){
		data_len = data_len>strlen("data")?strlen("data"):data_len;
		if(!memcmp(data, "data", data_len)){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_AUTH;
		}
	}
	return MOSQ_ERR_NOT_SUPPORTED;
}

int mosquitto_auth_continue(void *user_data, const struct mosquitto *client, const char *method, const void *data, int data_len)
{
	return MOSQ_ERR_AUTH;
}
