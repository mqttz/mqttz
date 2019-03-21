/* Tests for persistence.
 *
 * FIXME - these need to be aggressive about finding failures, at the moment
 * they are just confirming that good behaviour works. */

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#define WITH_BROKER
#define WITH_PERSISTENCE

#include "mosquitto_broker_internal.h"
#include "persist.h"

uint64_t last_retained;
char *last_sub = NULL;
int last_qos;
uint32_t last_identifier;

static void TEST_persistence_disabled(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
}


static void TEST_empty_file(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;

	config.persistence_filepath = "files/persist_read/empty.test-db";
	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
}


static void TEST_corrupt_header(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;

	config.persistence_filepath = "files/persist_read/corrupt-header-short.test-db";
	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, 1);

	config.persistence_filepath = "files/persist_read/corrupt-header-long.test-db";
	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, 1);
}

static void TEST_unsupported_version(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/unsupported-version.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, 1);
}


static void TEST_v3_config_ok(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v3-cfg.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.last_db_id, 0x7856341200000000);
}


static void TEST_v4_config_ok(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v4-cfg.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.last_db_id, 0x7856341200000000);
}


static void TEST_v3_config_truncated(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v3-cfg-truncated.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, 1);
	CU_ASSERT_EQUAL(db.last_db_id, 0);
}


static void TEST_v3_config_bad_dbid(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v3-cfg-bad-dbid.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, 1);
	CU_ASSERT_EQUAL(db.last_db_id, 0);
}


static void TEST_v3_bad_chunk(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v3-bad-chunk.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.last_db_id, 0x17);
}


static void TEST_v3_message_store(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v3-message-store.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.msg_store_count, 1);
	CU_ASSERT_EQUAL(db.msg_store_bytes, 7);
	CU_ASSERT_PTR_NOT_NULL(db.msg_store);
	if(db.msg_store){
		CU_ASSERT_EQUAL(db.msg_store->db_id, 1);
		CU_ASSERT_STRING_EQUAL(db.msg_store->source_id, "source_id");
		CU_ASSERT_EQUAL(db.msg_store->source_mid, 2);
		CU_ASSERT_EQUAL(db.msg_store->mid, 0);
		CU_ASSERT_EQUAL(db.msg_store->qos, 2);
		CU_ASSERT_EQUAL(db.msg_store->retain, 1);
		CU_ASSERT_STRING_EQUAL(db.msg_store->topic, "topic");
		CU_ASSERT_EQUAL(db.msg_store->payloadlen, 7);
		if(db.msg_store->payloadlen == 7){
			CU_ASSERT_NSTRING_EQUAL(UHPA_ACCESS_PAYLOAD(db.msg_store), "payload", 7);
		}
	}
}

static void TEST_v3_client(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	struct mosquitto *context;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v3-client.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);

	CU_ASSERT_PTR_NOT_NULL(db.contexts_by_id);
	HASH_FIND(hh_id, db.contexts_by_id, "client-id", strlen("client-id"), context);
	CU_ASSERT_PTR_NOT_NULL(context);
	if(context){
		CU_ASSERT_PTR_NULL(context->inflight_msgs);
		CU_ASSERT_EQUAL(context->last_mid, 0x5287);
	}
}

static void TEST_v3_client_message(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	struct mosquitto *context;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v3-client-message.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);

	CU_ASSERT_PTR_NOT_NULL(db.contexts_by_id);
	HASH_FIND(hh_id, db.contexts_by_id, "client-id", strlen("client-id"), context);
	CU_ASSERT_PTR_NOT_NULL(context);
	if(context){
		CU_ASSERT_PTR_NOT_NULL(context->inflight_msgs);
		if(context->inflight_msgs){
			CU_ASSERT_PTR_NULL(context->inflight_msgs->next);
			CU_ASSERT_PTR_NOT_NULL(context->inflight_msgs->store);
			if(context->inflight_msgs->store){
				CU_ASSERT_EQUAL(context->inflight_msgs->store->ref_count, 1);
				CU_ASSERT_STRING_EQUAL(context->inflight_msgs->store->source_id, "source_id");
				CU_ASSERT_EQUAL(context->inflight_msgs->store->source_mid, 2);
				CU_ASSERT_EQUAL(context->inflight_msgs->store->mid, 0);
				CU_ASSERT_EQUAL(context->inflight_msgs->store->qos, 2);
				CU_ASSERT_EQUAL(context->inflight_msgs->store->retain, 1);
				CU_ASSERT_STRING_EQUAL(context->inflight_msgs->store->topic, "topic");
				CU_ASSERT_EQUAL(context->inflight_msgs->store->payloadlen, 7);
				if(context->inflight_msgs->store->payloadlen == 7){
					CU_ASSERT_NSTRING_EQUAL(UHPA_ACCESS_PAYLOAD(context->inflight_msgs->store), "payload", 7);
				}
			}
			CU_ASSERT_EQUAL(context->inflight_msgs->mid, 0x73);
			CU_ASSERT_EQUAL(context->inflight_msgs->qos, 1);
			CU_ASSERT_EQUAL(context->inflight_msgs->retain, 0);
			CU_ASSERT_EQUAL(context->inflight_msgs->direction, mosq_md_out);
			CU_ASSERT_EQUAL(context->inflight_msgs->state, mosq_ms_wait_for_puback);
			CU_ASSERT_EQUAL(context->inflight_msgs->dup, 0);
		}
	}
}

static void TEST_v3_retain(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	last_retained = 0;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v3-retain.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.msg_store_count, 1);
	CU_ASSERT_EQUAL(db.msg_store_bytes, 7);
	CU_ASSERT_PTR_NOT_NULL(db.msg_store);
	if(db.msg_store){
		CU_ASSERT_EQUAL(db.msg_store->db_id, 0x54);
		CU_ASSERT_STRING_EQUAL(db.msg_store->source_id, "source_id");
		CU_ASSERT_EQUAL(db.msg_store->source_mid, 2);
		CU_ASSERT_EQUAL(db.msg_store->mid, 0);
		CU_ASSERT_EQUAL(db.msg_store->qos, 2);
		CU_ASSERT_EQUAL(db.msg_store->retain, 1);
		CU_ASSERT_STRING_EQUAL(db.msg_store->topic, "topic");
		CU_ASSERT_EQUAL(db.msg_store->payloadlen, 7);
		if(db.msg_store->payloadlen == 7){
			CU_ASSERT_NSTRING_EQUAL(UHPA_ACCESS_PAYLOAD(db.msg_store), "payload", 7);
		}
	}
	CU_ASSERT_EQUAL(last_retained, 0x54);
}

static void TEST_v3_sub(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	struct mosquitto *context;
	int rc;

	last_sub = NULL;
	last_qos = -1;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v3-sub.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);

	CU_ASSERT_PTR_NOT_NULL(db.contexts_by_id);
	HASH_FIND(hh_id, db.contexts_by_id, "client-id", strlen("client-id"), context);
	CU_ASSERT_PTR_NOT_NULL(context);
	if(context){
		CU_ASSERT_PTR_NOT_NULL(last_sub);
		if(last_sub){
			CU_ASSERT_STRING_EQUAL(last_sub, "subscription")
			free(last_sub);
		}
		CU_ASSERT_EQUAL(last_qos, 1);
	}
}

static void TEST_v4_message_store(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v4-message-store.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.msg_store_count, 1);
	CU_ASSERT_EQUAL(db.msg_store_bytes, 7);
	CU_ASSERT_PTR_NOT_NULL(db.msg_store);
	if(db.msg_store){
		CU_ASSERT_EQUAL(db.msg_store->db_id, 0xFEDCBA9876543210);
		CU_ASSERT_STRING_EQUAL(db.msg_store->source_id, "source_id");
		CU_ASSERT_EQUAL(db.msg_store->source_mid, 0x88);
		CU_ASSERT_EQUAL(db.msg_store->mid, 0);
		CU_ASSERT_EQUAL(db.msg_store->qos, 1);
		CU_ASSERT_EQUAL(db.msg_store->retain, 0);
		CU_ASSERT_STRING_EQUAL(db.msg_store->topic, "topic");
		CU_ASSERT_EQUAL(db.msg_store->payloadlen, 7);
		if(db.msg_store->payloadlen == 7){
			CU_ASSERT_NSTRING_EQUAL(UHPA_ACCESS_PAYLOAD(db.msg_store), "payload", 7);
		}
	}
}

static void TEST_v5_config_ok(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v5-cfg.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.last_db_id, 0x7856341200000000);
}


static void TEST_v5_config_truncated(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v5-cfg-truncated.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, 1);
	CU_ASSERT_EQUAL(db.last_db_id, 0);
}


static void TEST_v5_bad_chunk(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v5-bad-chunk.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.last_db_id, 0x17);
}


static void TEST_v5_message_store(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v5-message-store.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.msg_store_count, 1);
	CU_ASSERT_EQUAL(db.msg_store_bytes, 7);
	CU_ASSERT_PTR_NOT_NULL(db.msg_store);
	if(db.msg_store){
		CU_ASSERT_EQUAL(db.msg_store->db_id, 1);
		CU_ASSERT_STRING_EQUAL(db.msg_store->source_id, "source_id");
		CU_ASSERT_EQUAL(db.msg_store->source_mid, 2);
		CU_ASSERT_EQUAL(db.msg_store->mid, 0);
		CU_ASSERT_EQUAL(db.msg_store->qos, 2);
		CU_ASSERT_EQUAL(db.msg_store->retain, 1);
		CU_ASSERT_STRING_EQUAL(db.msg_store->topic, "topic");
		CU_ASSERT_EQUAL(db.msg_store->payloadlen, 7);
		if(db.msg_store->payloadlen == 7){
			CU_ASSERT_NSTRING_EQUAL(UHPA_ACCESS_PAYLOAD(db.msg_store), "payload", 7);
		}
	}
}

static void TEST_v5_client(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	struct mosquitto *context;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v5-client.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);

	CU_ASSERT_PTR_NOT_NULL(db.contexts_by_id);
	HASH_FIND(hh_id, db.contexts_by_id, "client-id", strlen("client-id"), context);
	CU_ASSERT_PTR_NOT_NULL(context);
	if(context){
		CU_ASSERT_PTR_NULL(context->inflight_msgs);
		CU_ASSERT_EQUAL(context->last_mid, 0x5287);
	}
}

static void TEST_v5_client_message(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	struct mosquitto *context;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v5-client-message.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);

	CU_ASSERT_PTR_NOT_NULL(db.contexts_by_id);
	HASH_FIND(hh_id, db.contexts_by_id, "client-id", strlen("client-id"), context);
	CU_ASSERT_PTR_NOT_NULL(context);
	if(context){
		CU_ASSERT_PTR_NOT_NULL(context->inflight_msgs);
		if(context->inflight_msgs){
			CU_ASSERT_PTR_NULL(context->inflight_msgs->next);
			CU_ASSERT_PTR_NOT_NULL(context->inflight_msgs->store);
			if(context->inflight_msgs->store){
				CU_ASSERT_EQUAL(context->inflight_msgs->store->ref_count, 1);
				CU_ASSERT_STRING_EQUAL(context->inflight_msgs->store->source_id, "source_id");
				CU_ASSERT_EQUAL(context->inflight_msgs->store->source_mid, 2);
				CU_ASSERT_EQUAL(context->inflight_msgs->store->mid, 0);
				CU_ASSERT_EQUAL(context->inflight_msgs->store->qos, 2);
				CU_ASSERT_EQUAL(context->inflight_msgs->store->retain, 1);
				CU_ASSERT_STRING_EQUAL(context->inflight_msgs->store->topic, "topic");
				CU_ASSERT_EQUAL(context->inflight_msgs->store->payloadlen, 7);
				if(context->inflight_msgs->store->payloadlen == 7){
					CU_ASSERT_NSTRING_EQUAL(UHPA_ACCESS_PAYLOAD(context->inflight_msgs->store), "payload", 7);
				}
			}
			CU_ASSERT_EQUAL(context->inflight_msgs->mid, 0x73);
			CU_ASSERT_EQUAL(context->inflight_msgs->qos, 1);
			CU_ASSERT_EQUAL(context->inflight_msgs->retain, 0);
			CU_ASSERT_EQUAL(context->inflight_msgs->direction, mosq_md_out);
			CU_ASSERT_EQUAL(context->inflight_msgs->state, mosq_ms_wait_for_puback);
			CU_ASSERT_EQUAL(context->inflight_msgs->dup, 0);
		}
	}
}

static void TEST_v5_retain(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	int rc;

	last_retained = 0;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v5-retain.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(db.msg_store_count, 1);
	CU_ASSERT_EQUAL(db.msg_store_bytes, 7);
	CU_ASSERT_PTR_NOT_NULL(db.msg_store);
	if(db.msg_store){
		CU_ASSERT_EQUAL(db.msg_store->db_id, 0x54);
		CU_ASSERT_STRING_EQUAL(db.msg_store->source_id, "source_id");
		CU_ASSERT_EQUAL(db.msg_store->source_mid, 2);
		CU_ASSERT_EQUAL(db.msg_store->mid, 0);
		CU_ASSERT_EQUAL(db.msg_store->qos, 2);
		CU_ASSERT_EQUAL(db.msg_store->retain, 1);
		CU_ASSERT_STRING_EQUAL(db.msg_store->topic, "topic");
		CU_ASSERT_EQUAL(db.msg_store->payloadlen, 7);
		if(db.msg_store->payloadlen == 7){
			CU_ASSERT_NSTRING_EQUAL(UHPA_ACCESS_PAYLOAD(db.msg_store), "payload", 7);
		}
	}
	CU_ASSERT_EQUAL(last_retained, 0x54);
}

static void TEST_v5_sub(void)
{
	struct mosquitto_db db;
	struct mosquitto__config config;
	struct mosquitto *context;
	int rc;

	last_sub = NULL;
	last_qos = -1;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	db.config = &config;

	config.persistence = true;
	config.persistence_filepath = "files/persist_read/v5-sub.test-db";

	rc = persist__restore(&db);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);

	CU_ASSERT_PTR_NOT_NULL(db.contexts_by_id);
	HASH_FIND(hh_id, db.contexts_by_id, "client-id", strlen("client-id"), context);
	CU_ASSERT_PTR_NOT_NULL(context);
	if(context){
		CU_ASSERT_PTR_NOT_NULL(last_sub);
		if(last_sub){
			CU_ASSERT_STRING_EQUAL(last_sub, "subscription")
			free(last_sub);
		}
		CU_ASSERT_EQUAL(last_qos, 1);
		CU_ASSERT_EQUAL(last_identifier, 0x7623);
	}
}

/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_persist_read_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Persist read", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit persist read test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Persistence disabled", TEST_persistence_disabled)
			|| !CU_add_test(test_suite, "Empty file", TEST_empty_file)
			|| !CU_add_test(test_suite, "Corrupt header", TEST_corrupt_header)
			|| !CU_add_test(test_suite, "Unsupported version", TEST_unsupported_version)
			|| !CU_add_test(test_suite, "v3 config ok", TEST_v3_config_ok)
			|| !CU_add_test(test_suite, "v3 config bad truncated", TEST_v3_config_truncated)
			|| !CU_add_test(test_suite, "v3 config bad dbid", TEST_v3_config_bad_dbid)
			|| !CU_add_test(test_suite, "v3 bad chunk", TEST_v3_bad_chunk)
			|| !CU_add_test(test_suite, "v3 message store", TEST_v3_message_store)
			|| !CU_add_test(test_suite, "v3 client", TEST_v3_client)
			|| !CU_add_test(test_suite, "v3 client message", TEST_v3_client_message)
			|| !CU_add_test(test_suite, "v3 retain", TEST_v3_retain)
			|| !CU_add_test(test_suite, "v3 sub", TEST_v3_sub)
			|| !CU_add_test(test_suite, "v4 config ok", TEST_v4_config_ok)
			|| !CU_add_test(test_suite, "v4 message store", TEST_v4_message_store)
			|| !CU_add_test(test_suite, "v5 config ok", TEST_v5_config_ok)
			|| !CU_add_test(test_suite, "v5 config bad truncated", TEST_v5_config_truncated)
			|| !CU_add_test(test_suite, "v5 bad chunk", TEST_v5_bad_chunk)
			|| !CU_add_test(test_suite, "v5 message store", TEST_v5_message_store)
			|| !CU_add_test(test_suite, "v5 client", TEST_v5_client)
			|| !CU_add_test(test_suite, "v5 client message", TEST_v5_client_message)
			|| !CU_add_test(test_suite, "v5 retain", TEST_v5_retain)
			|| !CU_add_test(test_suite, "v5 sub", TEST_v5_sub)
			){

		printf("Error adding persist CUnit tests.\n");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int fails;

    if(CU_initialize_registry() != CUE_SUCCESS){
        printf("Error initializing CUnit registry.\n");
        return 1;
    }

    if(0
			|| init_persist_read_tests()
			){

        CU_cleanup_registry();
        return 1;
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
	fails = CU_get_number_of_failures();
    CU_cleanup_registry();

    return (int)fails;
}
