#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mqtt_protocol.h"
#include "property_mosq.h"
#include "packet_mosq.h"

static void byte_prop_read_helper(
		uint8_t *payload,
		int remaining_length,
		int rc_expected,
		int identifier,
		uint8_t value_expected)
{
	struct mosquitto__packet packet;
	struct mqtt5__property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(&packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.i8, value_expected);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		property__free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_byte_helper(int identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 4; /* Proplen = (Identifier + byte)*2 */
	payload[1] = identifier;
	payload[2] = 1;
	payload[3] = identifier;
	payload[4] = 0;

	byte_prop_read_helper(payload, 5, MOSQ_ERR_PROTOCOL, identifier, 1);
}

static void bad_byte_helper(int identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = identifier;
	payload[2] = 2; /* 0, 1 are only valid values */

	byte_prop_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, identifier, 0);
}


static void int32_prop_read_helper(
		uint8_t *payload,
		int remaining_length,
		int rc_expected,
		int identifier,
		uint32_t value_expected)
{
	struct mosquitto__packet packet;
	struct mqtt5__property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(&packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.i32, value_expected);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		property__free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_int32_helper(int identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 10; /* Proplen = (Identifier + int32)*2 */
	payload[1] = identifier;
	payload[2] = 1;
	payload[3] = 1;
	payload[4] = 1;
	payload[5] = 1;
	payload[6] = identifier;
	payload[7] = 0;
	payload[8] = 0;
	payload[9] = 0;
	payload[10] = 0;

	int32_prop_read_helper(payload, 11, MOSQ_ERR_PROTOCOL, identifier, 1);
}


static void int16_prop_read_helper(
		uint8_t *payload,
		int remaining_length,
		int rc_expected,
		int identifier,
		uint16_t value_expected)
{
	struct mosquitto__packet packet;
	struct mqtt5__property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(&packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.i16, value_expected);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		property__free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_int16_helper(int identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 6; /* Proplen = (Identifier + int16)*2 */
	payload[1] = identifier;
	payload[2] = 1;
	payload[3] = 1;
	payload[4] = identifier;
	payload[5] = 0;
	payload[6] = 0;

	int16_prop_read_helper(payload, 7, MOSQ_ERR_PROTOCOL, identifier, 1);
}

static void string_prop_read_helper(
		uint8_t *payload,
		int remaining_length,
		int rc_expected,
		int identifier,
		const char *value_expected)
{
	struct mosquitto__packet packet;
	struct mqtt5__property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(&packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.s.len, strlen(value_expected));
		CU_ASSERT_STRING_EQUAL(properties->value.s.v, value_expected);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		property__free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_string_helper(int identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = identifier;
	payload[2] = 0;
	payload[3] = 1; /* 1 length string */
	payload[4] = 'h';
	payload[5] = identifier;
	payload[6] = 0;
	payload[7] = 1;
	payload[8] = 'h';

	string_prop_read_helper(payload, 9, MOSQ_ERR_PROTOCOL, identifier, "");
}

static void bad_string_helper(int identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 6;
	payload[1] = identifier;
	payload[2] = 0;
	payload[3] = 3; /* 1 length string */
	payload[4] = 'h';
	payload[5] = 0; /* 0 in string not allowed */
	payload[6] = 'h';

	string_prop_read_helper(payload, 7, MOSQ_ERR_MALFORMED_UTF8, identifier, "");
}

static void binary_prop_read_helper(
		uint8_t *payload,
		int remaining_length,
		int rc_expected,
		int identifier,
		const uint8_t *value_expected,
		int len_expected)
{
	struct mosquitto__packet packet;
	struct mqtt5__property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(&packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.bin.len, len_expected);
		CU_ASSERT_EQUAL(memcmp(properties->value.bin.v, value_expected, len_expected), 0);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		property__free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_binary_helper(int identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = identifier;
	payload[2] = 0;
	payload[3] = 1; /* 2 length binary */
	payload[4] = 'h';
	payload[5] = identifier;
	payload[6] = 0;
	payload[7] = 1;
	payload[8] = 'h';

	string_prop_read_helper(payload, 9, MOSQ_ERR_PROTOCOL, identifier, "");
}

/* ========================================================================
 * NO PROPERTIES
 * ======================================================================== */

static void TEST_no_properties(void)
{
	struct mosquitto__packet packet;
	struct mqtt5__property *properties = NULL;
	uint8_t payload[5];
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	packet.remaining_length = 1;
	rc = property__read_all(&packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 1);
}

static void TEST_truncated(void)
{
	struct mosquitto__packet packet;
	struct mqtt5__property *properties = NULL;
	uint8_t payload[5];
	int rc;

	/* Zero length packet */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	packet.remaining_length = 0;
	rc = property__read_all(&packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_PROTOCOL);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 0);

	/* Proplen > 0 but not enough data */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	payload[0] = 2;
	packet.payload = payload;
	packet.remaining_length = 1;
	rc = property__read_all(&packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_PROTOCOL);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 1);

	/* Proplen > 0 but not enough data */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	payload[0] = 4;
	payload[1] = PROP_PAYLOAD_FORMAT_INDICATOR;
	packet.payload = payload;
	packet.remaining_length = 2;
	rc = property__read_all(&packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_PROTOCOL);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 2);
}

/* ========================================================================
 * INVALID PROPERTY ID
 * ======================================================================== */

static void TEST_invalid_property_id(void)
{
	struct mosquitto__packet packet;
	struct mqtt5__property *properties = NULL;
	uint8_t payload[5];
	int rc;

	/* ID = 0 */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	payload[0] = 4;
	packet.payload = payload;
	packet.remaining_length = 2;
	rc = property__read_all(&packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_MALFORMED_PACKET);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 2);

	/* ID = 4 */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	payload[0] = 4;
	payload[1] = 4;
	packet.payload = payload;
	packet.remaining_length = 2;
	rc = property__read_all(&packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_MALFORMED_PACKET);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 2);
}

/* ========================================================================
 * SINGLE PROPERTIES
 * ======================================================================== */

static void TEST_single_payload_format_indicator(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = PROP_PAYLOAD_FORMAT_INDICATOR;
	payload[2] = 1;

	byte_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, PROP_PAYLOAD_FORMAT_INDICATOR, 1);
}

static void TEST_single_request_problem_information(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = PROP_REQUEST_PROBLEM_INFO;
	payload[2] = 1;

	byte_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, PROP_REQUEST_PROBLEM_INFO, 1);
}

static void TEST_single_request_response_information(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = PROP_REQUEST_RESPONSE_INFO;
	payload[2] = 1;

	byte_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, PROP_REQUEST_RESPONSE_INFO, 1);
}

static void TEST_single_maximum_qos(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = PROP_MAXIMUM_QOS;
	payload[2] = 1;

	byte_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, PROP_MAXIMUM_QOS, 1);
}

static void TEST_single_retain_available(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = PROP_RETAIN_AVAILABLE;
	payload[2] = 1;

	byte_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, PROP_RETAIN_AVAILABLE, 1);
}

static void TEST_single_wildcard_subscription_available(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = PROP_WILDCARD_SUB_AVAILABLE;
	payload[2] = 0;

	byte_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, PROP_WILDCARD_SUB_AVAILABLE, 0);
}

static void TEST_single_subscription_identifier_available(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = PROP_SUBSCRIPTION_ID_AVAILABLE;
	payload[2] = 0;

	byte_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, PROP_SUBSCRIPTION_ID_AVAILABLE, 0);
}

static void TEST_single_shared_subscription_available(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = PROP_SHARED_SUB_AVAILABLE;
	payload[2] = 1;

	byte_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, PROP_SHARED_SUB_AVAILABLE, 1);
}

static void TEST_single_message_expiry_interval(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = PROP_MESSAGE_EXPIRY_INTERVAL;
	payload[2] = 0x12;
	payload[3] = 0x23;
	payload[4] = 0x34;
	payload[5] = 0x45;

	int32_prop_read_helper(payload, 6, MOSQ_ERR_SUCCESS, PROP_MESSAGE_EXPIRY_INTERVAL, 0x12233445);
}

static void TEST_single_session_expiry_interval(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = PROP_SESSION_EXPIRY_INTERVAL;
	payload[2] = 0x45;
	payload[3] = 0x34;
	payload[4] = 0x23;
	payload[5] = 0x12;

	int32_prop_read_helper(payload, 6, MOSQ_ERR_SUCCESS, PROP_SESSION_EXPIRY_INTERVAL, 0x45342312);
}

static void TEST_single_will_delay_interval(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = PROP_WILL_DELAY_INTERVAL;
	payload[2] = 0x45;
	payload[3] = 0x34;
	payload[4] = 0x23;
	payload[5] = 0x12;

	int32_prop_read_helper(payload, 6, MOSQ_ERR_SUCCESS, PROP_WILL_DELAY_INTERVAL, 0x45342312);
}

static void TEST_single_maximum_packet_size(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = PROP_MAXIMUM_PACKET_SIZE;
	payload[2] = 0x45;
	payload[3] = 0x34;
	payload[4] = 0x23;
	payload[5] = 0x12;

	int32_prop_read_helper(payload, 6, MOSQ_ERR_SUCCESS, PROP_MAXIMUM_PACKET_SIZE, 0x45342312);
}

static void TEST_single_server_keep_alive(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = PROP_SERVER_KEEP_ALIVE;
	payload[2] = 0x45;
	payload[3] = 0x34;

	int16_prop_read_helper(payload, 4, MOSQ_ERR_SUCCESS, PROP_SERVER_KEEP_ALIVE, 0x4534);
}

static void TEST_single_receive_maximum(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = PROP_RECEIVE_MAXIMUM;
	payload[2] = 0x68;
	payload[3] = 0x42;

	int16_prop_read_helper(payload, 4, MOSQ_ERR_SUCCESS, PROP_RECEIVE_MAXIMUM, 0x6842);
}

static void TEST_single_topic_alias_maximum(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = PROP_TOPIC_ALIAS_MAXIMUM;
	payload[2] = 0x68;
	payload[3] = 0x42;

	int16_prop_read_helper(payload, 4, MOSQ_ERR_SUCCESS, PROP_TOPIC_ALIAS_MAXIMUM, 0x6842);
}

static void TEST_single_topic_alias(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = PROP_TOPIC_ALIAS;
	payload[2] = 0x68;
	payload[3] = 0x42;

	int16_prop_read_helper(payload, 4, MOSQ_ERR_SUCCESS, PROP_TOPIC_ALIAS, 0x6842);
}

static void TEST_single_content_type(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = PROP_CONTENT_TYPE;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(payload, 9, MOSQ_ERR_SUCCESS, PROP_CONTENT_TYPE, "hello");
}

static void TEST_single_response_topic(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = PROP_RESPONSE_TOPIC;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(payload, 9, MOSQ_ERR_SUCCESS, PROP_RESPONSE_TOPIC, "hello");
}

static void TEST_single_assigned_client_identifier(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = PROP_ASSIGNED_CLIENT_IDENTIFIER;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(payload, 9, MOSQ_ERR_SUCCESS, PROP_ASSIGNED_CLIENT_IDENTIFIER, "hello");
}

static void TEST_single_authentication_method(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = PROP_AUTHENTICATION_METHOD;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(payload, 9, MOSQ_ERR_SUCCESS, PROP_AUTHENTICATION_METHOD, "hello");
}

static void TEST_single_response_information(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = PROP_RESPONSE_INFO;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(payload, 9, MOSQ_ERR_SUCCESS, PROP_RESPONSE_INFO, "hello");
}

static void TEST_single_server_reference(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = PROP_SERVER_REFERENCE;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(payload, 9, MOSQ_ERR_SUCCESS, PROP_SERVER_REFERENCE, "hello");
}

static void TEST_single_reason_string(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = PROP_REASON_STRING;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(payload, 9, MOSQ_ERR_SUCCESS, PROP_REASON_STRING, "hello");
}

static void TEST_single_correlation_data(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = PROP_CORRELATION_DATA;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 1;
	payload[5] = 'e';
	payload[6] = 0;
	payload[7] = 'l';
	payload[8] = 9;

	binary_prop_read_helper(payload, 9, MOSQ_ERR_SUCCESS, PROP_CORRELATION_DATA, &payload[4], 5);
}

static void TEST_single_authentication_data(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = PROP_AUTHENTICATION_DATA;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 1;
	payload[5] = 'e';
	payload[6] = 0;
	payload[7] = 'l';
	payload[8] = 9;

	binary_prop_read_helper(payload, 9, MOSQ_ERR_SUCCESS, PROP_AUTHENTICATION_DATA, &payload[4], 5);
}

/* ========================================================================
 * DUPLICATE PROPERTIES
 * ======================================================================== */

static void TEST_duplicate_payload_format_indicator(void)
{
	duplicate_byte_helper(PROP_PAYLOAD_FORMAT_INDICATOR);
}

static void TEST_duplicate_request_problem_information(void)
{
	duplicate_byte_helper(PROP_REQUEST_PROBLEM_INFO);
}

static void TEST_duplicate_request_response_information(void)
{
	duplicate_byte_helper(PROP_REQUEST_RESPONSE_INFO);
}

static void TEST_duplicate_maximum_qos(void)
{
	duplicate_byte_helper(PROP_MAXIMUM_QOS);
}

static void TEST_duplicate_retain_available(void)
{
	duplicate_byte_helper(PROP_RETAIN_AVAILABLE);
}

static void TEST_duplicate_wildcard_subscription_available(void)
{
	duplicate_byte_helper(PROP_WILDCARD_SUB_AVAILABLE);
}

static void TEST_duplicate_subscription_identifier_available(void)
{
	duplicate_byte_helper(PROP_SUBSCRIPTION_ID_AVAILABLE);
}

static void TEST_duplicate_shared_subscription_available(void)
{
	duplicate_byte_helper(PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_duplicate_message_expiry_interval(void)
{
	duplicate_int32_helper(PROP_MESSAGE_EXPIRY_INTERVAL);
}

static void TEST_duplicate_session_expiry_interval(void)
{
	duplicate_int32_helper(PROP_SESSION_EXPIRY_INTERVAL);
}

static void TEST_duplicate_will_delay_interval(void)
{
	duplicate_int32_helper(PROP_WILL_DELAY_INTERVAL);
}

static void TEST_duplicate_maximum_packet_size(void)
{
	duplicate_int32_helper(PROP_MAXIMUM_PACKET_SIZE);
}

static void TEST_duplicate_server_keep_alive(void)
{
	duplicate_int16_helper(PROP_SERVER_KEEP_ALIVE);
}

static void TEST_duplicate_receive_maximum(void)
{
	duplicate_int16_helper(PROP_RECEIVE_MAXIMUM);
}

static void TEST_duplicate_topic_alias_maximum(void)
{
	duplicate_int16_helper(PROP_TOPIC_ALIAS_MAXIMUM);
}

static void TEST_duplicate_topic_alias(void)
{
	duplicate_int16_helper(PROP_TOPIC_ALIAS);
}

static void TEST_duplicate_content_type(void)
{
	duplicate_string_helper(PROP_CONTENT_TYPE);
}

static void TEST_duplicate_response_topic(void)
{
	duplicate_string_helper(PROP_RESPONSE_TOPIC);
}

static void TEST_duplicate_assigned_client_identifier(void)
{
	duplicate_string_helper(PROP_ASSIGNED_CLIENT_IDENTIFIER);
}

static void TEST_duplicate_authentication_method(void)
{
	duplicate_string_helper(PROP_AUTHENTICATION_METHOD);
}

static void TEST_duplicate_response_information(void)
{
	duplicate_string_helper(PROP_RESPONSE_INFO);
}

static void TEST_duplicate_server_reference(void)
{
	duplicate_string_helper(PROP_SERVER_REFERENCE);
}

static void TEST_duplicate_reason_string(void)
{
	duplicate_string_helper(PROP_REASON_STRING);
}

static void TEST_duplicate_correlation_data(void)
{
	duplicate_binary_helper(PROP_CORRELATION_DATA);
}

static void TEST_duplicate_authentication_data(void)
{
	duplicate_binary_helper(PROP_AUTHENTICATION_DATA);
}

/* ========================================================================
 * BAD PROPERTY VALUES
 * ======================================================================== */

static void TEST_bad_request_problem_information(void)
{
	bad_byte_helper(PROP_REQUEST_PROBLEM_INFO);
}

static void TEST_bad_request_response_information(void)
{
	bad_byte_helper(PROP_REQUEST_RESPONSE_INFO);
}

static void TEST_bad_maximum_qos(void)
{
	bad_byte_helper(PROP_MAXIMUM_QOS);
}

static void TEST_bad_retain_available(void)
{
	bad_byte_helper(PROP_RETAIN_AVAILABLE);
}

static void TEST_bad_wildcard_sub_available(void)
{
	bad_byte_helper(PROP_WILDCARD_SUB_AVAILABLE);
}

static void TEST_bad_subscription_id_available(void)
{
	bad_byte_helper(PROP_SUBSCRIPTION_ID_AVAILABLE);
}

static void TEST_bad_shared_sub_available(void)
{
	bad_byte_helper(PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_bad_maximum_packet_size(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = PROP_MAXIMUM_PACKET_SIZE;
	payload[2] = 0;
	payload[3] = 0;
	payload[4] = 0;
	payload[5] = 0; /* 0 is invalid */

	int32_prop_read_helper(payload, 6, MOSQ_ERR_PROTOCOL, PROP_MAXIMUM_PACKET_SIZE, 0);
}

static void TEST_bad_receive_maximum(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = PROP_RECEIVE_MAXIMUM;
	payload[2] = 0;
	payload[3] = 0; /* 0 is invalid */

	int32_prop_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, PROP_RECEIVE_MAXIMUM, 0);
}

static void TEST_bad_topic_alias(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = PROP_TOPIC_ALIAS;
	payload[2] = 0;
	payload[3] = 0; /* 0 is invalid */

	int32_prop_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, PROP_TOPIC_ALIAS, 0);
}

static void TEST_bad_content_type(void)
{
	bad_string_helper(PROP_CONTENT_TYPE);
}

/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_property_read_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Property read", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Property read test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Truncated packet", TEST_truncated)
			|| !CU_add_test(test_suite, "Invalid property ID", TEST_invalid_property_id)
			|| !CU_add_test(test_suite, "No properties", TEST_no_properties)
			|| !CU_add_test(test_suite, "Single Payload Format Indicator", TEST_single_payload_format_indicator)
			|| !CU_add_test(test_suite, "Single Request Problem Information", TEST_single_request_problem_information)
			|| !CU_add_test(test_suite, "Single Request Response Information", TEST_single_request_response_information)
			|| !CU_add_test(test_suite, "Single Maximum QoS", TEST_single_maximum_qos)
			|| !CU_add_test(test_suite, "Single Retain Available", TEST_single_retain_available)
			|| !CU_add_test(test_suite, "Single Wildcard Subscription Available", TEST_single_wildcard_subscription_available)
			|| !CU_add_test(test_suite, "Single Subscription Identifier Available", TEST_single_subscription_identifier_available)
			|| !CU_add_test(test_suite, "Single Shared Subscription Available", TEST_single_shared_subscription_available)
			|| !CU_add_test(test_suite, "Single Message Expiry Interval", TEST_single_message_expiry_interval)
			|| !CU_add_test(test_suite, "Single Session Expiry Interval", TEST_single_session_expiry_interval)
			|| !CU_add_test(test_suite, "Single Will Delay Interval", TEST_single_will_delay_interval)
			|| !CU_add_test(test_suite, "Single Maximum Packet Size", TEST_single_maximum_packet_size)
			|| !CU_add_test(test_suite, "Single Server Keep Alive", TEST_single_server_keep_alive)
			|| !CU_add_test(test_suite, "Single Receive Maximum", TEST_single_receive_maximum)
			|| !CU_add_test(test_suite, "Single Topic Alias Maximum", TEST_single_topic_alias_maximum)
			|| !CU_add_test(test_suite, "Single Topic Alias", TEST_single_topic_alias)
			|| !CU_add_test(test_suite, "Single Content Type", TEST_single_content_type)
			|| !CU_add_test(test_suite, "Single Response Topic", TEST_single_response_topic)
			|| !CU_add_test(test_suite, "Single Assigned Client Identifier", TEST_single_assigned_client_identifier)
			|| !CU_add_test(test_suite, "Single Authentication Method", TEST_single_authentication_method)
			|| !CU_add_test(test_suite, "Single Response Information", TEST_single_response_information)
			|| !CU_add_test(test_suite, "Single Server Reference", TEST_single_server_reference)
			|| !CU_add_test(test_suite, "Single Reason String", TEST_single_reason_string)
			|| !CU_add_test(test_suite, "Single Correlation Data", TEST_single_correlation_data)
			|| !CU_add_test(test_suite, "Single Authentication Data", TEST_single_authentication_data)
			|| !CU_add_test(test_suite, "Duplicate Payload Format Indicator", TEST_duplicate_payload_format_indicator)
			|| !CU_add_test(test_suite, "Duplicate Request Problem Information", TEST_duplicate_request_problem_information)
			|| !CU_add_test(test_suite, "Duplicate Request Response Information", TEST_duplicate_request_response_information)
			|| !CU_add_test(test_suite, "Duplicate Maximum QoS", TEST_duplicate_maximum_qos)
			|| !CU_add_test(test_suite, "Duplicate Retain Available", TEST_duplicate_retain_available)
			|| !CU_add_test(test_suite, "Duplicate Wildcard Subscription Available", TEST_duplicate_wildcard_subscription_available)
			|| !CU_add_test(test_suite, "Duplicate Subscription Identifier Available", TEST_duplicate_subscription_identifier_available)
			|| !CU_add_test(test_suite, "Duplicate Shared Subscription Available", TEST_duplicate_shared_subscription_available)
			|| !CU_add_test(test_suite, "Duplicate Message Expiry Interval", TEST_duplicate_message_expiry_interval)
			|| !CU_add_test(test_suite, "Duplicate Session Expiry Interval", TEST_duplicate_session_expiry_interval)
			|| !CU_add_test(test_suite, "Duplicate Will Delay Interval", TEST_duplicate_will_delay_interval)
			|| !CU_add_test(test_suite, "Duplicate Maximum Packet Size", TEST_duplicate_maximum_packet_size)
			|| !CU_add_test(test_suite, "Duplicate Server Keep Alive", TEST_duplicate_server_keep_alive)
			|| !CU_add_test(test_suite, "Duplicate Receive Maximum", TEST_duplicate_receive_maximum)
			|| !CU_add_test(test_suite, "Duplicate Topic Alias Maximum", TEST_duplicate_topic_alias_maximum)
			|| !CU_add_test(test_suite, "Duplicate Topic Alias", TEST_duplicate_topic_alias)
			|| !CU_add_test(test_suite, "Duplicate Content Type", TEST_duplicate_content_type)
			|| !CU_add_test(test_suite, "Duplicate Response Topic", TEST_duplicate_response_topic)
			|| !CU_add_test(test_suite, "Duplicate Assigned Client ID", TEST_duplicate_assigned_client_identifier)
			|| !CU_add_test(test_suite, "Duplicate Authentication Method", TEST_duplicate_authentication_method)
			|| !CU_add_test(test_suite, "Duplicate Response Information", TEST_duplicate_response_information)
			|| !CU_add_test(test_suite, "Duplicate Server Reference", TEST_duplicate_server_reference)
			|| !CU_add_test(test_suite, "Duplicate Reason String", TEST_duplicate_reason_string)
			|| !CU_add_test(test_suite, "Duplicate Correlation Data", TEST_duplicate_correlation_data)
			|| !CU_add_test(test_suite, "Duplicate Authentication Data", TEST_duplicate_authentication_data)
			|| !CU_add_test(test_suite, "Bad Request Problem Information", TEST_bad_request_problem_information)
			|| !CU_add_test(test_suite, "Bad Request Response Information", TEST_bad_request_response_information)
			|| !CU_add_test(test_suite, "Bad Maximum QoS", TEST_bad_maximum_qos)
			|| !CU_add_test(test_suite, "Bad Retain Available", TEST_bad_retain_available)
			|| !CU_add_test(test_suite, "Bad Wildcard Subscription Available", TEST_bad_wildcard_sub_available)
			|| !CU_add_test(test_suite, "Bad Subscription Identifier Available", TEST_bad_subscription_id_available)
			|| !CU_add_test(test_suite, "Bad Shared Subscription Available", TEST_bad_shared_sub_available)
			|| !CU_add_test(test_suite, "Bad Maximum Packet Size", TEST_bad_maximum_packet_size)
			|| !CU_add_test(test_suite, "Bad Receive Maximum", TEST_bad_receive_maximum)
			|| !CU_add_test(test_suite, "Bad Topic Alias", TEST_bad_topic_alias)
			|| !CU_add_test(test_suite, "Bad Content Type", TEST_bad_content_type)
			){

		printf("Error adding Property read CUnit tests.\n");
		return 1;
	}

	return 0;
}
