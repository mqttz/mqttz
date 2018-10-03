#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "packet_mosq.h"

static void byte_read_helper(
		uint8_t *payload,
		int remaining_length,
		int rc_expected,
		uint8_t value_expected)
{
	struct mosquitto__packet packet;
	uint8_t value = 0;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_byte(&packet, &value);
	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(value, value_expected);
}


static void uint16_read_helper(
		uint8_t *payload,
		int remaining_length,
		int rc_expected,
		uint16_t value_expected)
{
	struct mosquitto__packet packet;
	uint16_t value = 0;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_uint16(&packet, &value);
	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(value, value_expected);
}


static void uint32_read_helper(
		uint8_t *payload,
		int remaining_length,
		int rc_expected,
		uint32_t value_expected)
{
	struct mosquitto__packet packet;
	uint32_t value = 0;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_uint32(&packet, &value);
	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(value, value_expected);
}


static void varint_read_helper(
		uint8_t *payload,
		int remaining_length,
		int rc_expected,
		int32_t value_expected,
		int8_t bytes_expected)
{
	struct mosquitto__packet packet;
	int32_t value = -1;
	int8_t bytes = -1;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_varint(&packet, &value, &bytes);
	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(value, value_expected);
	CU_ASSERT_EQUAL(bytes, bytes_expected);
}


/* ========================================================================
 * BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests reading a Byte from an incoming packet.
 *
 * It tests:
 *  * Empty packets
 */
static void TEST_byte_read_empty(void)
{
	/* Empty packet */
	byte_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Byte from an incoming packet.
 *
 * It tests:
 *  * Success at boundaries
 */
static void TEST_byte_read_success(void)
{
	struct mosquitto__packet packet;
	uint8_t payload[20];
	int rc;

	/* 0 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	byte_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 0x00);

	/* Middle */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x1F;
	byte_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 0x1F);

	/* 65,535 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	byte_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 0xFF);

}


/* ========================================================================
 * TWO BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests reading a Two Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Empty packets
 */
static void TEST_uint16_read_empty(void)
{
	struct mosquitto__packet packet;
	int rc;

	/* Empty packet */
	uint16_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Two Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Truncated packets
 */
static void TEST_uint16_read_truncated(void)
{
	struct mosquitto__packet packet;
	uint8_t payload[20];
	int rc;

	/* 1 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	uint16_read_helper(payload, 1, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Two Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Success at boundaries
 *  * Endianness
 */
static void TEST_uint16_read_success(void)
{
	struct mosquitto__packet packet;
	uint8_t payload[20];
	int rc;

	/* 0 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x00;
	uint16_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 0x0000);

	/* Endian check */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	payload[1] = 0xF3;
	uint16_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 0x38F3);

	/* 65,535 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	uint16_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 0xFFFF);

}


/* ========================================================================
 * FOUR BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests reading a Four Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Empty packets
 */
static void TEST_uint32_read_empty(void)
{
	struct mosquitto__packet packet;
	int rc;

	/* Empty packet */
	uint32_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Four Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Truncated packets
 */
static void TEST_uint32_read_truncated(void)
{
	struct mosquitto__packet packet;
	uint8_t payload[20];
	int rc;

	/* 1 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	uint32_read_helper(payload, 1, MOSQ_ERR_PROTOCOL, 0);

	/* 2 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	payload[1] = 0x38;
	uint32_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, 0);

	/* 3 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	payload[1] = 0x38;
	payload[2] = 0x38;
	uint32_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Four Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Success at boundaries
 *  * Endianness
 */
static void TEST_uint32_read_success(void)
{
	struct mosquitto__packet packet;
	uint8_t payload[20];
	int rc;

	/* 0 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x00;
	payload[2] = 0x00;
	payload[3] = 0x00;
	uint32_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 0x00000000);

	/* Endian check */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x12;
	payload[1] = 0x34;
	payload[2] = 0x56;
	payload[3] = 0x78;
	uint32_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 0x12345678);

	/* Biggest value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0xFF;
	payload[3] = 0xFF;
	uint32_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 0xFFFFFFFF);

}


/* ========================================================================
 * VARIABLE BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Empty packet
 */
static void TEST_varint_read_empty(void)
{
	struct mosquitto__packet packet;
	int rc;

	/* Empty packet */
	varint_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, -1, -1);
}


/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Truncated packets (varint encoding is longer than data)
 */
static void TEST_varint_read_truncated(void)
{
	struct mosquitto__packet packet;
	uint8_t payload[20];
	int rc;

	/* Varint bigger than packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	varint_read_helper(payload, 1, MOSQ_ERR_PROTOCOL, -1, -1);

	/* Varint bigger than packet */
	memset(payload, 1, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	varint_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, -1, -1);

	/* Varint bigger than packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x80;
	varint_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, -1, -1);

	/* Varint bigger than packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x80;
	payload[3] = 0x80;
	varint_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, -1, -1);
}


/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Correct values on boundaries of 1, 2, 3, 4 byte encodings
 */
static void TEST_varint_read_boundaries(void)
{
	struct mosquitto__packet packet;
	uint8_t payload[20];
	int rc;

	/* Value = 0 */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	varint_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 0, 1);

	/* Value = 127 (just beneath the crossover to two bytes */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x7F;
	varint_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 127, 1);

	/* Value = 128 (just after the crossover to two bytes */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0x80;
	payload[1] = 0x01;
	varint_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 128, 2);

	/* Value = 16383 (just before the crossover to three bytes */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0xFF;
	payload[1] = 0x7F;
	varint_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 16383, 2);

	/* Value = 16384 (just after the crossover to three bytes */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x01;
	varint_read_helper(payload, 3, MOSQ_ERR_SUCCESS, 16384, 3);

	/* Value = 2,097,151 (just before the crossover to four bytes */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0x7F;
	varint_read_helper(payload, 3, MOSQ_ERR_SUCCESS, 2097151, 3);

	/* Value = 2,097,152 (just after the crossover to four bytes */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x80;
	payload[3] = 0x01;
	varint_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 2097152, 4);

	/* Value = 268,435,455 (highest value allowed) */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0xFF;
	payload[3] = 0x7F;
	varint_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 268435455, 4);
}

/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Too long encoding (5 bytes)
 */
static void TEST_varint_read_5_bytes(void)
{
	struct mosquitto__packet packet;
	uint8_t payload[20];
	int rc;

	/* Value = 268,435,456 (one higher than highest value allowed) */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x80;
	payload[3] = 0x80;
	payload[4] = 0x01;
	varint_read_helper(payload, 5, MOSQ_ERR_PROTOCOL, -1, -1);
}


/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Overlong encodings (e.g. 2 bytes to encode "1")
 */
static void TEST_varint_read_overlong_encoding(void)
{
	struct mosquitto__packet packet;
	uint8_t payload[20];
	int rc;

	/* Overlong encoding of 0 (1 byte value encoded as 2 bytes) */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0x80;
	payload[1] = 0x00;
	varint_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, -1, -1);

	/* Overlong encoding of 127 (1 byte value encoded as 2 bytes) */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0xFF;
	payload[1] = 0x00;
	varint_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, -1, -1);

	/* Overlong encoding of 128 (2 byte value encoded as 3 bytes) */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0x80;
	payload[1] = 0x81;
	payload[2] = 0x00;
	varint_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, -1, -1);

	/* Overlong encoding of 16,383 (2 byte value encoded as 3 bytes) */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0x00;
	varint_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, -1, -1);

	/* Overlong encoding of 16,384 (3 byte value encoded as 4 bytes) */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x81;
	payload[3] = 0x00;
	varint_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, -1, -1);

	/* Overlong encoding of 2,097,151 (3 byte value encoded as 4 bytes) */
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0xFF;
	payload[3] = 0x00;
	varint_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, -1, -1);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_datatype_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("datatypes", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Byte read (empty packet)", TEST_byte_read_empty)
			|| !CU_add_test(test_suite, "Byte read (success values)", TEST_byte_read_success)
			|| !CU_add_test(test_suite, "Two Byte Integer read (empty packet)", TEST_uint16_read_empty)
			|| !CU_add_test(test_suite, "Two Byte Integer read (truncated packet)", TEST_uint16_read_truncated)
			|| !CU_add_test(test_suite, "Two Byte Integer read (success values)", TEST_uint16_read_success)
			|| !CU_add_test(test_suite, "Four Byte Integer read (empty packet)", TEST_uint32_read_empty)
			|| !CU_add_test(test_suite, "Four Byte Integer read (truncated packet)", TEST_uint32_read_truncated)
			|| !CU_add_test(test_suite, "Four Byte Integer read (success values)", TEST_uint32_read_success)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (empty packet)", TEST_varint_read_empty)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (truncated packets)", TEST_varint_read_truncated)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (encoding boundaries)", TEST_varint_read_boundaries)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (five byte encoding)", TEST_varint_read_5_bytes)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (overlong encodings)", TEST_varint_read_overlong_encoding)
			){

		printf("Error adding datatypes CUnit tests.\n");
		return 1;
	}

	return 0;
}
