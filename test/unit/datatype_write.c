#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include <arpa/inet.h>

#include "packet_mosq.h"

/* ========================================================================
 * BYTE TESTS
 * ======================================================================== */

/* This tests writing a Byte to an incoming packet.  */
static void TEST_byte_write(void)
{
	uint8_t payload[260];
	struct mosquitto__packet packet;
	int i;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	packet.packet_length = 256;

	for(i=0; i<256; i++){
		packet__write_byte(&packet, 255-i);
	}

	CU_ASSERT_EQUAL(packet.pos, 256);
	for(i=0; i<256; i++){
		CU_ASSERT_EQUAL(payload[i], 255-i);
	}
}


/* ========================================================================
 * TWO BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests writing a Two Byte Integer to an incoming packet.  */
static void TEST_uint16_write(void)
{
	uint8_t payload[650];
	uint16_t *payload16;
	struct mosquitto__packet packet;
	int i;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	packet.packet_length = 650;

	for(i=0; i<325; i++){
		packet__write_uint16(&packet, 100*i);
	}

	CU_ASSERT_EQUAL(packet.pos, 650);
	payload16 = (uint16_t *)payload;
	for(i=0; i<325; i++){
		CU_ASSERT_EQUAL(payload16[i], htons(100*i));
	}
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_datatype_write_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Datatype write", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Byte write)", TEST_byte_write)
			|| !CU_add_test(test_suite, "Two Byte Integer write", TEST_uint16_write)
			){

		printf("Error adding Datatype write CUnit tests.\n");
		return 1;
	}

	return 0;
}
