#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

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
			|| !CU_add_test(test_suite, "Byte write (empty packet)", TEST_byte_write)
			){

		printf("Error adding Datatype write CUnit tests.\n");
		return 1;
	}

	return 0;
}
