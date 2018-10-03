include ../../config.mk

.PHONY: all test clean coverage

CFLAGS=-I../.. -I../../lib -coverage
TEST_LDFLAGS=-lcunit -coverage

all : test

packet_datatypes.o : ../../lib/packet_datatypes.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

memory_mosq.o : ../../lib/memory_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

mosq_test : test.o datatypes.o memory_mosq.o packet_datatypes.o
	$(CROSS_COMPILE)$(CC) -o $@ $^ ${TEST_LDFLAGS}

test : mosq_test
	./mosq_test

clean : 
	-rm -f test *.o

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out
