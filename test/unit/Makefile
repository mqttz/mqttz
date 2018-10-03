include ../../config.mk

.PHONY: all test clean coverage

CFLAGS=-I../.. -I../../lib -coverage -Wall
TEST_LDFLAGS=-lcunit -coverage

all : test

mosq_test : test.o datatypes.o utf8.o memory_mosq.o packet_datatypes.o utf8_mosq.o
	$(CROSS_COMPILE)$(CC) -o $@ $^ ${TEST_LDFLAGS}

memory_mosq.o : ../../lib/memory_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

packet_datatypes.o : ../../lib/packet_datatypes.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

utf8_mosq.o : ../../lib/utf8_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

test : mosq_test
	./mosq_test

clean : 
	-rm -f test *.o

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out
