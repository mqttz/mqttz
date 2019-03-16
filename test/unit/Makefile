include ../../config.mk

.PHONY: all test test-broker test-lib clean coverage

CFLAGS=-I../.. -I../../lib -I../../src -coverage -Wall -ggdb
TEST_LDFLAGS=-lcunit -coverage

TEST_OBJS = test.o \
			datatype_read.o \
			datatype_write.o \
			property_add.o \
			property_read.o \
			property_user_read.o \
			property_write.o \
			stubs.o \
			util_topic_test.o \
			utf8.o

LIB_OBJS = memory_mosq.o \
		   packet_datatypes.o \
		   property_mosq.o \
		   util_topic.o \
		   utf8_mosq.o

PERSIST_READ_TEST_OBJS = \
		persist_read_test.o \
		persist_read_stubs.o

PERSIST_READ_OBJS = \
		memory_mosq.o \
		persist_read.o \
		persist_read_v234.o \
		util_mosq.o

all : test

mosq_test : ${TEST_OBJS} ${LIB_OBJS}
	$(CROSS_COMPILE)$(CC) -o $@ $^ ${TEST_LDFLAGS}

persist_read_test : ${PERSIST_READ_TEST_OBJS} ${PERSIST_READ_OBJS}
	$(CROSS_COMPILE)$(CC) -o $@ $^ ${TEST_LDFLAGS}

memory_mosq.o : ../../lib/memory_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

packet_datatypes.o : ../../lib/packet_datatypes.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

persist_read.o : ../../src/persist_read.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

persist_read_v234.o : ../../src/persist_read_v234.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

property_mosq.o : ../../lib/property_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

util_mosq.o : ../../lib/util_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

util_topic.o : ../../lib/util_topic.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

utf8_mosq.o : ../../lib/utf8_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

test-lib : mosq_test
	./mosq_test

test-broker : persist_read_test
	./persist_read_test

test : test-broker test-lib

clean : 
	-rm -rf mosq_test persist_read_test
	-rm -rf *.o *.gcda *.gcno coverage.info out/

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out
