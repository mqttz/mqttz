include ../../config.mk

.PHONY: all test clean coverage

CFLAGS=-I../.. -I../../lib -coverage -Wall -ggdb
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

all : test

mosq_test : ${TEST_OBJS} ${LIB_OBJS}
	$(CROSS_COMPILE)$(CC) -o $@ $^ ${TEST_LDFLAGS}

memory_mosq.o : ../../lib/memory_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

packet_datatypes.o : ../../lib/packet_datatypes.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

property_mosq.o : ../../lib/property_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

util_topic.o : ../../lib/util_topic.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

utf8_mosq.o : ../../lib/utf8_mosq.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $^

test : mosq_test
	./mosq_test

clean : 
	-rm -rf mosq_test *.o *.gcda *.gcno coverage.info out/

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out
