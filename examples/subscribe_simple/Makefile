include ../../config.mk

.PHONY: all

all : sub_single sub_multiple

sub_single : single.o
	${CROSS_COMPILE}${CC} $^ -o $@ ../../lib/libmosquitto.so.${SOVERSION}

sub_multiple : multiple.o
	${CROSS_COMPILE}${CC} $^ -o $@ ../../lib/libmosquitto.so.${SOVERSION}

single.o : single.c ../../lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I../../lib ${CFLAGS}

multiple.o : multiple.c ../../lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I../../lib ${CFLAGS}

../../lib/libmosquitto.so.${SOVERSION} :
	$(MAKE) -C ../../lib

clean : 
	-rm -f *.o sub_single sub_multiple
