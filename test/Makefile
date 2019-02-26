include ../config.mk

.PHONY: all test ptest clean

all :

test :
	$(MAKE) -C broker test
	$(MAKE) -C lib test
	$(MAKE) -C unit test

ptest :
	$(MAKE) -C broker ptest
	$(MAKE) -C lib ptest

clean : 
	$(MAKE) -C lib clean
	$(MAKE) -C broker clean
