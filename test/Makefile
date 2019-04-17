include ../config.mk

.PHONY: all test ptest clean

all :

test : utest
	$(MAKE) -C broker test
	$(MAKE) -C lib test

ptest : utest
	$(MAKE) -C broker ptest
	$(MAKE) -C lib ptest

utest :
	$(MAKE) -C unit test

reallyclean : clean
clean : 
	$(MAKE) -C lib clean
	$(MAKE) -C broker clean
	$(MAKE) -C unit clean
