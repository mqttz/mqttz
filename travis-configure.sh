#!/bin/bash

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
	export CFLAGS="-I/usr/local/opt/openssl/include $CFLAGS"
	export LDFLAGS="-L/usr/local/opt/openssl/lib $LDFLAGS"
	cmake .
fi
