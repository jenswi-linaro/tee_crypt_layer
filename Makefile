
SHELL :=/bin/bash

.PHONY: all
all:


OBJS	+= tee_hash.o
OBJS	+= tee_openssl.o
OBJS	+= tee_tomcrypt.o
OBJS	+= tee_mac.o
OBJS	+= tee_cipher.o
OBJS	+= tee_test.o
OBJS	+= tee_authenc.o

CFLAGS += -g -O0 -std=gnu99 -Wall -pedantic -Werror
CPPFLAGS += -I. -Iinclude
LDLIBS += -ltomcrypt
LDLIBS += -L/home/jens/src/openssl-1.0.1e
LDLIBS += -static -lcrypto -lz -ldl

tee_test: $(OBJS)

all: tee_test

.PHONY: clean
clean:
	rm -f $(OBJS) tee_test


.PHONY: cscope
cscope:
	rm -f cscope.*
	find $(PWD) -name "*.[chsS]" > cscope.files
	cscope -b -q
