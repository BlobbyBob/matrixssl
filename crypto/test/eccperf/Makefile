#
#   Makefile for crypto testing
#
#   Copyright (c) 2013-2016 Rambus Inc. All Rights Reserved.
#

# SRC and MATRIXSSL_ROOT must be defined before including common.mk
TEST_SRC:=eccperf.c
SRC:=$(TEST_SRC)
MATRIXSSL_ROOT:=../../..
include $(MATRIXSSL_ROOT)/common.mk

# Generated files
TEST_EXE:=eccperf

# Linked files
STATIC:=\
	$(MATRIXSSL_ROOT)/crypto/libcrypt_s.a \
	$(MATRIXSSL_ROOT)/core/libcore_s.a

#ifdef USE_ROT_CRYPTO
STATIC+=$(LIBDRIVER_VAL_UP_PATH)
#endif

all: compile

compile: $(OBJS) $(TEST_EXE)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

$(TEST_EXE): $(TEST_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TEST_EXE)

