#
#   Makefile for MatrixSSL example apps
#   'make' builds debug (Default).
#   'make gold' builds optimized.
#
#	Copyright (c) 2013-2019 Rambus Inc. All Rights Reserved.
#

MATRIXSSL_ROOT:=../..
SERVER_SRC:=server.c http.c
CLIENT_SRC:=client.c http.c
NET_SRC:=net.c
SRC=$(SERVER_SRC) $(CLIENT_SRC)
SERVER_EXE:=server$(E)
CLIENT_EXE:=client$(E)
NET_EXE:=matrixnet$(E)
EXE=$(SERVER_EXE) $(CLIENT_EXE)

TLSDTLS_SERVER_SRC:=tlsDtlsServer.c http.c
TLSDTLS_SERVER_EXE:=tlsDtlsServer$(E)

SIMPLE_CLIENT_SRC:=simpleClient.c
SIMPLE_CLIENT_EXE:=simpleClient$(E)
SIMPLE_SERVER_SRC:=simpleServer.c
SIMPLE_SERVER_EXE:=simpleServer$(E)

IA_CLIENT_SRC:=interactiveClient.c interactiveCommon.c
IA_CLIENT_EXE:=interactiveClient$(E)
IA_SERVER_SRC:=interactiveServer.c interactiveCommon.c
IA_SERVER_EXE:=interactiveServer$(E)

SRC+=$(SIMPLE_CLIENT_SRC)
EXE+=$(SIMPLE_CLIENT_EXE)
SRC+=$(SIMPLE_SERVER_SRC)
EXE+=$(SIMPLE_SERVER_EXE)
SRC+=$(IA_CLIENT_SRC)
EXE+=$(IA_CLIENT_EXE)
SRC+=$(IA_SERVER_SRC)
EXE+=$(IA_SERVER_EXE)
SRC+=$(TLSDTLS_SERVER_SRC)
EXE+=$(TLSDTLS_SERVER_EXE)

#The Mac OS X Xcode project has a target name of 'server' or 'client'
ifneq (,$(TARGET_NAME))
 ifneq (,$(findstring server,$(TARGET_NAME)))
  CLIENT_EXE:=
  CLIENT_SRC:=
 else
  SERVER_EXE:=
  SERVER_SRC:=
 endif
endif

# Optional extensions to CFLAGS/LDFLAGS
CFLAGS+=$(CFLAGS_INTERNAL)
LDFLAGS+=$(LDFLAGS_INTERNAL)

# Extra dependencies
MATRIXSSL_CONFIG:=$(shell make parse-config --directory $(MATRIXSSL_ROOT)/matrixssl)

include $(MATRIXSSL_ROOT)/common.mk

# Linked files
STATIC:=\
	$(MATRIXSSL_ROOT)/matrixssl/libssl_s.a \
	$(MATRIXSSL_ROOT)/crypto/libcrypt_s.a \
	$(MATRIXSSL_ROOT)/core/libcore_s.a \
	$(STATIC_INTERNAL)

#ifdef USE_ROT_CRYPTO
STATIC+=$(LIBDRIVER_VAL_UP_PATH)
#endif

STATIC_CLIENT:=\
	$(MATRIXSSL_ROOT)/apps/common/client_common_s.a

# Allow selecting the client auth identity (ID_RSA, ID_ECDH_ECDSA,
# etc.) via an environment variable.
CIPHER_OPTION?=ID_RSA
ifneq '$(CIPHER_OPTION)' ''
  CFLAGS+=-D$(CIPHER_OPTION)
endif

compile: $(OBJS) $(EXE)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

$(SERVER_EXE): $(SERVER_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

$(CLIENT_EXE): $(CLIENT_SRC:.c=.o) $(STATIC) $(STATIC_CLIENT)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

$(SIMPLE_CLIENT_EXE): $(SIMPLE_CLIENT_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

$(IA_CLIENT_EXE): $(IA_CLIENT_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

$(SIMPLE_SERVER_EXE): $(SIMPLE_SERVER_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

$(IA_SERVER_EXE): $(IA_SERVER_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

$(NET_EXE): $(NET_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

$(TLSDTLS_SERVER_EXE): $(TLSDTLS_SERVER_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

clean:
	rm -f $(EXE) $(OBJS) TLS_*.tmp SSL_*.tmp

