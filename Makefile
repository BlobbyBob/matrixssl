#
# Top-level Makefile for building various versions of MatrixSSL.
#
# Copyright (c) 2016 INSIDE Secure Corporation. All Rights Reserved.
#
# @version $Format:%h%d$

# A list of the most important build targets provided by this Makefile:
# Make command            Description
# make all                Default target: Build all software using current
#                         MatrixSSL configuration
# make libs               Build MatrixSSL libraries using current
#                         MatrixSSL configuration
# make tests              Build MatrixSSL test programs using current
#                         MatrixSSL configuration
# make apps               Build MatrixSSL example programs using current
#                         MatrixSSL configuration
# make check-config       Apply default configuration if not present.
# make *-config           (Specify *) select one of prepackaged configurations
#                         from configs directory.
#
# Additional targets for MatrixSSL Open Source and Commercial Editions
#
# make all-tls            Build MatrixSSL using options suitable for most
#                         TLS use cases and the MatrixSSL stock crypto.
# make all-noecc          Build MatrixSSL using options that disable ECC,
#                         using the MatrixSSL stock crypto.
# make all-rsaonly        Build MatrixSSL using options that disable ECC and DH,
#                         using the MatrixSSL stock crypto.
#
# Additional targets for MatrixSSL FIPS Edition
#
# make all-fips           Compile MatrixSSL FIPS Edition with default
#                         configuration.
# make all-cl-nonfips     Compile MatrixSSL FIPS Edition using CL library in
#                         non-FIPS Mode of operation.
# make all-combined       Compile MatrixSSL FIPS Edition allowing run-time
#                         selection of FIPS or non-FIPS mode.
# make all-combined-default-nonfips  The same than make all combined, but
#                         non-FIPS mode is the default.
#
#

default: all
util: all-utils

CONFIG_EXTRA_DEPENDENCIES=

# Use default config if no config is being used.
check-config: $(CONFIG_EXTRA_DEPENDENCIES)
	@if [ ! -e core/coreConfig.h ];then \
		cp configs/default/coreConfig.h core/coreConfig.h;\
		echo NOTE: Using default configuration from configs/default/coreConfig.h.;\
	fi
	@if [ ! -e crypto/cryptoConfig.h ];then \
		cp configs/default/cryptoConfig.h crypto/cryptoConfig.h;\
		echo NOTE: Using default configuration from configs/default/cryptoConfig.h.;\
	fi
	@if [ ! -e matrixssl/matrixsslConfig.h ];then \
		cp configs/default/matrixsslConfig.h matrixssl/matrixsslConfig.h;\
		echo NOTE: Using default configuration from configs/default/matrixsslConfig.h.;\
	fi

clean-config:
	rm -f core/coreConfig.h crypto/cryptoConfig.h matrixssl/matrixsslConfig.h

# Apply any of pre-existing configurations from configs directory
%-config: configs/% $(CONFIG_EXTRA_DEPENDENCIES)
	@echo Using $</*Config.h.
	cp $</coreConfig.h core/coreConfig.h
	cp $</cryptoConfig.h crypto/cryptoConfig.h
	cp $</matrixsslConfig.h matrixssl/matrixsslConfig.h

# Set non-fips configuration (standard configuration for MatrixSSL commercial)
# and build all libraries
all-nonfips:
	make nonfips-config
	$(MAKE) --directory=core
	$(MAKE) --directory=crypto
	$(MAKE) --directory=matrixssl
	if [ -e crypto/cms ]; then $(MAKE) --directory=crypto/cms;fi
	if [ -e matrixssh ]; then if make --directory=crypto parse-config | grep -q '#define USE_AES_CTR' && make --directory=crypto parse-config | grep -q '#define USE_DH'; then $(MAKE) --directory=matrixssh;fi;fi

# Set non-fips configuration and build tests
test-nonfips:
	make nonfips-config
	$(MAKE) --directory=crypto/test
	$(MAKE) --directory=matrixssl/test
	if [ -e crypto/cms ]; then $(MAKE) --directory=crypto/cms/test;fi

# Find out if MatrixSSL FIPS Edition is present
ifeq (,$(wildcard configs/fips*/matrixsslConfig.h))
CONFIG_FIPS_AVAILABLE=0
CONFIG_NONFIPS_PREFIX=
else
CONFIG_FIPS_AVAILABLE=1
CONFIG_NONFIPS_PREFIX=nonfips-
endif

# These are some examples of configuration selection targets for MatrixSSL.
# You can instead apply any of any of configurations in configs directory with
# make CONFIGNAME-config and then proceed with make all / make libs etc.

# Omit ECC (Only support RSA and DH, using MatrixSSL stock crypto)
all-noecc:
	make $(CONFIG_NONFIPS_PREFIX)noecc-config
	make all

# Only support RSA (MatrixSSL stock crypto)
all-rsaonly:
	make $(CONFIG_NONFIPS_PREFIX)rsaonly-config
	make all

# A commonly recommended set of options for MatrixSSL using stock crypto,
# for the most common TLS use cases. This configuration disables
# DH and 3DES options in rare use (which is typically considered good for
# security).
all-tls:
	make $(CONFIG_NONFIPS_PREFIX)tls-config
	make all

# These configurations are specific to FIPS version of MatrixSSL.
# The targets are only available on MatrixSSL FIPS Edition.

# Set fips only configuration and build all libraries
all-fips:
	make fipsonly-config
	make all

# Set nonfips only configuration and build all libraries
all-cl-nonfips:
	make cl-nonfips-config
	make all

# Set combined fips/nonfips configuration and build all libraries
all-combined:
	make combined-config
	make all

# Set combined-default-nonfips configuration and build all libraries
all-combined-default-nonfips:
	make combined-default-nonfips-config
	make all

# Set combined fips/nonfips configuration with maximum algorithm
# support, and build all libraries
all-combined-fulltest:
	make combined-fulltest-config
	make all

ifneq (,$(findstring clean,$(MAKECMDGOALS)))
  SUBARGS:=clean
endif
# Set fips only configuration and build tests
test-fips:
	make fipsonly-config
	make test


# Set combined fips/nonfips only configuration and build tests
test-combined:
	make combined-config
	make test

# Set combined nonfips/fips configuration and build tests
test-combined-default-nonfips:
	make combined-default-nonfips-config
	make test

.PHONY: all libs tests apps clean

# Add dependencies
all: libs tests apps
all: check-config
libs: check-config
tests: check-config libs
apps: check-config libs
all-utils: check-config

# Alias
test: tests

libs:
	$(MAKE) --directory=core
	if make --directory=crypto parse-config | grep -q -e '#define USE_FIPS_CRYPTO' -e '#define USE_CL_CRYPTO'; then $(MAKE) --directory=crypto-cl; else $(MAKE) --directory=crypto; fi
	if make --directory=crypto parse-config | grep -q '#define USE_CMS'; then $(MAKE) --directory=crypto/cms;fi
	$(MAKE) --directory=matrixssl
	if [ -e matrixssh ]; then if make --directory=crypto parse-config | grep -q '#define USE_AES_CTR' && make --directory=crypto parse-config | grep -q '#define USE_DH'; then $(MAKE) --directory=matrixssh;fi;fi

tests:
	$(MAKE) --directory=crypto/test
	$(MAKE) --directory=matrixssl/test
	if make --directory=crypto parse-config | grep -q '#define USE_CMS'; then $(MAKE) --directory=crypto/cms/test;fi

# Note apps is also a direct subdirectory
#ifdef MATRIXSSL_COMMERCIAL

APPS_ADDITIONAL = apps_crypto

.PHONY: apps_crypto

apps_crypto:
	if [ -e apps/crypto ];then $(MAKE) --directory=apps/crypto;fi

#endif /* MATRIXSSL_COMMERCIAL */

apps: $(APPS_ADDITIONAL)
	$(MAKE) --directory=apps/ssl
	$(MAKE) --directory=apps/dtls

clean:
	$(MAKE) clean --directory=core
	$(MAKE) clean --directory=crypto
	$(MAKE) clean --directory=crypto/test
	$(MAKE) clean --directory=matrixssl
	$(MAKE) clean --directory=crypto/test
	$(MAKE) clean --directory=matrixssl/test
	if [ -e crypto-cl ]; then $(MAKE) clean --directory=crypto-cl;fi
	if [ -e crypto/cms ]; then $(MAKE) clean --directory=crypto/cms;fi
	$(MAKE) clean --directory=apps/ssl
	$(MAKE) clean --directory=apps/dtls
	if [ -e apps/crypto ];then $(MAKE) clean --directory=apps/crypto;fi
	if [ -e crypto/cms/test ]; then $(MAKE) clean --directory=crypto/cms/test;fi
	if [ -e matrixssh ]; then $(MAKE) clean --directory=matrixssh; fi

clobber: clean clean-config

