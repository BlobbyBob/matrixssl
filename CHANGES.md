MatrixSSL Release Notes
========

#Changes in 3.8.3
--------
> **Version 3.8.3**
> April 2016
> *&copy; INSIDE Secure - 2016 - All Rights Reserved*

1. FEATURES AND IMPROVEMENTS
  - Simplified Configuration Options
  - DTLS Combined Package
  - CHACHA20_POLY1305 Cipher Suites
  - Libsodium Crypto Provider
  - Extended Master Secret
  - Online Certificate Status Protocol
  - TLS Fallback SCSV
  - Trusted CA Indication Extension
  - Removed gmt_unix_time from client and server random
  - Removed support for SSLv2 CLIENT_HELLO messages
  - Ephemeral ECC Key Caching
2. BUG FIXES
  - Support for parsing large certificate blobs
  - X.509 certificate parse fix for issuerUniqueID and subjectUniqueID
  - Diffie-Hellman public key exchange bug
  - SHA512 based Server Key Exchange signatures
  - Allow independent hashSigAlg identifiers in Certificate Request message
  - Improvements to DTLS Cookie handling
  - Fixed key type verification for chosen cipher suite
  - Validation of RSA Signature Creation
  - Side Channel Vulnerability on RSA Cipher Suites
  - Access Violation on Malicious TLS Record

#1 FEATURES AND IMPROVEMENTS

##Simplified Configuration Options
The configuration files _coreConfig.h_, _cryptoConfig.h_ and _matrixsslConfig.h_ have been simplified, and the default options have been changed to improve security and code size.

- Many of the insecure algorithms or deprecated options that can be
   enabled in _cryptoConfig.h_ and _matrixsslConfig.h_ have been moved
   into _cryptolib.h_ and _matrixssllib.h_, respectively.   
- TLS 1.1 is now the default minimum TLS version compiled in. The new
   `USE_TLS_1_1_AND_ABOVE` setting enables this.
- Rehandshaking on an existing connection is now disabled completely by
   default with the `USE_REHANDSHAKING` configuration option.

##DTLS Combined Package
DTLS is now packaged with MatrixSSL, and can be enabled with the `USE_DTLS` configuration option. TLS and DTLS connections can be made simultaneously with the same application.

##CHACHA20_POLY1305 Cipher Suites
MatrixSSL now has support for ChaCha20-Poly1305 cipher suites compatible with RFC draft https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305.
The supported cipher suites are defined for TLS 1.2 and can be enabled at compile time.

_cryptoConfig.h_
: `USE_CHACHA20_POLY1305`

_matrixsslConfig.h_
: `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
`TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`

MatrixSSL must be linked with the libsodium library to provide implementation of the crypto primitives.

##Libsodium Crypto Provider
MatrixSSL now includes a layer for crypto primitives to the *libsodium* crypto library, in addition to the *OpenSSL libcrypto* and the native (default) MatrixSSL crypto library. *libsodium* provides crypto primitives for ChaCha20 and Poly1305. In addition, enabling the layer will use *libsodium* primitives for SHA256/SHA384/SHA512 based hashes and AES-256-GCM ciphers that provide high performance on *Intel* platforms.

> As of this release, the current version of libsodium is available here:
https://download.libsodium.org/libsodium/releases/libsodium-1.0.8.tar.gz
To build libsodium, follow the instructions here:
https://download.libsodium.org/doc/installation/index.html

To enable in the MatrixSSL make system, enable the following and rebuild:

_common.mk_
: `PS_LIBSODIUM:=1`
`LIBSODIUM_ROOT:=`*(path_to_libsodium_build)*

##Extended Master Secret
The “extended master secret” as specified in [RFC 7627](https://tools.ietf.org/html/rfc7627) is an important security feature for TLS implementations that use session resumption.  The extended master secret feature associates the internal TLS master secret directly to the connection context to prevent man-in-the-middle attacks during session resumption.  One such attack is a synchronizing triple handshake as described in [Triple Handshakes and Cookie Cutters: Breaking and Fixing Authentication over TLS](https://mitls.org/pages/attacks/3SHAKE).

See the _Extended Master Secret_ section in the _MatrixSSL API_ document for details.

##Online Certificate Status Protocol
The Online Certificate Status Protocol (OCSP) is an alternative to the Certificate Revocation List (CRL) mechanism for performing certificate revocation tests on server keys.  TLS integrates with OCSP in a mechanism known as “OCSP stapling”.   This feature allows the client to request that the server provide a time-stamped OCSP response when presenting the X.509 certificate during the TLS handshake.   The primary goal for this scheme is to allow resource constrained clients to perform certificate revocation tests without having to communicate with an OCSP Responder themselves.

See the _OCSP Revocation_ section in the _MatrixSSL API_ document for details.

##TLS Fallback SCSV
The RFC for detecting version rollback attacks has been implemented per [RFC7507](https://tools.ietf.org/html/rfc7507). See the _MatrixSSL Developer’s Guide_ for more information.

##Trusted CA Indication Extension
The Trusted CA Indication extension is specified in [RFC 6066](https://tools.ietf.org/html/rfc6066).  This feature allows TLS clients to send their list of certificate authorities to servers in the `CLIENT_HELLO` message.  
See the Trusted CA Indication section in the _MatrixSSL_API_ document for details.

##Removed gmt_unix_time from client and server random
The TLS RFC specifies that the first 4 bytes of the `CLIENT_HELLO` and `SERVER_HELLO` random values be the current platform time. Current best practices recommend using random data for all 32 bytes. MatrixSSL now uses all random data by default.

##Removed support for SSLv2 CLIENT_HELLO messages
SSLv2 `CLIENT_HELLO` parsing was previously supported to maintain compatibility with very old TLS implementations. Although this does not present a security risk at this time, the code has been removed, and only modern TLS record header parsing is supported.

##Ephemeral ECC Key Caching
Previous versions of MatrixSSL generated new, unique ephemeral keys for each connection using `ECDHE_` cipher suites, as per NIST recommendations. Beginning with this version, ephemeral keys are cached and re-used for connections within a time frame of two hours and a maximum usage of 1000 times. This improves performance of ECDHE suites, and is inline with the configuration current web browsers. This feature can be configured in _matrixsslConfig.h_.

#2 BUG FIXES

##Support for parsing large certificate blobs
Certificate collections larger than 64KB were not being parsed correctly after a change to some data types (32 bit to 16 bit) in the parsing code.  This bug is now fixed and large collections of certificates are now parsing correctly.

##X.509 certificate parse fix for issuerUniqueID and subjectUniqueID
Previous MatrixSSL versions could not parse these rarely encountered members of X.509 certificates.

##Diffie-Hellman public key exchange bug
MatrixSSL clients would not successfully handshake with servers that sent Diffie-Hellman public keys that were not the same byte length as the DH group Prime parameter.  Clients will now successfully handshake with servers that provide shorter length public keys.

##SHA512 based Server Key Exchange signatures
SHA512 was not supported for `SERVER_KEY_EXCHANGE` messages in previous versions.

##Allow independent hashSigAlg identifiers in Certificate Request message
Previous client versions of MatrixSSL would not allow servers to send signature algorithm identifiers that were not already specified by the client in the `CLIENT_HELLO` message.  Now, the client will correctly allow the server to send an independent list of supported algorithms and the client will look for matches from that list.

##Improvements to DTLS Cookie handling
HMAC-SHA1 or HMAC-SHA256 are now used to generate the DTLS cookie, and additional checking is done on the cookie for Denial-of-Service prevention.

##Fixed key type verification for chosen cipher suite
An internal verification function that determined whether the server key type was correct for the chosen cipher suite has now been fixed.  Previous versions would sometimes incorrectly determine the server was using the wrong key type if the server was using a certificate chain where parent certificates did not use the same key type.  This bug resulted in a failed handshake and is now fixed.

##Validation of RSA Signature Creation 
An internal RSA validation of created signatures has been added to the library in the `psRsaEncryptPriv()` function.

A security researcher has shown it is possible for RSA private key information to leak under some special failure circumstances.  Information on the exploit can be found here: https://people.redhat.com/~fweimer/rsa-crt-leaks.pdf

The potential leak is only possible if a `DHE_RSA` based cipher suite is supported on the server side.  This is the only handshake combination in which an RSA signature is sent over the wire (during the `SERVER_KEY_EXCHANGE` message).  The signature itself must have been incorrectly generated for the exploit to be possible.

The additional signature validation test will now cause the TLS handshake to fail prior to a faulty signature being sent to the client.

##Side Channel Vulnerability on RSA Cipher Suites
A Bleichenbacher variant attack, where certain information is leaked from the results of a RSA private key operation has been reported by a security researcher. The code has been updated to error without providing any information on the premaster contents.

> Note that other side channel attacks may still be possible as MatrixSSL non-FIPS crypto is not always constant-time.

##Access Violation on Malicious TLS Record
TLS cipher suites with CBC mode in TLS 1.1 and 1.2 could have an access violation (read beyond memory) with a maliciously crafted message.

#3 KNOWN ISSUES

- *Microsoft Windows* targets do not support certificate date validation currently. Users requiring this feature can use Windows APIs to get and parse the current date, using the POSIX implementation as a reference.
- *Arm* platforms linking with some versions of *OpenSSL* `libcrypto` library may have errors in AES-CBC cipher suites due to the library's inability to handle in-situ encryption within the same block.

#Changes in 3.8.2
--------
> **Version 3.8.2**
> December 2015
> *&copy; INSIDE Secure - 2015 - All Rights Reserved*

1. FILE/API REORGANIZATION
  - File Locations
  - Crypto API
2. SECURITY IMPROVEMENTS
  - Simplified Configuration
  - Deprecated Ciphers
  - Deprecated TLS Features
  - Key Strength
  - Ephemeral Cipher Suites Enabled by Default
  - ECC Curve List
  - Reordered cipher suite preferences
  - memset_s()
  - Handshake State Machine Improvements
3. FEATURES AND IMPROVEMENTS
  - DTLS Protocol Included
  - Optimized Diffie-Hellman performance
  - Optimized EC signature generation performance
  - OpenSSL Crypto Primitive Provider
  - OpenSSL TLS API layer
  - Reduced TLS session footprint
  - X.509 Improvements
  - PKCS#12 Key Parsing
  - Improved certificate callback example
  - Per digest control of HMAC algorithms
  - Default high resolution timing
  - Assert and Error Optimizations
4. BUG FIXES
  - 64 bit little endian platforms
  - X.509 KeyUsage extension
  - X.509 date validation fix
  - Fixed handshake parse issue
  - TLS server sending old self-signed certificate
  - Fixed ECC variable encoding bugs
  - DHE_PSK compatibility
  - AES-GCM with AESNI
  - Library configuration test
  - Windows psGetFileBuf

#1 FILE/API REORGANIZATION

##File Locations
MatrixSSL 3.8.2 introduces directory changes to the distribution since 3.7.2

Functionality|3.7.2|3.8.2
---|---|---
TLS/DTLS example apps|./apps|./apps/ssl ./apps/dtls
Test keys and certificates|./sampleCerts|./testkeys
XCode and Visual Studio projects|*(various)*|./xcode ./visualstudio

 Several file changes and renames are present as well:
 
Functionality|3.7.2|3.8.2
---|---|---
TLS Decoding|./matrixssl/sslDecode.c|./matrixssl/sslDecode.c ./matrixssl/hsDecode.c ./matrixssl/extDecode.c
Private key import / export|./crypto/pubkey/pkcs.c.|./crypto/keyformat/pkcs.c
 Configuration consistency and sanity checks|./matrixssl/matrixssllib.h|./matrixssl/matrixsslCheck.h

##Crypto API
The API layers into the raw cryptographic operations have been significantly changed. The crypto API changes do not affect the main MatrixSSL API for creating TLS sessions, etc. However, developers who interface with crypto directly, or who want to write a custom hardware layer will be interested in the new layer.

###API Model
The cryptography API for symmetric crypto, digests and HMAC follow the common model:

**Init API**
: Initializes the cipher and returns an error on failure (typically due to bad input parameters or insufficient memory).

**Encrypt/Decrypt/Update API**
: Performs the operation and does not return an error code (previously some APIs would return the number of bytes decrypted).

**Clear API**
: Zero and/or free any associated memory associated with the cipher.

###Standard Types
Standard C99 types from `<stdint.h>` are used to specify integer parameters.

`uint8_t`
: The length of an IV, password or an AES-GCM tag

`uint16_t`
: The length of an asymmetric key (RSA/DH/ECC), a HMAC key or Additional Authenticated Data (AAD) for an AEAD cipher such as AES-GCM.

`uint32_t`
: The length of data to be processed by the cipher

`uint64_t`: Internally used by crypto library to store large counter values and when optimizing for 64 bit platforms.

###Const Correctness
Pointers to values that are not modified are marked `const`.

###API Name changes
API names have been standardized as follows:

API|3.7.2|3.8.2
---|---|---
Initialization of low level AES block cipher|psAesInitKey|psAesInitBlockKey
AES CBC|psAesInit, psAesDecrypt, psAesEncrypt|psAesInitCBC, psAesDecryptCBC, psAesEncryptCBC
SHA2 HMAC|psHmacSha2|psHmacSha256, psHmacSha384
ECC signature creation|psEccSignHash|psEccDsaSign
ECC signature validation|psEcDsaValidateSignature|psEccDsaVerify

###Standardized Context Names
Cryptographic functions that used to accept generic “context” identifiers now require the specific key/algorithm structure, for example:

API|3.7.2|3.8.2
---|---|---
HMAC family|psHmacContext_t|psHmacSha1_t, psHmacSha256_t, ...
Digest family|psDigestContext_t|psSha1_t, psSha256_t, etc...
Symmetric family|psCipherContext_t|psAesCbc_t, psAesGcm_t, psDes3Key_t
RSA private key parse (pkcs1)|psPubKey_t|psRsaKey_t
ECC private key parse|psPubKey_t|psEccKey_t

###Standardized Return Types
In general, Init apis return a standard `PS_*` status code. A status code that is not `PS_SUCCESS` typically indicates invalid input parameters or a resource allocation failure.  Update and Clear APIs no longer have a return. For example:

API|3.7.2|3.8.2
---|---|---
HMAC Init|void|int32_t
HMAC Final|int32_t|void
Digest Init|void|int32_t
Digest Final|int32_t|void

###Memory Model
In general, APIs now take an allocated cipher structure, and do not allocate the structure in the Init routine. In the past, the memory allocation model was inconsistent.

For ECC and DH, there are now additional APIs that allow the key to be allocated and initialized, to complement the APIs which just initialize the keys.

The Clear API must always be called when done with a context, as some algorithms internally allocate additional memory for operation.

#2 SECURITY IMPROVEMENTS

##Simplified Configuration
The configuration of ciphers and cipher suites in _crypto/cryptoConfig.h_ and _matrixssl/matrixsslConfig.h_ has been simplified considerably. Existing and new users of MatrixSSL should take a look at these files to understand the various options and features supported.

##Deprecated Ciphers
- ARC4, SEED, IDEA, RC2, MD4 and MD2 are deprecated, and not enabled by default in _cryptoConfig.h_
- MD5 and SHA1 are not recommended for use, but enabled by default because they are required for TLS protocols before version 1.2. Although they are enabled in _cryptoConfig.h,_ their use within the TLS protocol is limited to where required, and they can be independently disabled from use as a certificate signature algorithm and an HMAC algorithm. The new crypto primitive `psMd5Sha1_t` is intended to replace standalone MD5 or SHA1 use outside of where required in TLS.
- 3DES is not deprecated, but be aware of key strength limitations vs. AES-128 and AES-256.

##Deprecated TLS Features
- TLS cipher suites that rely on deprecated crypto algorithms have also been deprecated in matrixsslConfig.h
- TLS Compression support is now deprecated and the option removed from the configuration.
- False Start support is now deprecated and the option removed from the configuration.

##Key Strength
Key strength defines have not changed since previous releases, however it should be noted that the default minimum RSA/DH sizes of 1024 and ECC sizes of 192 do not meet a growing number of security standards and larger keys should be beginning to be deployed.

##Ephemeral Cipher Suites Enabled by Default
ECDHE and DHE cipher suites are now enabled by default. Be aware that for embedded platforms, this may require significant additional CPU load.

##ECC Curve List
The supported ECC Curve list is now always given in bit-strength order. This ensures that when negotiating EC Parameters, the strongest available will be used.

##Reordered cipher suite preferences
Clients send a priority list order of cipher suites during TLS negotiations, and servers use a priority list of ciphers to pick a common cipher for the connection.

MatrixSSL orders this list using the following rules, resulting in some change to the cipher suite preference order in _cipherSuite.c_. In order to make as secure a connection as possible, the parameters of Authentication, Data Integrity and Data Security were taken in that order to generate a new cipher preference list. In places where these parameters are of equivalent strength, the faster algorithm is preferred (although the “faster” algorithm often depends on the platform). *Currently DHE is prioritized over ECDHE due only to performance. In future releases, ECDHE may be the preferred key exchange mode.*

The ordering of the ciphers is grouped and sub-grouped by the following:

1. Non-deprecated
2. Ephemeral
3. Authentication Method (PKI > PSK > anon)
4. Hash Strength (SHA384 > SHA256 > SHA > MD5)
5. Cipher Strength (AES256 > AES128 > 3DES > ARC4 > SEED > IDEA > NULL)
6. PKI Key Exchange (DHE* > ECDHE > ECDH > RSA > PSK)
7. Cipher Mode (GCM > CBC)
8. PKI Authentication Method (ECDSA > RSA > PSK)

##memset_s()
Use the `memset_s()` api to zero memory regardless of compiler optimization which might skip zeroing for memory that is not subsequently used. For platforms without a built in implementation, `memset_s()` is automatically built in `core/memset_s.c`

##Handshake State Machine Improvements

###Simplified code paths
The handshake decode state machine was split among additional files and functions. Switch statements replace other logic to more clearly show each case and its result. The state machine is still quite complex due to the large number of modes and states that are supported in MatrixSSL. Always consult support when making changes to the state machine.

###Multiple state tracking
Connection state tracking has always been implemented as "expected next state", with no security issues. However for a double check, MatrixSSL now implements independent tracking of the last state encoded and decoded, as well as the expected next state.

###More strict extension processing
The extension parsing is more strict in what can be accepted and when.

#3 FEATURES AND IMPROVEMENTS

##DTLS Protocol Included
Beginning in the 3.8.2 version of MatrixSSL, the DTLS 1.0 and DTLS 1.2 protocols are included in MatrixSSL open source package.

Enable `USE_DTLS` in _./matrixssl/matrixsslConfig.h_ to include it in library. Additional documentation, app examples, and test code is included to aid in development.

##Optimized Diffie-Hellman performance
Use smaller generated key sizes for a given DH prime field size per [NIST SP 800-57 Part 1](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf). This provides up to a 9x performance gain for DH operations, greatly increasing the speed of ephemeral ciphers using DH.

##Optimized EC signature generation performance
Improved performance for finding valid ECC key pairs, especially on larger key sizes.

##OpenSSL Crypto Primitive Provider
Allows MatrixSSL to be linked against _OpenSSL_ `libcrypto` as a crypto primitive provider. This allows platforms that use _OpenSSL_ as their crypto API (such as _Cavium Octeon_) provide hardware acceleration to MatrixSSL applications.

##OpenSSL TLS API layer
Users wishing to replace _OpenSSL_ with MatrixSSL often desire a layer that will ease the integration. MatrixSSL 3.8.2 includes an _OpenSSL_API layer that was previously provided upon request. This layer is found in the _./matrixssl_ directory in the _opensslApi.c_and _opensslSocket.c_ files. The _opensslApi.h_ and _opensslSocket.h_ headers define the interface.

##Reduced TLS session footprint
The size of each TLS session was reduced by 512 bytes for AES cipher suites, and additionally by ~100 bytes for all cipher suites.

##X.509 Improvements
OID parsing has been improved and provides better feedback on error. SHA-512 signed certificates are now supported.

##PKCS#12 Key Parsing
Support for longer passwords and additional private key bag.

##Improved certificate callback example
The _./apps/ssl/client.c_ application now has a more robust processing example to help integrators understand the relationship between the incoming `alert` value and the individual `authStatus` members of the server’s certificate chain.

##Per digest control of HMAC algorithms
Each HMAC algorithm can now be specifically enabled/disabled with `USE_HMAC_(digest)` defines in _cryptoConfig.h_

##Default high resolution timing
POSIX platforms will have high-resolution timers active by default

##Assert and Error Optimizations
`USE_CORE_ASSERT` and `USE_CORE_ERROR` can now be disabled in _coreConfig.h_. This can reduce code size by removing the static strings used in errors and asserts. Recommended for final deployment only.

#4 BUG FIXES

##64 bit little endian platforms
The `STORE32L` macro in _cryptolib.h_ has been fixed for little endian 64 platforms. The `STORE32H` macro in _cryptolib.h_ has been fixed for big endian 64 platforms not using assembly language optimizations.
Platforms such as *MIPS64* are now automatically detected by the build system.

##X.509 KeyUsage extension
Fixed the parse to allow for `BIT_STRING` lengths longer than should be expected.

##X.509 date validation fix
A bug has been fixed in the `validateDateRange()` function in _x509.c_. In previous versions, the time format (`ASN_UTCTIME`, etc..) of the `notAfter` date was being set based on the `notBefore` field. This bug would have caused problems for certificates that used different time formats for the `notBefore` and `notAfter` fields.

##Fixed handshake parse issue
A bug was found on the server side while parsing a specific case of handshake messages from a client. If the cipher suite used a key exchange mechanism of ECDHE or ECHE, and the handshake was using client authentication, and the client was sending the `CLIENT_KEY_EXCHANGE` message and `CERTIFICATE_VERIFY` message in a single record, the MatrixSSL server was unable to parse that flight and would close the connection. This is now fixed.

##TLS server sending old self-signed certificate
A bug has been fixed so that if a server sends a self-signed certificate that does not contain the `AuthorityKeyIdentifier` extension, the authentication logic will detect that and not report an error to the certificate callback.
> Servers shouldn’t send self-signed certificates in the `CERTIFICATE` message. Client must still always have the same self-signed cert loaded in order to authenticate.

##Fixed ECC variable encoding bugs
For Client Auth rehandshakes, the variable signature sizes of ECDSA resulted in an issue when clients were creating the encrypted `CERTIFICATE_VERIFY` message.
`secp224r1` curves also had an additional bug that could cause an invalid signature in some cases due to the variable encoding rules.

##DHE_PSK compatibility
Fixed issue with `DHE_PSK` ciphers when a `PSK_ID` was not used. Previously a handshake alert would occur.

##AES-GCM with AESNI
Fixed an issue causing an invalid encoding of large data buffers with aes-gcm on Intel platforms with AESNI.

##Library configuration test
The mechanism to test that MatrixSSL applications have been compiled using the same configuration as the MatrixSSL static libraries has been fixed.

##Windows psGetFileBuf
Parameters to `CreateFileA()` are now correct for opening existing files.

#5 KNOWN ISSUES
- *Microsoft Windows* targets do not support certificate date validation currently. Users requiring this feature can use Windows APIs to get and parse the current date, using the POSIX implementation as a reference.
- *Arm* platforms linking with some versions of *OpenSSL* `libcrypto` library may have errors in AES-CBC cipher suites due to the library's inability to handle in-situ encryption within the same block.