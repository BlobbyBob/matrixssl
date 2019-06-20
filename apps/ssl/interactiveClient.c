/**
 *      @file    interactiveClient.c
 *      @version $Format:%h%d$
 *
 *      Interactive client-side test tool.
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */

#include "matrixssl/matrixsslApi.h"
#include "osdep.h"

# ifdef USE_CLIENT_SIDE_SSL

# if defined(USE_TLS_1_2) && defined(USE_SECP256R1) && defined(USE_SHA256) && defined(USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) && defined(USE_IDENTITY_CERTIFICATES)

# include <sys/types.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <limits.h>

/* Key material. */
# include "testkeys/EC/256_EC.h"
# include "testkeys/EC/256_EC_KEY.h"
# include "testkeys/EC/256_EC_CA.h"
# include "testkeys/RSA/2048_RSA.h"
# include "testkeys/RSA/2048_RSA_KEY.h"
# include "testkeys/RSA/3072_RSA.h"
# include "testkeys/RSA/3072_RSA_KEY.h"
# include "testkeys/RSA/ALL_RSA_CAS.h"
# include "testkeys/EC/ALL_EC_CAS.h"
# include "testkeys/PSK/tls13_psk.h"

# define SERVER_IP_ADDRESS "127.0.0.1"
# define SERVER_PORT 4433

/* Do we expect the server to the first piece of app data? */
static int g_server_sends_first;
/* Use matrixSslEncodeToOutdata for encoding small app data? */
static int g_encode_to_outdata;
/* Already received MATRIXSSL_HANDSHAKE_COMPLETE? */
static int g_handshake_complete;
/* Skip server authentication entirely? */
static psBool_t g_skip_server_auth;

static size_t leftNBytes;
static size_t sentNBytes;

/* HTTP GET request header. */
static unsigned char g_httpRequestHdr[] = "GET %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
    "Accept: */*\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

/* Certificate callback. See section 6 in the API manual for details.
   In this test, we do no extra checks of our own; we simply accept
   the result of MatrixSSL's internal certificate validation. */
static int32_t certCb(ssl_t *ssl, psX509Cert_t *cert, int32_t alert)
{
    if (g_skip_server_auth)
    {
        return SSL_ALLOW_ANON_CONNECTION;
    }
    else
    {
        return alert;
    }
}

/* Returns a line of user input (without the newline character),
   or < 0 on error. The returned string may be truncated if it
   did not fit into buf. */
int get_user_input(char *buf, int buf_len)
{
    char *s, *p;
    char c;

    s = fgets(buf, buf_len, stdin);
    if (s == NULL)
    {
        return PS_FAILURE;
    }

    p = strchr(buf, '\n');
    if (p)
    {
        *p = '\0';
    }
    else
    {
        /* Flush stdin up to newline or EOF. */
        c = getchar();
        while (c != '\n' && !feof(stdin) && !ferror(stdin))
        {
            c = getchar();
        }
    }

    //printf("Got: %s (len: %zu)\n", buf, strlen(buf));

    return PS_SUCCESS;
}

int get_user_input_char(char *c, char defaultChoice)
{
    char buf[2] = {0};
    size_t buf_len = sizeof(buf);
    int rc;

    rc = get_user_input(buf, buf_len);
    if (rc < 0)
    {
        return rc;
    }

    if (Strlen(buf) == 0)
    {
        *c = defaultChoice;
    }
    else
    {
        *c = buf[0];
    }

    return PS_SUCCESS;
}

static int32_t getAppDataFromUser(ssl_t *ssl,
        unsigned char *data,
        size_t *dataLen)
{
    int rc;
    char buf[1024] = {0};
    size_t buf_len = sizeof(buf);
    size_t max_len;

    max_len = buf_len;
    if (*dataLen < buf_len && *dataLen < INT_MAX)
    {
        max_len = *dataLen;
    }

    rc = get_user_input(buf, (int)max_len);
    if (rc < 0)
    {
        printf("Failed to get user input\n");
        return PS_FAILURE;
    }

    Memcpy(data, buf, Strlen(buf) + 1);
    *dataLen = Strlen(buf) + 1;

    return PS_SUCCESS;
}

/*
  Ask the for app data to send over the encrypted connection,
  or for some other action.
  Return value:
   < 0 on error,
   PS_SUCCESS for nominal connection closure
   MATRIXSSL_REQUEST_SEND to send app data.
*/
static int32_t askSendAppData(ssl_t *ssl)
{
    int32_t rc;
    unsigned char *buf;
    unsigned char data[1024] = {0};
    size_t dataLen = sizeof(data);
    size_t sendNBytes;
    static unsigned char *fileData = NULL;
    unsigned char *pData;
    const char *s;

    if (leftNBytes > 0)
    {
        pData = fileData;
        goto continue_sending;
    }

    printf("You: ");
    rc = getAppDataFromUser(ssl, data, &dataLen);
    if (rc < 0)
    {
        return rc;
    }

    if (data[0] == ':')
    {
        /* Handle commands. */

        /* Handle :quit, :exit and :q */
        s = (char*)&data[1];
        if (!Strncmp(s, "quit", strlen("quit"))
                || !Strncmp(s, "exit", strlen("exit"))
                || (dataLen == 2 && data[1] == 'q'))
        {
            rc = matrixSslEncodeClosureAlert(ssl);
            (void)rc;
            return PS_SUCCESS;
        }
        if (!Strncmp(s, "file", strlen("file")))
        {
# ifdef MATRIX_USE_FILE_SYSTEM
            printf("Enter file name: ");
            dataLen = sizeof(data);
            rc = getAppDataFromUser(ssl, data, &dataLen);
            if (rc < 0)
            {
                goto out_fail;
            }
            rc = psGetFileBuf(NULL, (char*)data, &fileData, &dataLen);
            if (rc < 0)
            {
                printf("Unable to open file\n");
                sprintf((char*)data, "%s", "[I tried to send a file, but failed]");
            }
# else
            printf("Need MATRIX_USE_FILE_SYSTEM for this\n");
            rc = PS_UNSUPPORTED_FAIL;
            goto out_fail;
# endif /* MATRIX_USE_FILE_SYSTEM */
        }
        if (!Strncmp(s, "url", strlen("url")))
        {
            unsigned char url[sizeof(data)] = {0};
            int n;

            printf("Enter URL to GET: ");
            dataLen = sizeof(url);
            rc = getAppDataFromUser(ssl, url, &dataLen);
            if (rc < 0)
            {
                goto out_fail;
            }
            n = Snprintf((char*)data,
                    sizeof(data),
                    (char*)g_httpRequestHdr,
                    (char*)url,
                    "localhost");
            dataLen = n + 1;
            printf("Sending: %s (len: %zu)\n", data, dataLen);
        }
    }

    if (fileData != NULL)
    {
        pData = fileData;
    }
    else
    {
        pData = data;
    }

    leftNBytes = dataLen;
    sentNBytes = 0;

continue_sending:
    /* Get pointer to the internal plaintext buffer and fill
       it with the plaintext data. The returned buffer may
       be smaller, in which case we'll come back here to
       continue on next call. */
    if (g_encode_to_outdata && leftNBytes < 16384)
    {
        rc = matrixSslEncodeToOutdata(ssl, pData, leftNBytes);
        if (rc < 0)
        {
            printf("matrixSslEncodeToOutdata failed: %d\n", rc);
            goto out_fail;
        }
        leftNBytes = 0;
    }
    else
    {
        rc = matrixSslGetWritebuf(ssl, &buf, leftNBytes);
        if (rc < 0)
        {
            rc = PS_FAILURE;
            goto out_fail;
        }

        if (rc < leftNBytes)
        {
            sendNBytes = rc;
        }
        else
        {
            sendNBytes = leftNBytes;
        }

        memcpy(buf, pData, sendNBytes);
        sentNBytes += sendNBytes;
        leftNBytes -= sendNBytes;

        printf("Sent %zu/%zu bytes\n", sentNBytes, sentNBytes + leftNBytes);

        /* Encrypt. */
        rc = matrixSslEncodeWritebuf(ssl, sendNBytes);
        if (rc < 0)
        {
            rc = PS_FAILURE;
            goto out_fail;
        }
    }

    /* Ask the main loop to send it over the wire. */
    rc = MATRIXSSL_REQUEST_SEND;

out_fail:
    if (fileData != NULL)
    {
        if (leftNBytes == 0)
        {
            psFree(fileData, NULL);
            fileData = NULL;
        }
    }
    return rc;
}

psRes_t getUserProtocolVersion(psProtocolVersion_t *verOut)
{
    const char *proto_ver_prompt =
        "Select protocol version to use:\n" \
        "(4) TLS 1.3 (default)\n" \
        "(3) TLS 1.2\n" \
        "(2) TLS 1.1\n" \
        "(1) TLS 1.0\n";
    char c;
    psProtocolVersion_t v;
    int got_it = 0;
    int rc;

    printf("%s", proto_ver_prompt);

    while (got_it == 0)
    {
        rc = get_user_input_char(&c, '4');
        if (rc < 0)
        {
            printf("getUserProtocolVersion failed\n");
            return PS_FAILURE;
        }
        got_it = 1;
        switch (c)
        {
        case '4':
            v = v_tls_1_3;
            break;
        case '3':
            v = v_tls_1_2;
            break;
        case '2':
            v = v_tls_1_1;
            break;
        case '1':
            v = v_tls_1_0;
            break;
        case 'q':
            return PS_FAILURE;
        default:
            printf("Invalid choice: %c\n", c);
            got_it = 0;
        }
    }

    *verOut = v;

    return PS_SUCCESS;
}

psRes_t getUserKeyPair(const unsigned char **cert,
        int32_t *certLen,
        const unsigned char **key,
        int32_t *keyLen,
        int32_t *keyType,
        int32_t *pskLen)
{
    const char *key_prompt =
        "Select authentication key pair to use:\n" \
         "(1) P-256 ECDSA (default)\n" \
         "(2) 2048-bit RSA\n" \
         "(3) 3072-bit RSA\n" \
         "(4) PSK (32 bytes)\n" \
         "(5) PSK (48 bytes)\n";
    char c;
    int got_it = 0;
    int rc;

    /* Default keys. */
    *cert = EC256;
    *certLen = EC256_SIZE;
    *key = EC256KEY;
    *keyLen = EC256KEY_SIZE;
    *keyType = PS_ECC;
    *pskLen = 0;

    printf("%s", key_prompt);

    while (got_it == 0)
    {
        rc = get_user_input_char(&c, '1');
        if (rc < 0)
        {
            printf("getUserKeyPair failed\n");
            return PS_FAILURE;
        }
        got_it = 1;
        switch (c)
        {
        case '1':
            /* Use defaults from above. */
            break;
        case '2':
            *cert = RSA2048;
            *certLen = RSA2048_SIZE;
            *key = RSA2048KEY;
            *keyLen = RSA2048KEY_SIZE;
            *keyType = PS_RSA;
            break;
        case '3':
            *cert = RSA3072;
            *certLen = RSA3072_SIZE;
            *key = RSA3072KEY;
            *keyLen = RSA3072KEY_SIZE;
            *keyType = PS_RSA;
            break;
        case '4':
            *pskLen = 32;
            /* Load default keys in addition to the PSK. */
            break;
        case '5':
            *pskLen = 48;
            /* Load default keys in addition to the PSK. */
            break;
        case 'q':
            return PS_FAILURE;
        default:
            printf("Invalid choice: %c\n", c);
            got_it = 0;
        }
    }

    return PS_SUCCESS;
}

int load_keys(sslKeys_t *keys)
{
    const unsigned char *key, *cert;
    int32_t keyLen, certLen;
    int32_t keyType;
    const unsigned char *psk;
    const unsigned char *psk_id;
    psSize_t psk_id_len;
    int32_t pskLen;
    int rc;
    matrixSslLoadKeysOpts_t keyOpts;

    rc = getUserKeyPair(&key, &keyLen, &cert, &certLen, &keyType, &pskLen);
    if (rc < 0)
    {
        return rc;
    }

    Memset(&keyOpts, 0, sizeof(keyOpts));
    keyOpts.key_type = keyType;

# ifdef USE_TLS_1_3
    if (pskLen > 0)
    {
        if (pskLen == 32)
        {
            psk = g_tls13_test_psk_256;
            psk_id = g_tls13_test_psk_id_sha256;
            psk_id_len = sizeof(g_tls13_test_psk_id_sha256);
        }
        else if (pskLen == 48)
        {
            psk = g_tls13_test_psk_384;
            psk_id = g_tls13_test_psk_id_sha384;
            psk_id_len = sizeof(g_tls13_test_psk_id_sha384);
        }
        else
        {
            printf("Invalid PSK length\n");
            return EXIT_FAILURE;
        }
        rc = matrixSslLoadTls13Psk(
                keys,
                psk,
                pskLen,
                psk_id,
                psk_id_len,
                NULL);
        if (rc < 0)
        {
            printf("matrixSslLoadTls13Psk failed\n");
            return EXIT_FAILURE;
        }
    }
# endif

   rc = matrixSslLoadKeysMem(
            keys,
            key,
            keyLen,
            cert,
            certLen,
            RSACAS,
            sizeof(RSACAS),
            &keyOpts);
    if (rc < 0)
    {
        printf("matrixSslLoadKeysMem failed for key pair: %d\n", rc);
        return EXIT_FAILURE;
    }

    if (keyType == PS_ECC)
    {
        rc = matrixSslLoadKeysMem(
                keys,
                NULL,
                0,
                NULL,
                0,
                ECCAS,
                sizeof(ECCAS),
                &keyOpts);
        if (rc < 0)
        {
            printf("matrixSslLoadKeysMem failed for ECC CAs: %d\n", rc);
            return EXIT_FAILURE;
        }
    }

    return PS_SUCCESS;
}

psRes_t getUserFirstSender(void)
{
    const char *get_first_sender_prompt =
        "Who will send app data first?\n" \
        "(1) client (default)\n" \
        "(2) server\n";
    int rc;
    char c;
    int got_it = 0;

    printf("%s", get_first_sender_prompt);
    while (got_it == 0)
    {
        rc = get_user_input_char(&c, '1');
        if (rc < 0)
        {
            printf("getUserFirstSender failed\n");
            return PS_FAILURE;
        }
        got_it = 1;
        switch (c)
        {
        case '1':
            g_server_sends_first = 0;
            break;
        case '2':
            g_server_sends_first = 1;
            break;
        case 'q':
            return PS_FAILURE;
        default:
            printf("Invalid choice: %c\n", c);
            got_it = 0;
        }
    }

    return PS_SUCCESS;
}

psRes_t getEncodingFunc(void)
{
    const char *get_encoding_func_prompt =
        "Use matrixSslEncodeToOutdata for small <16KB application data?\n" \
        "(1) no (default)\n" \
        "(2) yes\n";
    int rc;
    char c;
    int got_it = 0;

    printf("%s", get_encoding_func_prompt);
    while (got_it == 0)
    {
        rc = get_user_input_char(&c, '1');
        if (rc < 0)
        {
            printf("getUserFirstSender failed\n");
            return PS_FAILURE;
        }
        got_it = 1;
        switch (c)
        {
        case '1':
            g_encode_to_outdata = 0;
            break;
        case '2':
            g_encode_to_outdata = 1;
            break;
        case 'q':
            return PS_FAILURE;
        default:
            printf("Invalid choice: %c\n", c);
            got_it = 0;
        }
    }

    return PS_SUCCESS;
}

psRes_t getUserSigAlgs(uint16_t *sigAlgs, psSize_t *numSigAlgs)
{
    const char *sig_algs_prompt =
        "Signature algorithms to use:\n" \
        "(1) sigalg_ecdsa_secp256r1_sha256 (default)\n" \
        "(2) sigalg_rsa_pss_rsae_sha256\n" \
        "(3) sigalg_rsa_pkcs1_sha256\n";

    int rc;
    char c;
    int got_it = 0;
    psSize_t i = 0;

    printf("%s", sig_algs_prompt);
    while (got_it == 0)
    {
        rc = get_user_input_char(&c, '1');
        if (rc < 0)
        {
            printf("getUserSigAlgs failed\n");
            return PS_FAILURE;
        }
        got_it = 1;
        switch (c)
        {
        case '1':
            sigAlgs[i++] = sigalg_ecdsa_secp256r1_sha256;
            break;
        case '2':
            sigAlgs[i++] = sigalg_rsa_pss_rsae_sha256;
            break;
        case '3':
            sigAlgs[i++] = sigalg_rsa_pkcs1_sha256;
            break;
        case 'q':
            return PS_FAILURE;
        default:
            printf("Invalid choice: %c\n", c);
            got_it = 0;
        }
    }

    *numSigAlgs = i;

    return PS_SUCCESS;
}

psRes_t getUserCiphersuites(psCipher16_t *ciphersuites,
        psSize_t *numCiphersuites)
{
    static const char *ciphersuites_prompt =
        "Ciphersuite to use:\n" \
        "(1) TLS_AES_128_GCM_SHA256 (default)\n" \
        "(2) TLS_AES_256_GCM_SHA384\n" \
        "(3) TLS_CHACHA20_POLY1305_SHA256\n" \
        "(4) TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\n" \
        "(5) TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n" \
        "(6) TLS_RSA_WITH_AES_128_GCM_SHA256\n" \
        "(7) All TLS 1.3 suites (prefer SHA256)\n" \
        "(8) All TLS 1.3 suites (prefer SHA384)\n";
    int rc;
    char c;
    int got_it = 0;
    psSize_t i = 0;

    printf("%s", ciphersuites_prompt);
    while (got_it == 0)
    {
        rc = get_user_input_char(&c, '1');
        if (rc < 0)
        {
            printf("getUserCiphersuites failed\n");
            return PS_FAILURE;
        }
        got_it = 1;
        switch (c)
        {
        case '1':
            ciphersuites[i++] = TLS_AES_128_GCM_SHA256;
            break;
        case '2':
            ciphersuites[i++] = TLS_AES_256_GCM_SHA384;
            break;
        case '3':
            ciphersuites[i++] = TLS_CHACHA20_POLY1305_SHA256;
            break;
        case '4':
            ciphersuites[i++] = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
            break;
        case '5':
            ciphersuites[i++] = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
            break;
        case '6':
            ciphersuites[i++] = TLS_RSA_WITH_AES_128_GCM_SHA256;
            break;
        case '7':
            ciphersuites[i++] = TLS_AES_128_GCM_SHA256;
            ciphersuites[i++] = TLS_AES_256_GCM_SHA384;
            ciphersuites[i++] = TLS_CHACHA20_POLY1305_SHA256;
            break;
        case '8':
            ciphersuites[i++] = TLS_AES_256_GCM_SHA384;
            ciphersuites[i++] = TLS_AES_128_GCM_SHA256;
            ciphersuites[i++] = TLS_CHACHA20_POLY1305_SHA256;
            break;
        case 'q':
            return PS_FAILURE;
        default:
            printf("Invalid choice: %c\n", c);
            got_it = 0;
        }
    }

    *numCiphersuites = i;

    return PS_SUCCESS;
}

psRes_t getMaximumFragmentLength(short *maxFragLen)
{
    const char *max_frag_len_prompt =
        "Maximum fragment length\n" \
        "(1) none (default)\n" \
        "(2) 512\n" \
        "(3) 1024\n" \
        "(4) 2048\n" \
        "(5) 4096\n";
    int rc;
    char c;
    int got_it = 0;

    printf("%s", max_frag_len_prompt);
    while (got_it == 0)
    {
        rc = get_user_input_char(&c, '1');
        if (rc < 0)
        {
            printf("getMaximumFragmentLength failed\n");
            return PS_FAILURE;
        }
        got_it = 1;
        switch (c)
        {
        case '1':
            *maxFragLen = 0;
            break;
        case '2':
            *maxFragLen = 512;
            break;
        case '3':
            *maxFragLen = 1024;
            break;
        case '4':
            *maxFragLen = 2048;
            break;
        case '5':
            *maxFragLen = 4096;
            break;
        default:
            printf("Invalid choice: %c\n", c);
            got_it = 0;
        }
    }

    return PS_SUCCESS;
}

psRes_t getServerAddress(char *addr_out, int *addr_out_len)
{
    const char *server_address_prompt =
        "Server IP address (default 127.0.0.1):\n";
    char addr[40];
    int addr_len = (int)sizeof(addr);
    const char *addr_default = "127.0.0.1";
    int rc;

    printf("%s", server_address_prompt);
    rc = get_user_input(addr, addr_len);
    if (rc < 0)
    {
        return PS_FAILURE;
    }

    if (Strlen(addr) == 0)
    {
        Strncpy(addr_out, addr_default, 39);
    }
    else
    {
        Strncpy(addr_out, addr, 39);
    }

    *addr_out_len = strlen(addr);

    return PS_SUCCESS;
}

psRes_t getServerPort(int *port_out)
{
    const char *server_port_prompt =
        "Server port (default: 4433)\n";
    char buf[6];
    int buf_len = sizeof(buf);
    long int port;
    char *end;
    int got_it = 0;
    int rc;

    printf("%s", server_port_prompt);

    while (got_it == 0)
    {
        rc = get_user_input(buf, buf_len);
        if (rc < 0)
        {
            return PS_FAILURE;
        }
        got_it = 1;
        port = Strtol(buf, &end, 10);
        if (port < 0 || port > 65536)
        {
            printf("Invalid port\n");
            got_it = 0;
        }
        if (buf == end)
        {
            port = 4433;
        }
    }

    *port_out = port;
    return PS_SUCCESS;
}

psRes_t getServerName(
        char *name_out,
        int name_out_len,
        char *ip_addr)
{
    const char *server_name_prompt_fmt =
        "Server name (default: %s)\n";
    char server_name_prompt[256];
    char buf[256];
    int buf_len = sizeof(buf);
    int got_it = 0;
    int rc;

    /* Default name = previously selected IP address. */
    snprintf(server_name_prompt,
            256,
            server_name_prompt_fmt,
            ip_addr);
    printf("%s", server_name_prompt);

    while (got_it == 0)
    {
        rc = get_user_input(buf, buf_len);
        if (rc < 0)
        {
            return PS_FAILURE;
        }
        got_it = 1;
    }

    if (Strlen(buf) == 0)
    {
        if (name_out_len < Strlen(ip_addr))
        {
            printf("Default server name won't fit into output buffer\n");
            return PS_FAILURE;
        }
        Strncpy(name_out, ip_addr, name_out_len - 1);
    }
    else
    {
        Strncpy(name_out, buf, buf_len - 1);
    }

    return PS_SUCCESS;
}

psRes_t getAllowAnon(psBool_t *allow)
{
    const char *allow_anon_prompt =
        "Skip server authentication?\n" \
        "(1) no (default)\n" \
        "(2) yes\n";
    int rc;
    char c;
    int got_it = 0;

    printf("%s", allow_anon_prompt);
    while (got_it == 0)
    {
        rc = get_user_input_char(&c, '1');
        if (rc < 0)
        {
            printf("getAllowAnon failed\n");
            return PS_FAILURE;
        }
        got_it = 1;
        switch (c)
        {
        case '1':
            *allow = PS_FALSE;
            break;
        case '2':
            *allow = PS_TRUE;
            break;
        default:
            printf("Invalid choice: %c\n", c);
            got_it = 0;
        }
    }

    return PS_SUCCESS;
}

int main(int argc, char **argv)
{
    uint16_t sigAlgs[16];
    psSize_t numSigAlgs;
    psProtocolVersion_t versions[1];
    psCipher16_t ciphersuites[1];
    psSize_t numCiphersuites;
    char serverAddress[39];
    char serverName[256] = { '\0' };
    int serverAddressLen;
    int serverPort;
    unsigned char *sniExtData;
    int32_t sniExtDataLen;
    tlsExtension_t *sniExt;
    sslSessOpts_t opts;
    sslKeys_t *keys;
    int32_t rc;
    uint32_t len;
    ssl_t *ssl = NULL;
    unsigned char *buf;
    ssize_t nrecv, nsent;
    int fd = -1;
    struct sockaddr_in addr;

    rc = matrixSslOpen();
    if (rc < 0)
    {
        return EXIT_FAILURE;
    }

    Memset(&opts, 0, sizeof(opts));

    rc = getUserProtocolVersion(&versions[0]);
    if (rc < 0)
    {
        return EXIT_FAILURE;
    }
    rc = matrixSslSessOptsSetClientTlsVersions(
            &opts,
            versions,
            1);
    if (rc < 0)
    {
        printf("matrixSslSessOptsSetClientTlsVersions failed: %d\n", rc);
        return EXIT_FAILURE;
    }

    rc = matrixSslNewKeys(&keys, NULL);
    if (rc < 0)
    {
        return EXIT_FAILURE;
    }

    rc = load_keys(keys);
    if (rc < 0)
    {
        matrixSslDeleteKeys(keys);
        return EXIT_FAILURE;
    }

    /* Set P-256 as the supported ECC curve for signatures and key exchange. */
    opts.ecFlags = IS_SECP256R1;

    rc = getUserSigAlgs(sigAlgs, &numSigAlgs);
    if (rc < 0)
    {
        goto out_fail;
    }
    rc = matrixSslSessOptsSetSigAlgs(
            &opts,
            sigAlgs,
            numSigAlgs);
    if (rc < 0)
    {
        printf("matrixSslSessOptsSetSigAlgs failed: %d\n", rc);
        goto out_fail;
    }

    rc = getUserCiphersuites(ciphersuites, &numCiphersuites);
    if (rc < 0)
    {
        goto out_fail;
    }

    rc = getMaximumFragmentLength(&opts.maxFragLen);
    if (rc < 0)
    {
        goto out_fail;
    }

    rc = getServerAddress(serverAddress, &serverAddressLen);
    if (rc < 0)
    {
        goto out_fail;
    }

    rc = getServerPort(&serverPort);
    if (rc < 0)
    {
        goto out_fail;
    }

    rc = getServerName(serverName, sizeof(serverName), serverAddress);
    if (rc < 0)
    {
        goto out_fail;
    }

    matrixSslNewHelloExtension(&sniExt, NULL);
    matrixSslCreateSNIext(
            NULL,
            (unsigned char*)serverName,
            (uint32_t)Strlen(serverName),
            &sniExtData,
            &sniExtDataLen);
    matrixSslLoadHelloExtension(
            sniExt,
            sniExtData,
            sniExtDataLen,
            EXT_SNI);

    /* Create a new session and the ClientHello message. */
    rc = matrixSslNewClientSession(
            &ssl,
            keys,
            NULL,
            ciphersuites,
            numCiphersuites,
            certCb,
            serverName,
            sniExt,
            NULL,
            &opts);
    if (rc < 0)
    {
        printf("matrixSslNewClientSession failed: %d\n", rc);
        goto out_fail;
    }

    matrixSslDeleteHelloExtension(sniExt);
    psFree(sniExtData, NULL);

    rc = getUserFirstSender();
    if (rc < 0)
    {
        goto out_fail;
    }

    rc = getEncodingFunc();
    if (rc < 0)
    {
        goto out_fail;
    }

    rc = getAllowAnon(&g_skip_server_auth);
    if (rc < 0)
    {
        goto out_fail;
    }

    /* Open the TCP connection. */
    Memset((char *) &addr, 0x0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((short) serverPort);
    addr.sin_addr.s_addr = inet_addr(serverAddress);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        printf("socket failed: %d\n", fd);
        goto out_fail;
    }
    rc = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0)
    {
        close(fd);
        printf("connect failed: %d\n", rc);
        goto out_fail;
    }

WRITE_MORE:
    /* Get pointer to the output data to send. */
    rc = matrixSslGetOutdata(ssl, &buf);
    while (rc > 0)
    {
        len = rc;

        /* Send it over the wire. */
        nsent = send(fd, buf, len, 0);
        if (nsent <= 0)
        {
            printf("send() failed\n");
            goto out_fail;
        }

        /* Inform the TLS library how much we managed to send.
           Return code will tell us of what to do next. */
        rc = matrixSslSentData(ssl, nsent);
        if (rc < 0)
        {
            printf("matrixSslSentData failed: %d\n", rc);
            goto out_fail;
        }
        else if (rc == MATRIXSSL_REQUEST_CLOSE)
        {
            printf("Closing connection\n");
            goto out_ok;
        }
        else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
        {
            printf("Handshake complete\n");
            g_handshake_complete = 1;

            if (g_server_sends_first)
            {
                printf("Expecting server to transmit first\n");
                goto READ_MORE;
            }

            /* Send app data over the encrypted connection. */
get_more_user_data:
            rc = askSendAppData(ssl);
            if (rc == PS_SUCCESS)
            {
                goto out_ok;
            }
            else if (rc < 0)
            {
                goto out_fail;
            }
            goto WRITE_MORE;
        }
        /* rc == PS_SUCCESS. */

        /* More data to send? */
        if (leftNBytes > 0)
        {
            goto get_more_user_data;
        }

        rc = matrixSslGetOutdata(ssl, &buf);
    }

READ_MORE:
    /* Get pointer to buffer where incoming data should be read into. */
    rc = matrixSslGetReadbuf(ssl, &buf);
    if (rc < 0)
    {
        goto out_fail;
    }
    len = rc;

    /* Read data from the wire. */
    nrecv = recv(fd, buf, len, 0);
    if (nrecv < 0)
    {
        goto out_fail;
    }

    /* Ask the TLS library to process the data we read.
       Return code will tell us what to do next. */
    rc = matrixSslReceivedData(
            ssl,
            nrecv,
            &buf,
            &len);
    if (rc < 0)
    {
        goto out_fail;
    }
    else if (rc == MATRIXSSL_RECEIVED_ALERT)
    {
        printf("Exiting on alert\n");
        goto out_fail;
    }
    else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
    {
        if (g_handshake_complete)
        {
            /* This can happen when we receive further handshake messages
               from the server after successful completion of the
               handshake. In TLS 1.3, this occurs with NewSessionTicket
               messages and post-handshake client authentication.
               We already given whoever should transmit first a chance.
               So now we try again to get app data from the server. */
            goto READ_MORE;
        }

        printf("Handshake complete\n");
        g_handshake_complete = 1;

        if (g_server_sends_first)
        {
            printf("Expecting server to transmit first\n");
            goto READ_MORE;
        }

        /* Send app data over the encrypted connection. */
        rc = askSendAppData(ssl);
        if (rc == PS_SUCCESS)
        {
            goto out_ok;
        }
        else if (rc < 0)
        {
            goto out_fail;
        }
        goto WRITE_MORE;
    }
    else if (rc == MATRIXSSL_REQUEST_SEND)
    {
        /* Handshake messages or an alert have been encoded.
           These need to be sent over the wire. */
        goto WRITE_MORE;
    }
    else if (rc == MATRIXSSL_REQUEST_RECV)
    {
        /* Handshake still in progress. Need more messages
           from the peer. */
        goto READ_MORE;
    }
    else if (rc == MATRIXSSL_APP_DATA)
    {
        char *tmp;

        /* We received encrypted application data from the peer.
           Just print it out here. */
        tmp = malloc(len+1);
        if (tmp == NULL)
        {
            goto out_fail;
        }
        Memcpy(tmp, buf, len);
        tmp[len] = '\0';

        printf("Server: %s", tmp);
        if (strchr(tmp, '\n') == NULL)
        {
            printf("\n");
        }
        free(tmp);

        /* Inform the TLS library that we "processed" the data. */
        rc = matrixSslProcessedData(
                ssl,
                &buf,
                &len);
        if (rc < 0)
        {
            goto out_fail;
        }

        /* This test ends after successful reception of encrypted
           app data from the peer. */
        rc = askSendAppData(ssl);
        if (rc == PS_SUCCESS)
        {
            goto out_ok;
        }
        else if (rc < 0)
        {
            goto out_fail;
        }
        goto WRITE_MORE;
    }

out_ok:
    rc = PS_SUCCESS;

out_fail:
    matrixSslDeleteSession(ssl);
    matrixSslDeleteKeys(keys);
    matrixSslClose();
    close(fd);

    if (rc == PS_SUCCESS)
    {
        return EXIT_SUCCESS;
    }
    else
    {
        return EXIT_FAILURE;
    }
}

# else
int main(int argc, char **argv)
{
    _psTrace("This test requires USE_TLS_1_2, USE_SECP256R1, " \
            "USE_SHA256 and USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.\n");
    return 1;
}
# endif /* USE_TLS_1_2 && USE_SECP256R1 && USE_SHA256 && USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 && USE_IDENTITY_CERTIFICATES */
# else
int main(int argc, char **argv)
{
    _psTrace("This test requires USE_TLS_1_2, USE_SECP256R1, " \
            "USE_SHA256, USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 " \
            "and USE_IDENTITY_CERTIFICATES.\n");
    return 1;
}
# endif /* USE_CLIENT_SIDE_SSL */
