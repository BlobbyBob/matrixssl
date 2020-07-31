/**
 *      @file    interactiveServer.c
 *      @version $Format:%h%d$
 *
 *      Interactive client-side test tool.
 */
/*
 *      Copyright (c) 2013-2019 INSIDE Secure Corporation
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

# ifdef USE_SERVER_SIDE_SSL
#  include "interactiveCommon.h"

# if defined(USE_TLS_1_2) && defined(USE_SECP256R1) && defined(USE_SHA256) && defined(USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) && defined(USE_IDENTITY_CERTIFICATES)

# include <sys/types.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <limits.h>

# define SERVER_IP_ADDRESS "127.0.0.1"
# define SERVER_PORT 4433

/* Do we expect the server to the first piece of app data? */
int g_server_sends_first;
/* Use matrixSslEncodeToOutdata for encoding small app data? */
int g_encode_to_outdata;
/* Already received MATRIXSSL_HANDSHAKE_COMPLETE? */
int g_handshake_complete;
/* Skip server authentication entirely? */
psBool_t g_skip_server_auth;
/* Don't authenticate the client's certificate? */
psBool_t g_skip_client_auth;

size_t leftNBytes;
size_t sentNBytes;

/* HTTP GET request header. */
unsigned char g_httpRequestHdr[] = "GET %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
    "Accept: */*\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

/* Certificate callback. See section 6 in the API manual for details.
   In this test, we do no extra checks of our own; we simply accept
   the result of MatrixSSL's internal certificate validation. */
/*static int32_t certCb(ssl_t *ssl, psX509Cert_t *cert, int32_t alert)
{
    if (g_skip_client_auth)
    {
        return SSL_ALLOW_ANON_CONNECTION;
    }
    else
    {
        return alert;
    }
}*/

int main(int argc, char **argv)
{
    uint16_t sigAlgs[16];
    psSize_t numSigAlgs;
    psProtocolVersion_t versions[1];
    int serverPort;
    sslSessOpts_t opts;
    sslKeys_t *keys;
    int32_t rc;
    uint32_t len;
    ssl_t *ssl = NULL;
    unsigned char *buf;
    ssize_t nrecv, nsent;
    int fd = -1;
    int sock_fd;
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
    rc = matrixSslSessOptsSetServerTlsVersions(
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

    rc = getMaximumFragmentLength(&opts.maxFragLen);
    if (rc < 0)
    {
        goto out_fail;
    }

    rc = getServerPort(&serverPort);
    if (rc < 0)
    {
        goto out_fail;
    }

    /* Create a new server session. */
    rc = matrixSslNewServerSession(
            &ssl,
            keys,
            NULL,
            &opts);
    if (rc < 0)
    {
        printf("matrixSslNewClientSession failed: %d\n", rc);
        goto out_fail;
    }

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

    /* Start listening to a TCP port for connections. */
    Memset((char *) &addr, 0x0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((short) serverPort);
    addr.sin_addr.s_addr = INADDR_ANY;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        printf("socket failed: %d\n", fd);
        return EXIT_FAILURE;
    }
    rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0)
    {
        printf("bind failed: %d\n", rc);
        return EXIT_FAILURE;
    }
    rc = listen(fd, 1);
    if (rc < 0)
    {
        printf("listen failed: %d\n", rc);
        return EXIT_FAILURE;
    }
    printf("Listening for connections on port %d...\n", serverPort);
    sock_fd = accept(fd, NULL, NULL);
    if (rc < 0)
    {
        printf("accept failed: %d\n", rc);
        return EXIT_FAILURE;
    }
    printf("Received new connection\n");

    /* Try to receive ClientHello. */
    goto READ_MORE;

WRITE_MORE:
    /* Get pointer to the output data to send. */
    rc = matrixSslGetOutdata(ssl, &buf);
    while (rc > 0)
    {
        len = rc;

        /* Send it over the wire. */
        nsent = send(sock_fd, buf, len, 0);
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
            else
            {
                goto READ_MORE;
            }
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
    nrecv = recv(sock_fd, buf, len, 0);
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
        else
        {
            /* Wait for client to transmit first. */
            goto READ_MORE;
        }
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

        printf("Client: %s", tmp);
        if (strchr(tmp, '\n') == NULL)
        {
            printf("\n");
        }
        if (!Strncmp(tmp, "tls-unique:", strlen("tls-unique:")))
        {
            unsigned char bindings[36];
            psSizeL_t bindingsLen = sizeof(bindings);

            /* Possibly unused. */
            (void)bindings;
            (void)bindingsLen;

            printf("Got tls-unique-id ID from client.\n");
# ifdef USE_RFC5929_TLS_UNIQUE_CHANNEL_BINDINGS            
            printf(" Checking the client's tls-unique-id...\n");
            rc = matrixSslGetTlsUniqueChannelBindings(
                    ssl,
                    bindings,
                    &bindingsLen);
            (void)rc;
            if (len - strlen("tls-unique:") >= bindingsLen &&
                    !Memcmp(tmp + strlen("tls-unique:"),
                            bindings,
                            bindingsLen))
            {
                printf("It's the same as ours! No MITM.\n");
            }
            else
            {
                printf("It's different from ours. WARNING: could be a MITM...\n");
                psTraceBytes("ours", bindings, bindingsLen);
                psTraceBytes("received",
                        (const unsigned char*)tmp + strlen("tls-unique:"),
                        len - strlen("tls-unique:"));
            }
# else
            printf(" But would need USE_RFC5929_TLS_UNIQUE_CHANNEL_BINDINGS "
                    "to check!\n");
# endif
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
    close(sock_fd);

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
