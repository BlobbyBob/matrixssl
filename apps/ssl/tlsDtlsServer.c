/**
 *      @file    server.c
 *      @version $Format:%h%d$
 *
 *      Simple non-blocking MatrixSSL server example for multiple connections.
 *      Uses a single, hardcoded RSA identity.  No client authentication.
 */
/*
 *      Copyright (c) 2013-2017 Rambus Inc.
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
 *      commercial license for this software may be purchased from Rambus at
 *      http://www.rambus.com/
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
/******************************************************************************/

#define ENABLE_COMBINED_TLS_DTLS

#define main tls_main
#include "server.c"
#undef main

#ifdef USE_MULTITHREADING

# define sigsegv_handler dtls_sigsegv_handler
# define sigintterm_handler dtls_sigintterm_handler
# define setSocketOptions dtls_setSocketOptions
# define process_cmd_options dtls_process_cmd_options
# define usage dtls_usage
# define main dtls_main


# include "../dtls/dtlsCommon.c"
# include "../dtls/dtlsServer.c"

# undef main

static pthread_t tls_server_thread = 0;
static pthread_t dtls_server_thread = 0;

char **argv_server;
int argc_server = 0;

static void closedown_exit(const char *msg, int rc)
{

    if (msg)
      {
          Fprintf(stderr, "%s\n", msg);
      }
    exit(rc);
}

void *tls_server_main_pthread(void *null_arg)
{
    int rc;

    psAssert(null_arg == NULL);
    Printf("Launching TLS server\n");
    rc = tls_main(argc_server, argv_server);
    return (void *) (uintptr_t) rc;
}

void *dtls_server_main_pthread(void *null_arg)
{
    int rc;

    psAssert(null_arg == NULL);
    Printf("Launching DTLS server\n");
    rc = dtls_main(argc_server, argv_server);
    return (void *) (uintptr_t) rc;
}

int main(int argc, char **argv)
{
    int rc;
    void *rcv;

    argc_server = argc;
    argv_server = argv;
//    for (int i = 0; i < argc_server ; i++) {
//        argv_server[i] = argv[i + 1];
//    }
    rc = Pthread_create(&tls_server_thread, NULL, &tls_server_main_pthread, NULL);
    if (rc != 0)
    {
        closedown_exit("unable to launch TLS server", EXIT_FAILURE);
    }
    rc = Pthread_create(&dtls_server_thread, NULL, &dtls_server_main_pthread, NULL);
    if (rc != 0)
    {
        closedown_exit("unable to launch DTLS server", EXIT_FAILURE);
    }

    Pthread_join(dtls_server_thread, &rcv);
    Printf("Shutting down server\n");
    pthread_kill(tls_server_thread, SIGINT);
    Pthread_join(tls_server_thread, &rcv);
    return 0;
}

#else
int main(int argc, char **argv)
{
    Printf("You need to #define USE_MULTITHREADING for this test\n");
    return 1;
}

#endif

