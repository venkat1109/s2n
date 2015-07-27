/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>

#include <s2n.h>

#include "utils/s2n_safety.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

static struct s2n_connection *create_client_conn(int writefd, int readfd)
{
    struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
    if (conn == NULL) return NULL;
    GUARD_PTR(s2n_connection_set_read_fd(conn, readfd));
    GUARD_PTR(s2n_connection_set_write_fd(conn, writefd));
    return conn;
}

static struct s2n_connection *create_server_conn(int writefd, int readfd)
{
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    if (conn == NULL) return NULL;
    struct s2n_config *config = s2n_create_test_server_config();
    if (config == NULL) return NULL;
    GUARD_PTR(s2n_connection_set_config(conn, config));
    GUARD_PTR(s2n_connection_set_read_fd(conn, readfd));
    GUARD_PTR(s2n_connection_set_write_fd(conn, writefd));
    return conn;
}

static int negotiate(struct s2n_connection *client, struct s2n_connection *server)
{
    int client_more = 0;
    int server_more = 0;

    do
    {
        if (client_more) {
            GUARD(s2n_negotiate(client, &client_more));
        }
        if (server_more) {
            GUARD(s2n_negotiate(server, &server_more));
        }
    } while (client_more || server_more);

    return 0;
}

int write_fully(struct s2n_connection *conn, char *buffer, int size)
{
    char *ptr = buffer;
    int wbytes, more;
    do {
        GUARD(wbytes = s2n_send(conn, ptr, size, &more));
        size -= wbytes;
        ptr += wbytes;
    } while (size);
    return 0;
}

int read_fully(struct s2n_connection *conn, char *buffer, int size)
{
    char *ptr = buffer;
    int rbytes, more;
    do {
        GUARD(rbytes = s2n_recv(conn, ptr, size, &more));
        size -= rbytes;
        ptr += rbytes;
    } while (size);
    return 0;
}

static int setup_client_server(struct s2n_connection **client, struct s2n_connection **server)
{
    int server_to_client[2];
    int client_to_server[2];
    GUARD(pipe(server_to_client));
    GUARD(pipe(client_to_server));
    notnull_check(*client = create_client_conn(client_to_server[1], server_to_client[0]));
    notnull_check(*server = create_server_conn(server_to_client[1], client_to_server[0]));
    return 0;
}

static int tear_down_client_server(struct s2n_connection *client, struct s2n_connection *server)
{
    int status;
    struct s2n_config *server_config = server->config;

    GUARD(s2n_shutdown(client, &status));
    GUARD(s2n_shutdown(server, &status));
    GUARD(s2n_connection_free(client));
    GUARD(s2n_connection_free(server));
    GUARD(s2n_config_free(server_config));
    return 0;
}

const int IO_BUFFER_SIZE = 32 * 1024;

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    /* Create a pipe */
    EXPECT_SUCCESS(s2n_init());

    char buffer[IO_BUFFER_SIZE];
    memset(buffer, 'a', sizeof(buffer));

    int max_frag_size = 2048;

    for (; max_frag_size <= 16384; max_frag_size += 1024) {

        struct s2n_connection *client, *server;
        /* Setup client / server pipe */
        EXPECT_SUCCESS(setup_client_server(&client, &server));
        /* Negotiate the handshake. */
        EXPECT_SUCCESS(negotiate(client, server));

        struct s2n_dyn_record_size_config *rec_sz_config = &server->config->dyn_record_size;
        rec_sz_config->max_fragment_size = max_frag_size;
        rec_sz_config->bytes_out_threshold = 2 * 1024 * 1024;

        int limit = 20 * 1024 * 1024;

        for (int bytes = 0; bytes < limit; bytes += IO_BUFFER_SIZE) {
            EXPECT_SUCCESS(write_fully(server, buffer, IO_BUFFER_SIZE));
            EXPECT_SUCCESS(read_fully(client, buffer, IO_BUFFER_SIZE));
            int curr_max_size = max_frag_size;
            if (bytes < rec_sz_config->bytes_out_threshold) {
                curr_max_size = S2N_DEFAULT_FRAGMENT_LENGTH;
            }
            EXPECT_EQUAL(curr_max_size, server->curr_max_fragment_size);
        }

        EXPECT_SUCCESS(tear_down_client_server(client, server));
    }

    struct s2n_connection *client, *server;
    /* Setup client / server pipe */
    EXPECT_SUCCESS(setup_client_server(&client, &server));
    /* Negotiate the handshake. */
    EXPECT_SUCCESS(negotiate(client, server));

    /* Test boundary condition with bytes_out_threshold 'N' */
    struct s2n_dyn_record_size_config *rec_sz_config = &server->config->dyn_record_size;
    rec_sz_config->max_fragment_size = S2N_TLS_MAXIMUM_FRAGMENT_LENGTH;
    rec_sz_config->bytes_out_threshold = IO_BUFFER_SIZE - 1;

    /* send(N - 1), rec size shouldn't change */
    EXPECT_SUCCESS(write_fully(server, buffer, IO_BUFFER_SIZE - 2));
    EXPECT_SUCCESS(read_fully(client, buffer, IO_BUFFER_SIZE - 2));
    EXPECT_EQUAL(S2N_DEFAULT_FRAGMENT_LENGTH, server->curr_max_fragment_size);

    /* send(N), rec sz should change in the subsequent call */
    EXPECT_SUCCESS(write_fully(server, buffer, 1));
    EXPECT_SUCCESS(read_fully(client, buffer, 1));
    EXPECT_EQUAL(S2N_DEFAULT_FRAGMENT_LENGTH, server->curr_max_fragment_size);

    /* send(N+1), this send call should adapt the rec size */
    EXPECT_SUCCESS(write_fully(server, buffer, 1));
    EXPECT_SUCCESS(read_fully(client, buffer, 1));
    EXPECT_EQUAL(S2N_TLS_MAXIMUM_FRAGMENT_LENGTH, server->curr_max_fragment_size);

    /* Test idle timer reset */
    rec_sz_config->idle_millis_threshold = 10;
    usleep(11 * 1000);
    EXPECT_SUCCESS(write_fully(server, buffer, 1));
    EXPECT_SUCCESS(read_fully(client, buffer, 1));
    /* Expect a reset now */
    EXPECT_EQUAL(S2N_DEFAULT_FRAGMENT_LENGTH, server->curr_max_fragment_size);

    END_TEST();

    return 0;
}
