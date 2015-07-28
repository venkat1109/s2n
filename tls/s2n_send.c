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

#include <errno.h>
#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_record.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_cipher.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_flush(struct s2n_connection *conn, int *more)
{
    int w;

    *more = 1;

    /* Write any data that's already pending */
  WRITE:
    while (s2n_stuffer_data_available(&conn->out)) {
        w = s2n_stuffer_send_to_fd(&conn->out, conn->writefd, s2n_stuffer_data_available(&conn->out));
        if (w < 0) {
            return -1;
        }
        conn->wire_bytes_out += w;
    }
    if (conn->closing) {
        conn->closed = 1;
        GUARD(s2n_connection_wipe(conn));
    }
    GUARD(s2n_stuffer_rewrite(&conn->out));
    /* prepare stuffer for next write */
    GUARD(s2n_stuffer_wipe(&conn->out));


    /* If there's an alert pending out, send that */
    if (s2n_stuffer_data_available(&conn->reader_alert_out) == 2) {
        struct s2n_blob alert;
        alert.data = conn->reader_alert_out.blob.data;
        alert.size = 2;
        GUARD(s2n_record_write(conn, TLS_ALERT, &alert));
        GUARD(s2n_stuffer_rewrite(&conn->reader_alert_out));
        conn->closing = 1;

        /* Actually write it ... */
        goto WRITE;
    }

    /* Do the same for writer driven alerts */
    if (s2n_stuffer_data_available(&conn->writer_alert_out) == 2) {
        struct s2n_blob alert;
        alert.data = conn->writer_alert_out.blob.data;
        alert.size = 2;
        GUARD(s2n_record_write(conn, TLS_ALERT, &alert));
        GUARD(s2n_stuffer_rewrite(&conn->writer_alert_out));
        conn->closing = 1;

        /* Actually write it ... */
        goto WRITE;
    }

    *more = 0;

    return 0;
}

/*
 * Dynamically adjust the record size for latency / throughput.The dynamic adjustment
 * is based on three parameters (bytes_out, idle_time, max_fragment_size). When the
 * connection initially starts, we optimize for latency by using a small record size,
 * usually (Ethernet MTU - IP/TCP overhead). As the connection progresses and bytes_out
 * goes beyond a threshold, we switch to a bigger record size, which is capped by
 * max_fragment_size param for high throughput. During the steady state, if the connection
 * becomes idle for beyond idle_millis_threshold, the record size will go back to the
 * initial size. This is to account for tcp slow start restarts.
 */
int adjust_record_size_if_needed(struct s2n_connection *conn)
{
    uint16_t curr_fragment_size = conn->curr_max_fragment_size;
    uint16_t new_fragment_size = curr_fragment_size;
    uint32_t bytes_out = conn->dyn_record_sz_bytes_out;
    struct s2n_dyn_record_size_config *config = &conn->config->dyn_record_size;

    uint64_t elapsed_nanos = 0;

    if (curr_fragment_size == config->max_fragment_size) {
        /*
         * Shrink the max fragment size if the connection has been
         * idle for a while. TCP Slow Start Restart shrinks the cwnd
         * after long idle periods.
         */
        s2n_timer_reset(&conn->write_idle_timer, &elapsed_nanos);
        uint32_t elapsed_millis = elapsed_nanos / 1000000;
        if (elapsed_millis >= config->idle_millis_threshold) {
            new_fragment_size = S2N_DEFAULT_FRAGMENT_LENGTH;
            conn->dyn_record_sz_bytes_out = 0;
        }
    } else if (bytes_out >= config->bytes_out_threshold) {
        /*
         * Enough bytes have been transferred out for the cwnd
         * to grow beyond max_fragment_size. Increase the max
         * fragment size to optimize for throughput
         */
        new_fragment_size = config->max_fragment_size;
        s2n_timer_reset(&conn->write_idle_timer, &elapsed_nanos);
    }

    if (new_fragment_size != curr_fragment_size) {
        uint32_t new_blob_size = s2n_tls_record_length(new_fragment_size);
        if (s2n_stuffer_resize(&conn->out, new_blob_size) < 0) {
            if (s2n_errno == S2N_ERR_REALLOC) {
                /*
                 * If realloc() fails, we don't want to
                 * bail this connection. Dynamic record
                 * sizing is best effort.
                 */
                return 0;
            }
            return -1;
        }
        conn->curr_max_fragment_size = new_fragment_size;
    }

    return 0;
}

ssize_t s2n_send(struct s2n_connection *conn, void *buf, ssize_t size, int *more)
{
    struct s2n_blob in = {.data = buf };
    ssize_t bytes_written = 0;
    int max_payload_size;
    int w;

    if (conn->closed) {
        S2N_ERROR(S2N_ERR_CLOSED);
    }

    /* Flush any pending I/O */
    GUARD(s2n_flush(conn, more));

    *more = 1;

    GUARD(adjust_record_size_if_needed(conn));

    GUARD((max_payload_size = s2n_record_max_write_payload_size(conn)));

    /* TLS 1.0 and SSLv3 are vulnerable to the so-called Beast attack. Work
     * around this by splitting messages into one byte records, and then
     * the remainder can follow as usual.
     */
    int cbcHackUsed = 0;

    /* Now write the data we were asked to send this round */
    while (size) {
        in.size = size;
        if (in.size > max_payload_size) {
            in.size = max_payload_size;
        }

        if (conn->actual_protocol_version < S2N_TLS11 && conn->active.cipher_suite->cipher->type == S2N_CBC) {
            if (in.size > 1 && cbcHackUsed == 0) {
                in.size = 1;
                cbcHackUsed = 1;
            }
        }

        /* Write and encrypt the record */
        GUARD(s2n_stuffer_rewrite(&conn->out));
        GUARD(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        bytes_written += in.size;
        conn->dyn_record_sz_bytes_out += in.size;

        /* Send it */
        while (s2n_stuffer_data_available(&conn->out)) {
            errno = 0;
            w = s2n_stuffer_send_to_fd(&conn->out, conn->writefd, s2n_stuffer_data_available(&conn->out));
            if (w < 0) {
                if (errno == EWOULDBLOCK) {
                    return bytes_written;
                }
                return -1;
            }
            conn->wire_bytes_out += w;
        }

        in.data += in.size;
        size -= in.size;
    }

    *more = 0;

    return bytes_written;
}
