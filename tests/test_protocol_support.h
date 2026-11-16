/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_protocol_support.h — proje tipleriyle çalışan ortak test helper'ları
 *
 * Noise handshake çifti, cipher session, wire frame okuma ve app_state
 * fixture sıfırlama burada. Yalnız test binary'lerine dahil edilir;
 * `static inline` sayesinde ek nesne/link kuralı gerekmez.
 *
 * Saf POSIX yardımcılar (read_exact, ts_of, seccomp runner) için
 * test_support.h kullanılır.
 */
#ifndef NOX_TEST_PROTOCOL_SUPPORT_H
#define NOX_TEST_PROTOCOL_SUPPORT_H

#include "types.h"
#include "network.h"
#include "noise.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>

#include "test_support.h"

/* Determinist test cipher session'ı: tx/rx aynı anahtar ve nonce. */
static inline void nox_test_init_cipher_session(struct noise_session *session,
                                                uint64_t n)
{
    memset(session, 0, sizeof(*session));
    memset(session->tx.k, 0x42, NOX_KEY_LEN);
    memset(session->rx.k, 0x42, NOX_KEY_LEN);
    session->tx.n = n;
    session->rx.n = n;
    session->tx.has_key = true;
    session->rx.has_key = true;
}

/* Wire'dan 13B header + ct oku; decode sınırlarını uygular. */
static inline int nox_test_read_frame(int fd, struct frame_header *fh,
                                      uint8_t *wire, uint8_t *ct)
{
    if (nox_test_read_exact(fd, wire, FRAME_HEADER_WIRE_SIZE) != 0)
        return -1;
    if (frame_header_decode(wire, fh) != NOX_OK)
        return -1;
    if (fh->len > NOX_MAX_MSG_LEN + NOX_MAC_LEN)
        return -1;
    return nox_test_read_exact(fd, ct, fh->len);
}

/* Loopback Noise XX: initiator stack, responder sodium_malloc. Split
 * her handshake'i tüketir (zeroize) — iki complete handshake ister. */
static inline int nox_test_make_split_pair(struct noise_session *sess_i,
                                           struct noise_session *sess_r)
{
    uint8_t i_priv[NOX_KEY_LEN], i_pub[NOX_KEY_LEN];
    uint8_t r_priv[NOX_KEY_LEN], r_pub[NOX_KEY_LEN];
    crypto_box_curve25519xsalsa20poly1305_keypair(i_pub, i_priv);
    crypto_box_curve25519xsalsa20poly1305_keypair(r_pub, r_priv);

    struct noise_handshake hs_i;
    struct noise_handshake *hs_r = sodium_malloc(sizeof(*hs_r));
    if (!hs_r) return -1;

    if (handshake_init(&hs_i, true, i_priv, i_pub) != NOX_OK ||
        handshake_init(hs_r, false, r_priv, r_pub) != NOX_OK) {
        sodium_free(hs_r);
        return -1;
    }

    uint8_t msg[NOISE_MAX_HANDSHAKE_LEN], pl[64];
    size_t len, pl_len;
    nox_err_t err = NOX_OK;

    len = sizeof(msg);
    if (handshake_write(&hs_i, NULL, 0, msg, &len) == NOX_OK) {
        pl_len = sizeof(pl);
        if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) == NOX_OK) {
            len = sizeof(msg);
            if (handshake_write(hs_r, NULL, 0, msg, &len) == NOX_OK) {
                pl_len = sizeof(pl);
                if (handshake_read(&hs_i, msg, len, pl, sizeof(pl), &pl_len) == NOX_OK) {
                    len = sizeof(msg);
                    if (handshake_write(&hs_i, NULL, 0, msg, &len) == NOX_OK) {
                        pl_len = sizeof(pl);
                        if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) != NOX_OK)
                            err = NOX_ERR_CRYPTO;
                    } else err = NOX_ERR_CRYPTO;
                } else err = NOX_ERR_CRYPTO;
            } else err = NOX_ERR_CRYPTO;
        } else err = NOX_ERR_CRYPTO;
    } else err = NOX_ERR_CRYPTO;

    if (err == NOX_OK &&
        (!handshake_is_complete(&hs_i) || !handshake_is_complete(hs_r)))
        err = NOX_ERR_CRYPTO;

    if (err == NOX_OK)
        err = handshake_split(&hs_i, sess_i);   /* initiator → sender */
    if (err == NOX_OK)
        err = handshake_split(hs_r, sess_r);    /* responder → receiver */

    sodium_free(hs_r);
    return err == NOX_OK ? 0 : -1;
}

/* app_state'i güvenli başlangıç değerlerine döndür. */
static inline void nox_test_fixture_reset(struct app_state *app)
{
    memset(app, 0, sizeof(*app));
    app->active_peer_idx  = -1;
    app->epoll_fd         = -1;
    app->downloads_dir_fd = -1;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++)
        app->peers[i].fd = -1;
}

/* Frame-queue fixture teardown: peer fd → rx fd → epoll fd sırası
 * korunur; ardından app_state zeroize edilir. */
static inline void nox_test_frame_fixture_teardown(struct app_state *app,
                                                   int *rx_fd, int *epfd)
{
    struct peer_session *ps = &app->peers[0];

    if (ps->fd >= 0) {
        close(ps->fd);
        ps->fd = -1;
    }
    if (*rx_fd >= 0) {
        close(*rx_fd);
        *rx_fd = -1;
    }
    if (*epfd >= 0) {
        close(*epfd);
        *epfd = -1;
    }
    sodium_memzero(app, sizeof(*app));
}

#endif /* NOX_TEST_PROTOCOL_SUPPORT_H */
