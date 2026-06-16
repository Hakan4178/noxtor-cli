/* SPDX-License-Identifier: GPL-3.0-or-later
 * state_machine.h — Peer bağlantı durum makinesi
 *
 * Tek peer bağlantısının yaşam döngüsünü yönetir:
 *   IDLE → HANDSHAKE → (TOFU_PENDING →) ACTIVE → IDLE
 *
 * Tüm state geçişleri sm_dispatch() üzerinden yapılır.
 * Geçersiz geçişler NOX_ERR_STATE ile reddedilir ve loglanır.
 *
 * Faz 6.3'te peer_state_t, peer_session struct'ına taşınarak
 * çoklu oturum desteği sağlanacaktır.
 */

#ifndef PARANOID_STATE_MACHINE_H
#define PARANOID_STATE_MACHINE_H

#include "common.h"

/* Forward declaration */
struct app_state;

/* ================================================================
 * PEER DURUMLARI
 * ================================================================ */
typedef enum {
    ST_IDLE,              /* Bağlantı yok, listener aktif               */
    ST_CONNECTING,        /* SOCKS5 bağlantısı kuruluyor (outbound)     */
    ST_HANDSHAKE_INIT,    /* Noise XX handshake başlatıcı (outbound)    */
    ST_HANDSHAKE_RESP,    /* Noise XX handshake yanıtlayıcı (inbound)  */
    ST_TOFU_PENDING,      /* Kullanıcı TOFU onayı bekliyor              */
    ST_ACTIVE,            /* Şifreli kanal aktif — mesajlaşma hazır     */
    ST_FILE_TX,           /* Dosya gönderimi devam ediyor                */
    ST_FILE_RX,           /* Dosya alımı devam ediyor                   */
    ST_COUNT              /* sentinel — dizi boyutu için                 */
} peer_state_t;

/* ================================================================
 * PEER OLAYLARI
 * ================================================================ */
typedef enum {
    EV_CONNECT_CMD,         /* /connect komutu                          */
    EV_PEER_ACCEPTED,       /* accept4() başarılı (inbound)             */
    EV_HANDSHAKE_MSG,       /* Handshake mesajı alındı                  */
    EV_HANDSHAKE_DONE,      /* Noise XX tamamlandı — TOFU gerekli       */
    EV_SESSION_READY,       /* Bilinen peer — doğrudan session kur      */
    EV_TOFU_ACCEPTED,       /* Kullanıcı 'y' dedi                      */
    EV_TOFU_REJECTED,       /* Kullanıcı 'n' dedi                      */
    EV_PEER_DISCONNECTED,   /* Soket kapandı / hata                    */
    EV_HANDSHAKE_TIMEOUT,   /* 30s timeout                              */
    EV_HANDSHAKE_ERROR,     /* Handshake okuma/yazma hatası             */
    EV_FILE_START,          /* /file komutu veya METADATA frame alındı  */
    EV_FILE_DONE,           /* Transfer tamamlandı                      */
    EV_RATE_LIMIT,          /* Rate limit aşıldı                        */
    EV_SEQ_MISMATCH,        /* Beklenmeyen sequence number              */
    EV_ARENA_FAIL,          /* Arena allocation başarısız                */
    EV_TOR_DIED,            /* Tor process öldü (SIGCHLD veya kill)     */
    EV_COUNT                /* sentinel                                  */
} peer_event_t;

/* ================================================================
 * STATE MACHINE API
 * ================================================================ */

/**
 * sm_dispatch — Olay gönder, geçiş tablosunda eşleşme ara, action çalıştır.
 *
 * @param state  Uygulama durumu (peer_state okunur/yazılır)
 * @param event  Tetiklenen olay
 * @return NOX_OK başarılıysa, NOX_ERR_STATE geçersiz geçişse
 */
nox_err_t sm_dispatch(struct app_state *state, peer_event_t event);

/**
 * sm_state_name — State enum'unu insan okunur stringe çevir (debug log).
 */
const char *sm_state_name(peer_state_t st);

/**
 * sm_event_name — Event enum'unu insan okunur stringe çevir (debug log).
 */
const char *sm_event_name(peer_event_t ev);

#endif /* PARANOID_STATE_MACHINE_H */
