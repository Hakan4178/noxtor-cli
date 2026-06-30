/* SPDX-License-Identifier: GPL-3.0-or-later
 * state_machine.c — Peer bağlantı durum makinesi implementasyonu
 *
 * Geçiş tablosu + dispatch motoru + action fonksiyonları.
 *
 * Tasarım kararları:
 *   - Tablo statik, const — derleme zamanında doğrulanabilir.
 *   - Linear search — tablo küçük (~30 entry), O(n) yeterli.
 *   - Action fonksiyonları NOX_OK dönerse state geçişi uygulanır.
 *   - Recursive dispatch desteklenir (max 1 seviye: HS → SESSION).
 */

#include "state_machine.h"
#include "arena.h"
#include "common.h"
#include "database.h"
#include "file_transfer.h"
#include "network.h"
#include "noise.h"
#include "stdin_handler.h"
#include "types.h"
#include "ui.h"

#include <string.h>
#include <time.h>
#include <unistd.h>

/* ================================================================
 * DEBUG YARDIMCILARI — state/event → string
 * ================================================================ */

static const char *const state_names[] = {
    [ST_IDLE]           = "IDLE",
    [ST_CONNECTING]     = "CONNECTING",
    [ST_HANDSHAKE_INIT] = "HANDSHAKE_INIT",
    [ST_HANDSHAKE_RESP] = "HANDSHAKE_RESP",
    [ST_TOFU_PENDING]   = "TOFU_PENDING",
    [ST_ACTIVE]         = "ACTIVE",
    [ST_FILE_TX]        = "FILE_TX",
    [ST_FILE_RX]        = "FILE_RX",
};

static const char *const event_names[] = {
    [EV_CONNECT_CMD]       = "CONNECT_CMD",
    [EV_PEER_ACCEPTED]     = "PEER_ACCEPTED",
    [EV_HANDSHAKE_MSG]     = "HANDSHAKE_MSG",
    [EV_HANDSHAKE_DONE]    = "HANDSHAKE_DONE",
    [EV_SESSION_READY]     = "SESSION_READY",
    [EV_TOFU_ACCEPTED]     = "TOFU_ACCEPTED",
    [EV_TOFU_REJECTED]     = "TOFU_REJECTED",
    [EV_PEER_DISCONNECTED] = "PEER_DISCONNECTED",
    [EV_HANDSHAKE_TIMEOUT] = "HANDSHAKE_TIMEOUT",
    [EV_HANDSHAKE_ERROR]   = "HANDSHAKE_ERROR",
    [EV_FILE_START]        = "FILE_START",
    [EV_FILE_DONE]         = "FILE_DONE",
    [EV_RATE_LIMIT]        = "RATE_LIMIT",
    [EV_SEQ_MISMATCH]      = "SEQ_MISMATCH",
    [EV_ARENA_FAIL]        = "ARENA_FAIL",
    [EV_TOR_DIED]          = "TOR_DIED",
};

const char *sm_state_name(peer_state_t st)
{
    if ((unsigned)st < ST_COUNT)
        return state_names[st];
    return "UNKNOWN";
}

const char *sm_event_name(peer_event_t ev)
{
    if ((unsigned)ev < EV_COUNT)
        return event_names[ev];
    return "UNKNOWN";
}

/* ================================================================
 * ACTION FONKSİYONLARI
 * ================================================================ */

/* İleri bildirimler */
typedef nox_err_t (*transition_fn)(struct peer_session *, struct app_state *,
                                   peer_event_t);

static nox_err_t action_cleanup(struct peer_session *ps, struct app_state *state,
                                peer_event_t ev);
static nox_err_t action_connect(struct peer_session *ps, struct app_state *state,
                                peer_event_t ev);
static nox_err_t action_accept(struct peer_session *ps, struct app_state *state,
                               peer_event_t ev);
static nox_err_t action_hs_process(struct peer_session *ps, struct app_state *state,
                                   peer_event_t ev);
static nox_err_t action_tofu_prompt(struct peer_session *ps, struct app_state *state,
                                    peer_event_t ev);
static nox_err_t action_tofu_accept(struct peer_session *ps, struct app_state *state,
                                    peer_event_t ev);
static nox_err_t action_session_up(struct peer_session *ps, struct app_state *state,
                                   peer_event_t ev);
static nox_err_t action_file_begin(struct peer_session *ps, struct app_state *state,
                                   peer_event_t ev);
static nox_err_t action_file_end(struct peer_session *ps, struct app_state *state,
                                 peer_event_t ev);

/* ================================================================
 * GEÇİŞ TABLOSU
 *
 * {mevcut_state, olay, hedef_state, action_fonksiyonu}
 *
 * Linear search ile eşleşme aranır.
 * İlk eşleşme kullanılır — sıralama önemli.
 * ================================================================ */

typedef struct {
    peer_state_t  from;
    peer_event_t  event;
    peer_state_t  to;
    transition_fn action;
} state_transition_t;

static const state_transition_t transitions[] = {
/*  FROM               EVENT                  TO                 ACTION              */

/* ── IDLE → Bağlantı Başlangıcı ────────────────────────────────── */
  { ST_IDLE,           EV_CONNECT_CMD,        ST_HANDSHAKE_INIT, action_connect      },
  { ST_IDLE,           EV_PEER_ACCEPTED,      ST_HANDSHAKE_RESP, action_accept       },

/* ── HANDSHAKE → Mesaj İşleme (state değişmez, msg_index artar) ── */
  { ST_HANDSHAKE_INIT, EV_HANDSHAKE_MSG,      ST_HANDSHAKE_INIT, action_hs_process   },
  { ST_HANDSHAKE_RESP, EV_HANDSHAKE_MSG,      ST_HANDSHAKE_RESP, action_hs_process   },

/* ── HANDSHAKE → Tamamlanma ─────────────────────────────────────── */
  { ST_HANDSHAKE_INIT, EV_SESSION_READY,      ST_ACTIVE,         action_session_up   },
  { ST_HANDSHAKE_RESP, EV_SESSION_READY,      ST_ACTIVE,         action_session_up   },
  { ST_HANDSHAKE_INIT, EV_HANDSHAKE_DONE,     ST_TOFU_PENDING,   action_tofu_prompt  },
  { ST_HANDSHAKE_RESP, EV_HANDSHAKE_DONE,     ST_TOFU_PENDING,   action_tofu_prompt  },

/* ── TOFU → Karar ──────────────────────────────────────────────── */
  { ST_TOFU_PENDING,   EV_TOFU_ACCEPTED,      ST_ACTIVE,         action_tofu_accept  },
  { ST_TOFU_PENDING,   EV_TOFU_REJECTED,      ST_IDLE,           action_cleanup      },

/* ── ACTIVE → Dosya Transfer ───────────────────────────────────── */
  { ST_ACTIVE,         EV_FILE_START,          ST_FILE_TX,        action_file_begin   },
  { ST_FILE_TX,        EV_FILE_DONE,           ST_ACTIVE,         action_file_end     },

/* ── Her Durumdan Disconnect ───────────────────────────────────── */
  { ST_CONNECTING,     EV_PEER_DISCONNECTED,   ST_IDLE,           action_cleanup      },
  { ST_HANDSHAKE_INIT, EV_PEER_DISCONNECTED,   ST_IDLE,           action_cleanup      },
  { ST_HANDSHAKE_RESP, EV_PEER_DISCONNECTED,   ST_IDLE,           action_cleanup      },
  { ST_TOFU_PENDING,   EV_PEER_DISCONNECTED,   ST_IDLE,           action_cleanup      },
  { ST_ACTIVE,         EV_PEER_DISCONNECTED,   ST_IDLE,           action_cleanup      },
  { ST_FILE_TX,        EV_PEER_DISCONNECTED,   ST_IDLE,           action_cleanup      },
  { ST_FILE_RX,        EV_PEER_DISCONNECTED,   ST_IDLE,           action_cleanup      },

/* ── Handshake Timeout ─────────────────────────────────────────── */
  { ST_HANDSHAKE_INIT, EV_HANDSHAKE_TIMEOUT,   ST_IDLE,           action_cleanup      },
  { ST_HANDSHAKE_RESP, EV_HANDSHAKE_TIMEOUT,   ST_IDLE,           action_cleanup      },

/* ── Handshake Error ───────────────────────────────────────────── */
  { ST_HANDSHAKE_INIT, EV_HANDSHAKE_ERROR,     ST_IDLE,           action_cleanup      },
  { ST_HANDSHAKE_RESP, EV_HANDSHAKE_ERROR,     ST_IDLE,           action_cleanup      },

/* ── Sequence Mismatch ─────────────────────────────────────────── */
  { ST_ACTIVE,         EV_SEQ_MISMATCH,        ST_IDLE,           action_cleanup      },
  { ST_FILE_TX,        EV_SEQ_MISMATCH,        ST_IDLE,           action_cleanup      },
  { ST_FILE_RX,        EV_SEQ_MISMATCH,        ST_IDLE,           action_cleanup      },

/* ── Arena Fail ────────────────────────────────────────────────── */
  { ST_HANDSHAKE_INIT, EV_ARENA_FAIL,          ST_IDLE,           action_cleanup      },
  { ST_HANDSHAKE_RESP, EV_ARENA_FAIL,          ST_IDLE,           action_cleanup      },

/* ── Tor Died — Her durumdan idle'e ──────────────────────────────── */
  { ST_IDLE,             EV_TOR_DIED,           ST_IDLE,           action_cleanup      },
  { ST_CONNECTING,       EV_TOR_DIED,           ST_IDLE,           action_cleanup      },
  { ST_HANDSHAKE_INIT,   EV_TOR_DIED,           ST_IDLE,           action_cleanup      },
  { ST_HANDSHAKE_RESP,   EV_TOR_DIED,           ST_IDLE,           action_cleanup      },
  { ST_TOFU_PENDING,     EV_TOR_DIED,           ST_IDLE,           action_cleanup      },
  { ST_ACTIVE,           EV_TOR_DIED,           ST_IDLE,           action_cleanup      },
  { ST_FILE_TX,          EV_TOR_DIED,           ST_IDLE,           action_cleanup      },
  { ST_FILE_RX,          EV_TOR_DIED,           ST_IDLE,           action_cleanup      },

/* ── Rate Limit ────────────────────────────────────────────────── */
  { ST_HANDSHAKE_INIT, EV_RATE_LIMIT,          ST_IDLE,           action_cleanup      },
  { ST_HANDSHAKE_RESP, EV_RATE_LIMIT,          ST_IDLE,           action_cleanup      },
};

#define TRANSITION_COUNT (sizeof(transitions) / sizeof(transitions[0]))

/* ================================================================
 * DISPATCH MOTORU
 * ================================================================ */

nox_err_t sm_dispatch(struct peer_session *ps, struct app_state *state,
                      peer_event_t event)
{
    for (size_t i = 0; i < TRANSITION_COUNT; i++) {
        const state_transition_t *t = &transitions[i];

        if (t->from != ps->state || t->event != event)
            continue;

        NOX_INFO(LOG_MOD_MAIN, "SM: %s + %s → %s",
                 sm_state_name(t->from),
                 sm_event_name(event),
                 sm_state_name(t->to));

        nox_err_t err = t->action(ps, state, event);
        if (err == NOX_OK) {
            ps->state = t->to;
        }
        return err;
    }

    /* Geçersiz geçiş — bu state'te bu event beklenmiyordu */
    NOX_WARN(LOG_MOD_MAIN, "SM: geçersiz geçiş %s + %s — yok sayılıyor",
             sm_state_name(ps->state), sm_event_name(event));
    return NOX_ERR_STATE;
}

nox_err_t sm_dispatch_active(struct app_state *state, peer_event_t event)
{
    struct peer_session *ps = ACTIVE_PEER(state);
    if (!ps)
        return NOX_ERR_NOT_FOUND;
    return sm_dispatch(ps, state, event);
}

/* ================================================================
 * ACTION: CLEANUP — Merkezi temizlik
 *
 * Tüm peer state'ini sıfırlar. Herhangi bir hata / disconnect /
 * timeout / reject durumunda çağrılır.
 *
 * Bu fonksiyon, refactör öncesinde 18 farklı yerde tekrarlanan
 * cleanup kodunun tek noktasıdır.
 * ================================================================ */
static nox_err_t action_cleanup(struct peer_session *ps, struct app_state *state,
                                peer_event_t ev)
{
    (void)ev;

    /* 1. Soket temizliği */
    if (ps->fd >= 0) {
        epoll_remove_fd(state->epoll_fd, ps->fd);
        close(ps->fd);
        ps->fd = -1;
    }

    /* 2. Kriptografik state — key material'ı sıfırla ve serbest bırak */
    if (ps->hs) {
        sodium_memzero(ps->hs, sizeof(struct noise_handshake));
        sodium_free(ps->hs);
    }
    if (ps->session) {
        sodium_memzero(ps->session, sizeof(struct noise_session));
        sodium_free(ps->session);
    }
    ps->hs      = NULL;
    ps->session  = NULL;
    ps->tx_seq   = 0;
    ps->rx_seq   = 0;

    /* 3. Peer identity — Güvenli bir şekilde sıfırla */
    sodium_memzero(ps->peer_onion, sizeof(ps->peer_onion));
    sodium_memzero(ps->connect_target, sizeof(ps->connect_target));

    /* 4. TOFU state — Hassas verileri sıfırla */
    ps->tofu_pending = false;
    ps->tofu_peer_fd = -1;
    sodium_memzero(ps->tofu_onion, sizeof(ps->tofu_onion));
    sodium_memzero(ps->tofu_name, sizeof(ps->tofu_name));
    sodium_memzero(ps->tofu_new_key, sizeof(ps->tofu_new_key));

    /* 5. Dosya transferleri — peer'a özel state */
    ps->queue_flushed = false;
    if (ps->rx_file.active) {
        if (ps->rx_file.fd >= 0)
            close(ps->rx_file.fd);
        if (state->downloads_dir_fd >= 0 && ps->rx_file.local_name[0] != '\0')
            unlinkat(state->downloads_dir_fd, ps->rx_file.local_name, 0);
        sodium_memzero(&ps->rx_file, sizeof(ps->rx_file));
        ps->rx_file.fd = -1;
    }
    if (ps->tx_file.active) {
        if (ps->tx_file.fd >= 0)
            close(ps->tx_file.fd);
        if (ps->tx_file.plain_buf)
            sodium_free(ps->tx_file.plain_buf);
        sodium_memzero(&ps->tx_file, sizeof(ps->tx_file));
        ps->tx_file.fd = -1;
    }

    /* 6. Recv buffer sıfırlama */
    sodium_memzero(ps->recv_buf, sizeof(ps->recv_buf));
    ps->recv_pos = 0;

    /* 7. Peer identity — name ve unread_count */
    sodium_memzero(ps->name, sizeof(ps->name));
    ps->unread_count = 0;

    /* 8. Aktif peer index — eğer bu peer aktifse sıfırla */
    if (state->active_peer_idx >= 0 &&
        (unsigned)state->active_peer_idx < NOX_MAX_PEERS &&
        &state->peers[state->active_peer_idx] == ps) {
        state->active_peer_idx = -1;
        sodium_memzero(state->active_peer_onion, sizeof(state->active_peer_onion));
    }

    return NOX_OK;
}

/* ================================================================
 * ACTION STUBLARI — Adım 3-5'te doldurulacak
 *
 * Şimdilik NOX_OK döndürüyorlar — state geçişini onaylıyorlar.
 * Gerçek implementasyon event loop kodundan taşınacak.
 * ================================================================ */

static nox_err_t action_connect(struct peer_session *ps, struct app_state *state,
                                peer_event_t ev)
{
    (void)ps; (void)state; (void)ev;
    /* Adım 3'te stdin_handler.c /connect kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_accept(struct peer_session *ps, struct app_state *state,
                               peer_event_t ev)
{
    (void)ps; (void)state; (void)ev;
    /* Adım 3'te main.c accept4 kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_hs_process(struct peer_session *ps, struct app_state *state,
                                   peer_event_t ev)
{
    (void)ps; (void)state; (void)ev;
    /* Adım 3'te main.c handshake_read/write kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_tofu_prompt(struct peer_session *ps, struct app_state *state,
                                    peer_event_t ev)
{
    (void)ps; (void)state; (void)ev;
    /* Adım 4'te main.c TOFU UI kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_tofu_accept(struct peer_session *ps, struct app_state *state,
                                    peer_event_t ev)
{
    (void)ev;

    /* hs geçerlilik kontrolü — peer TOFU bekleme sırasında ayrılmış olabilir */
    if (!ps->hs) {
        ui_print_error(state,
            "Handshake durumu geçersiz (peer ayrılmış olabilir)");
        return NOX_ERR_PROTO;
    }

    /* db_add_contact — rehbere kaydet */
    if (!state->ghost_mode) {
        nox_err_t db_err = db_add_contact(
            ps->tofu_onion, ps->tofu_name, ps->tofu_new_key);
        if (db_err != NOX_OK) {
            ui_print_error(state, "Rehbere kaydetme başarısız");
            /* devam et — session yine kurulabilir */
        }
    } else {
        NOX_INFO(LOG_MOD_MAIN, "ghost mod aktif — rehber kaydı atlandı");
    }

    /* Session oluştur */
    ps->session = sodium_malloc(sizeof(struct noise_session));
    if (!ps->session) {
        ui_print_error(state, "Arena bellek hatası");
        sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
        return NOX_ERR_ALLOC;
    }

    if (handshake_split(ps->hs, ps->session) != NOX_OK) {
        ui_print_error(state, "session split başarısız");
        ps->session = NULL;
        sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
        return NOX_ERR_PROTO;
    }

    sodium_free(ps->hs);
    ps->hs = NULL; /* handshake tüketildi — timeout tetiklemesin */
    ps->tx_seq = 0;
    ps->rx_seq = 0;
    ps->queue_flushed = false;
    NOX_DEBUG(LOG_MOD_NOISE,
              "session setup (TOFU): tx_seq=0 rx_seq=0 queue_flushed=false");
    ps->tofu_pending = false;

    /* Peer kimliğini ata */
    snprintf(ps->peer_onion, sizeof(ps->peer_onion), "%s", ps->tofu_onion);
    strncpy(ps->name, ps->tofu_name, NOX_CONTACT_NAME_LEN);
    ps->name[NOX_CONTACT_NAME_LEN] = '\0';
    strncpy(state->active_peer_onion, ps->peer_onion, NOX_ONION_LEN);
    state->active_peer_onion[NOX_ONION_LEN] = '\0';

    NOX_INFO(LOG_MOD_NOISE, "session kuruldu — mesajlaşma hazır");
    ui_print_system(state, "[✓] şifreli kanal kuruldu (%s)", ps->tofu_name);
    ui_reset_sender();

    return NOX_OK;
}

static nox_err_t action_session_up(struct peer_session *ps, struct app_state *state,
                                   peer_event_t ev)
{
    (void)ps; (void)state; (void)ev;
    /* Adım 4'te main.c bilinen peer session kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_file_begin(struct peer_session *ps, struct app_state *state,
                                   peer_event_t ev)
{
    (void)ps; (void)state; (void)ev;
    /* Adım 5'te dosya transfer state geçişi */
    return NOX_OK;
}

static nox_err_t action_file_end(struct peer_session *ps, struct app_state *state,
                                 peer_event_t ev)
{
    (void)ps; (void)state; (void)ev;
    /* Adım 5'te dosya transfer tamamlanma */
    return NOX_OK;
}
