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
typedef nox_err_t (*transition_fn)(struct app_state *, peer_event_t);

static nox_err_t action_cleanup(struct app_state *state, peer_event_t ev);
static nox_err_t action_connect(struct app_state *state, peer_event_t ev);
static nox_err_t action_accept(struct app_state *state, peer_event_t ev);
static nox_err_t action_hs_process(struct app_state *state, peer_event_t ev);
static nox_err_t action_tofu_prompt(struct app_state *state, peer_event_t ev);
static nox_err_t action_tofu_accept(struct app_state *state, peer_event_t ev);
static nox_err_t action_session_up(struct app_state *state, peer_event_t ev);
static nox_err_t action_file_begin(struct app_state *state, peer_event_t ev);
static nox_err_t action_file_end(struct app_state *state, peer_event_t ev);

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

nox_err_t sm_dispatch(struct app_state *state, peer_event_t event)
{
    for (size_t i = 0; i < TRANSITION_COUNT; i++) {
        const state_transition_t *t = &transitions[i];

        if (t->from != state->peer_state || t->event != event)
            continue;

        NOX_INFO(LOG_MOD_MAIN, "SM: %s + %s → %s",
                 sm_state_name(t->from),
                 sm_event_name(event),
                 sm_state_name(t->to));

        nox_err_t err = t->action(state, event);
        if (err == NOX_OK) {
            state->peer_state = t->to;
        }
        return err;
    }

    /* Geçersiz geçiş — bu state'te bu event beklenmiyordu */
    NOX_WARN(LOG_MOD_MAIN, "SM: geçersiz geçiş %s + %s — yok sayılıyor",
             sm_state_name(state->peer_state), sm_event_name(event));
    return NOX_ERR_STATE;
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
static nox_err_t action_cleanup(struct app_state *state, peer_event_t ev)
{
    (void)ev;

    /* 1. Soket temizliği */
    if (state->peer_fd >= 0) {
        epoll_remove_fd(state->epoll_fd, state->peer_fd);
        close(state->peer_fd);
        state->peer_fd = -1;
    }

    /* 2. Kriptografik state — arena restore ÖNCESİ key material'ı sıfırla */
    if (state->hs) {
        sodium_memzero(state->hs, sizeof(struct noise_handshake));
    }
    if (state->session) {
        sodium_memzero(state->session, sizeof(struct noise_session));
    }
    state->hs      = NULL;
    state->session  = NULL;
    state->tx_seq   = 0;
    state->rx_seq   = 0;

    /* 3. Peer identity — Güvenli bir şekilde sıfırla */
    sodium_memzero(state->active_peer_onion, sizeof(state->active_peer_onion));
    sodium_memzero(state->connect_target, sizeof(state->connect_target));

    /* 4. Arena — güvenli geri sarma (session allocations'ı temizle) */
    arena_restore(&state->arena, state->session_arena_mark);

    /* 5. TOFU state — Hassas verileri sıfırla */
    state->tofu_pending = false;
    state->tofu_peer_fd = -1;
    sodium_memzero(state->tofu_onion, sizeof(state->tofu_onion));
    sodium_memzero(state->tofu_name, sizeof(state->tofu_name));
    sodium_memzero(state->tofu_new_key, sizeof(state->tofu_new_key));
    state->tofu_arena_mark = 0;

    /* 6. Dosya transferleri */
    file_transfer_cleanup(state);

    /* 7. Recv buffer sıfırlama — Plaintext mesaj veya peer identity kalıntısını önlemek için tüm buffer'ı sıfırla */
    sodium_memzero(state->recv_buf, sizeof(state->recv_buf));
    state->recv_pos = 0;

    return NOX_OK;
}

/* ================================================================
 * ACTION STUBLARI — Adım 3-5'te doldurulacak
 *
 * Şimdilik NOX_OK döndürüyorlar — state geçişini onaylıyorlar.
 * Gerçek implementasyon event loop kodundan taşınacak.
 * ================================================================ */

static nox_err_t action_connect(struct app_state *state, peer_event_t ev)
{
    (void)state; (void)ev;
    /* Adım 3'te stdin_handler.c /connect kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_accept(struct app_state *state, peer_event_t ev)
{
    (void)state; (void)ev;
    /* Adım 3'te main.c accept4 kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_hs_process(struct app_state *state, peer_event_t ev)
{
    (void)state; (void)ev;
    /* Adım 3'te main.c handshake_read/write kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_tofu_prompt(struct app_state *state, peer_event_t ev)
{
    (void)state; (void)ev;
    /* Adım 4'te main.c TOFU UI kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_tofu_accept(struct app_state *state, peer_event_t ev)
{
    (void)ev;

    /* hs geçerlilik kontrolü — peer TOFU bekleme sırasında ayrılmış olabilir */
    if (!state->hs) {
        ui_print_error(state,
            "Handshake durumu geçersiz (peer ayrılmış olabilir)");
        sm_dispatch(state, EV_PEER_DISCONNECTED);
        return NOX_ERR_PROTO;
    }

    /* db_add_contact — rehbere kaydet */
    if (!state->ghost_mode) {
        nox_err_t db_err = db_add_contact(
            state->tofu_onion, state->tofu_name, state->tofu_new_key, NULL, NULL, 0);
        if (db_err != NOX_OK) {
            ui_print_error(state, "Rehbere kaydetme başarısız");
            /* devam et — session yine kurulabilir */
        }
    } else {
        NOX_INFO(LOG_MOD_MAIN, "ghost mod aktif — rehber kaydı atlandı");
    }

    /* Session oluştur */
    state->session = arena_alloc(&state->arena, sizeof(struct noise_session));
    if (!state->session) {
        ui_print_error(state, "Arena bellek hatası");
        sm_dispatch(state, EV_PEER_DISCONNECTED);
        return NOX_ERR_ALLOC;
    }

    if (handshake_split(state->hs, state->session) != NOX_OK) {
        ui_print_error(state, "session split başarısız");
        state->session = NULL;
        sm_dispatch(state, EV_PEER_DISCONNECTED);
        return NOX_ERR_PROTO;
    }

    state->hs = NULL; /* handshake tüketildi — timeout tetiklemesin */
    state->tx_seq = 0;
    state->rx_seq = 0;
    state->tofu_pending = false;
    snprintf(state->active_peer_onion, sizeof(state->active_peer_onion),
             "%s", state->tofu_onion);

    NOX_INFO(LOG_MOD_NOISE, "session kuruldu — mesajlaşma hazır");
    ui_print_system(state, "[✓] şifreli kanal kuruldu (%s)", state->tofu_name);

    /* Kuyruktaki bekleyen mesajları gönder */
    if (!state->ghost_mode) {
        db_process_queue(state->active_peer_onion, send_queued_callback, state);
    }

    return NOX_OK;
}

static nox_err_t action_session_up(struct app_state *state, peer_event_t ev)
{
    (void)state; (void)ev;
    /* Adım 4'te main.c bilinen peer session kodundan taşınacak */
    return NOX_OK;
}

static nox_err_t action_file_begin(struct app_state *state, peer_event_t ev)
{
    (void)state; (void)ev;
    /* Adım 5'te dosya transfer state geçişi */
    return NOX_OK;
}

static nox_err_t action_file_end(struct app_state *state, peer_event_t ev)
{
    (void)state; (void)ev;
    /* Adım 5'te dosya transfer tamamlanma */
    return NOX_OK;
}
