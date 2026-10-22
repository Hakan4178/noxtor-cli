/* SPDX-License-Identifier: GPL-3.0-or-later
 * event_loop.c — noxtor-cli epoll tabanlı olay döngüsü
 */

#include "event_loop.h"
#include "arena.h"
#include "common.h"
#include "crypto.h"
#include "landlock_sandbox.h"
#include "seccomp_policy.h"
#include "frontend.h"
#include "tui.h"
#include "state_machine.h"
#include "stdin_handler.h"
#include "file_transfer.h"
#include "database.h"
#include "noise.h"
#include "network.h"

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <sodium.h>

/* ================================================================
 * PEER ARAMA YARDIMCILARI
 *
 * fd → peer_session eşlemesi: epoll'taki data.fd integer'ını
 * peer_session struct'ındaki fd veya listen_fd alanlarıyla eşleştirir.
 * ================================================================ */
/* UNIT TEST ERİŞİMİ (test_event_frames): saf arama — davranış kilitleri. */
struct peer_session *find_peer_by_fd(struct app_state *state, int fd)
{
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        struct peer_session *ps = &state->peers[i];
        if (ps->fd == fd)
            return ps;
    }
    return NULL;
}

/* K-10: doluluk kararı yalnız tamponun gerçek durumundan verilir.
 * `recv_pos >= capacity` savunmacı: bozulmuş bir konum da "dolu" sayılır. */
bool peer_recv_buf_full(const struct peer_session *ps)
{
    return ps && ps->recv_pos >= sizeof(ps->recv_buf);
}

/* ================================================================
 * H-1/H-2: HANDSHAKE CLAIM PAYLOAD v1 — [ver | onion | sig]
 *
 * Her iki rol de msg2/msg3 payload'ına kendi claim'ini koyar:
 * responder msg2'de (initiator bunu okuyup verify eder),
 * initiator msg3'te (responder bunu okuyup verify eder).
 *
 * sig = Ed25519_Sign(onion_seed, "noxtor-bind-v1" || onion || my_static_pub)
 * Verify eden taraf pubkey'i onion ADRESİNDEN çıkarır — self-asserted
 * claim kriptografik olarak onion kimliğine bağlanır (H-1) ve adres
 * checksum'ı zorunlu olur (H-2).
 *
 * Kapasite: 127B payload msg2'yi 223B'ye, msg3'ü 191B'ye çıkarır —
 * NOISE_MAX_HANDSHAKE_LEN (256) içine derleme zamanında sığmalı.
 * ================================================================ */
NOX_STATIC_ASSERT(32 + 48 + NOX_HS_PAYLOAD_V1_LEN + NOX_MAC_LEN <=
                      NOISE_MAX_HANDSHAKE_LEN,
                  "msg2 (e||enc(s)||enc(payload)) 256B'ye sığmalı");
NOX_STATIC_ASSERT(48 + NOX_HS_PAYLOAD_V1_LEN + NOX_MAC_LEN <=
                      NOISE_MAX_HANDSHAKE_LEN,
                  "msg3 (enc(s)||enc(payload)) 256B'ye sığmalı");

/* UNIT TEST ERİŞİMİ (test_event_frames): claim format/signature kilidi. */
nox_err_t hs_build_claim_payload(uint8_t pl[NOX_HS_PAYLOAD_V1_LEN],
                                 const struct app_state *state)
{
    if (!pl || !state)
        return NOX_ERR_CRYPTO;
    /* seed veya static pub yoksa imzalanamaz — fail-closed
     * (örn. Tor-death sonrası; handshake_init return kontrolü de
     * bu yolu kapatır) */
    if (!state->my_onion_seed || !state->my_static_pub)
        return NOX_ERR_STATE;

    uint8_t sig[crypto_sign_BYTES];
    nox_err_t err = crypto_onion_sign(sig, state->onion_addr,
                                      state->my_static_pub,
                                      state->my_onion_seed);
    if (err != NOX_OK) {
        sodium_memzero(sig, sizeof(sig));
        return err;
    }

    pl[0] = NOX_HS_PAYLOAD_V1_VER;
    memcpy(pl + 1, state->onion_addr, NOX_ONION_LEN);
    memcpy(pl + 1 + NOX_ONION_LEN, sig, sizeof(sig));
    sodium_memzero(sig, sizeof(sig));
    return NOX_OK;
}

/* ================================================================
 * Adım 13: peer claim'ini TOFU/session'a girmeden doğrula.
 *
 * Initiator msg2'yi okur okumaz (msg3 YAZMADAN) bu yardımcıyı çağırır;
 * responder msg3'ü okuduktan sonra aynı yardımcıyı kullanır. Başarıda
 * NUL-terminated onion adresi `out`a kopyalanır ve bir daha verify
 * edilmez. Hata log/UI burada üretilir; çağıran yalnız
 * EV_HANDSHAKE_ERROR dispatch edip payload'ı serbest bırakır.
 * ================================================================ */
static nox_err_t verify_peer_claim(const struct peer_session *ps,
                                   struct app_state *state,
                                   const uint8_t *pl, size_t pl_len,
                                   char out[NOX_ONION_LEN + 1])
{
    if (!ps || !ps->hs || !pl || !out)
        return NOX_ERR_PROTO;

    /* H-1/H-2 HARD CUT: yalnızca v1 [ver|onion(62)|sig(64)] = 127B.
     * Legacy (56+NUL / 63B) payload'ın HİÇBİR kod yolu yok — beta
     * kararı: eski peer temiz disconnect alır. */
    if (pl_len != NOX_HS_PAYLOAD_V1_LEN ||
        pl[0] != NOX_HS_PAYLOAD_V1_VER) {
        NOX_ERROR(LOG_MOD_NOISE,
                  "Handshake payload geçersiz veya desteklenmeyen sürüm "
                  "(len=%zu, beklenen %u)", pl_len, NOX_HS_PAYLOAD_V1_LEN);
        if (state)
            ui_print_error(state,
                           "Akran geçerli bir adres iletmedi (sürüm uyuşmuyor)");
        return NOX_ERR_PROTO;
    }

    char peer_onion[NOX_ONION_LEN + 1];
    memcpy(peer_onion, pl + 1, NOX_ONION_LEN);
    peer_onion[NOX_ONION_LEN] = '\0';

    /* Terminal injection koruması — base32 charset dışı karakter engeli */
    if (!validate_onion_address(peer_onion)) {
        NOX_ERROR(LOG_MOD_NOISE, "Geçersiz onion adresi formatı (injection?)");
        return NOX_ERR_PROTO;
    }

    /* H-1: claim ↔ onion ↔ static key imza doğrulaması.
     * pubkey onion ADRESİNDEN çıkarılır (checksum dahil, H-2);
     * imza peer'ın hs->rs statik anahtarı üzerinden verify edilir.
     * Başarısız → impersonation/MITM reddi, peer'a sıfır bilgi. */
    if (crypto_onion_verify(pl + 1 + NOX_ONION_LEN, peer_onion,
                            ps->hs->rs) != NOX_OK) {
        NOX_ERROR(LOG_MOD_NOISE,
                  "H-1: claim imzası doğrulanamadı — reddedildi (%.63s)",
                  peer_onion);
        if (state)
            ui_print_error(state,
                           "Peer kimlik doğrulaması başarısız — bağlantı reddedildi");
        return NOX_ERR_CRYPTO;
    }

    /* H-1: OUTBOUND — dial hedefi ile claim birebir aynı OLMALI.
     * Tor zaten dial edilen onion'un key'ini transport'ta doğruladı;
     * burada sadece claim'in o hedefle tutarlılığını garantiliyoruz.
     * Inbound'da connect_target boş → atlanır (imza yeterli). */
    if (ps->connect_target[0] != '\0' &&
        strcmp(peer_onion, ps->connect_target) != 0) {
        NOX_ERROR(LOG_MOD_NOISE,
                  "H-1: ONION MISMATCH (MITM) — dial=%.63s claim=%.63s",
                  ps->connect_target, peer_onion);
        if (state)
            ui_print_error(state,
                "BAĞLANTI REDDEDİLDİ: onion adresi uyuşmuyor (MITM riski)");
        return NOX_ERR_STATE;
    }

    memcpy(out, peer_onion, sizeof(peer_onion));
    return NOX_OK;
}

/* ================================================================
 * H2/H3: RX PLAINTEXT TAMPONU
 *
 * Peer başına tek tampon. Sahibi peer_session'dır; serbest bırakma
 * yalnızca action_cleanup'ta yapılır. TEXT ve FILE çözümü aynı
 * tamponu kullanır. Kural: kullan → sıfırla → dispatch.
 * ================================================================ */
static uint8_t *peer_rx_pt(struct peer_session *ps) {
  if (!ps->rx_pt_buf)
    ps->rx_pt_buf = sodium_malloc(NOX_MAX_MSG_LEN + 1);
  return ps->rx_pt_buf;
}

/* H2/H3: doğrulanamayan veya protokol dışı çerçeve = görünür kopma.
 * Nonce invariantı nedeniyle devam etmek güvenli değildir; tek kurtarma
 * yolu oturumu merkezi cleanup ile kapatmaktır. Çağıran, bu yardımcıdan
 * sonra peer'e dokunmadan döngüden çıkmalıdır. */
static void peer_proto_fatal(struct peer_session *ps, struct app_state *state,
                             const char *reason) {
  NOX_ERROR(LOG_MOD_NET, "PROTO_FATAL: %s (state=%s seq=%u)",
            reason, sm_state_name(ps->state), ps->rx_seq);
  ui_print_error(state,
                 "Hata: Akran bağlantısında protokol ihlali algılandı (%s). "
                 "Bağlantı kapatıldı.",
                 reason);
  (void)sm_dispatch(ps, state, EV_CRYPTO_FAIL);
}

/* ================================================================
 * FRAME PROCESSING — recv_buf'daki frame'leri işle
 *
 * Hem EPOLLIN handler'dan hem de epoll_wait öncesi drain'den
 * çağrılır. Bu sayede TOFU_PENDING sonrası bekleyen frame'ler
 * session kurulduktan sonra işlenebilir.
 * ================================================================ */

// Real attack surface in practice: untrusted network (AF_UNIX, attacker-controlled wire)
/* UNIT TEST ERİŞİMİ (test_event_frames): socketpair/buffer izolasyonuyla
 * frame dağıtım yolu — TEXT/SEQ/MAC/CTRL/FILE davranış kilitleri. */
void process_peer_frames(struct peer_session *ps, struct app_state *state,
                         int fd) {
  while (ps->recv_pos >= FRAME_HEADER_WIRE_SIZE) {

    struct frame_header fh;
    if (frame_header_decode(ps->recv_buf, &fh) != NOX_OK) {
      peer_proto_fatal(ps, state, "geçersiz frame başlığı");
      break;
    }

    /* A-1 FIX + H3: sıfır/aşırı payload doğrulanamaz; sessiz resync yok. */
    if (fh.len == 0 || fh.len > FRAME_MAX_PAYLOAD) {
      peer_proto_fatal(ps, state, "geçersiz frame boyutu");
      break;
    }

    size_t frame_total = FRAME_HEADER_WIRE_SIZE + fh.len;
    if (ps->recv_pos < frame_total)
      break; /* payload henüz tamamlanmadı, bir sonraki EPOLLIN'de devam */

    /* FIX: Session henüz kurulmadıysa TEXT/FILE frame'leri tüketme —
     * recv_buf'da beklesin, session sonrası drain ile işlenecek.
     * TOFU_PENDING sırasında peer mesaj gönderirse bunlar drop edilirdi,
     * bu da seq mismatch'e yol açardı. */
    if ((fh.type == NOX_MSG_TEXT || fh.type == NOX_MSG_FILE) && !ps->session) {
      NOX_DEBUG(LOG_MOD_NET,
               "session henüz yok — frame bekletiliyor (type=%u seq=%u recv_pos=%zu)",
               fh.type, fh.seq, ps->recv_pos);
      break;
    }

    /* Frame tamamlandı — payload'ı ayıkla */
    /* H2: header'ın ham 13 byte'ı AEAD'ye AD olarak girer. Kopya
     * memmove'dan ÖNCE alınır — recv_buf kaydırılınca içerik değişir. */
    uint8_t ad[FRAME_HEADER_WIRE_SIZE];
    memcpy(ad, ps->recv_buf, sizeof(ad));

    uint8_t *payload = sodium_malloc(fh.len);
    if (!payload) {
      ps->recv_pos = 0;
      break;
    }
    memcpy(payload, ps->recv_buf + FRAME_HEADER_WIRE_SIZE, fh.len);
    /* M-3 FIX: Frame sonrasındaki kalan byte'ları koru */
    size_t remaining = ps->recv_pos - frame_total;
    if (remaining > 0) {
      memmove(ps->recv_buf, ps->recv_buf + frame_total, remaining);
    }
    ps->recv_pos = remaining;

    /* Y-2 FIX: Handshake tamamlanmış (msg_index >= 3) bir peer'ın ek CTRL
     * frame'leri handshake_read'e giderse NOX_ERR_STATE → EV_HANDSHAKE_ERROR
     * → TOFU-PENDING bekleyen slot ölür. CTRL yalnızca handshake aktifken
     * (msg_index < 3) handshake'e verilir; fazlası sessizce düşürülür. */
    if (fh.type == NOX_MSG_CTRL && ps->hs && ps->hs->msg_index < 3) {
      /* H-1/H-2: claim payload v1 = 127 byte (eski 64'TEN BÜYÜK —
       * handshake_read out_cap buradan gelir, küçük kalırsa decrypt
       * başarısız olurdu). */
      uint8_t pl[NOX_HS_PAYLOAD_V1_LEN];
      size_t pl_len = sizeof(pl);
      nox_err_t hs_err =
          handshake_read(ps->hs, payload, fh.len, pl, sizeof(pl), &pl_len);
      if (hs_err != NOX_OK) {
        NOX_ERROR(LOG_MOD_NOISE, "Handshake okuma hatası: %s",
                  nox_strerror(hs_err));
        ui_print_error(
            state, "Akran ile handshake el sıkışması başarısız oldu.");
        sm_dispatch(ps, state, EV_HANDSHAKE_ERROR);
        sodium_free(payload);
        break;
      }

      uint8_t remote_pub[NOX_KEY_LEN];
      char peer_onion[NOX_ONION_LEN + 1];
      sodium_memzero(peer_onion, sizeof(peer_onion));
      bool claim_verified = false;

      /* Adım 13: initiator msg2'deki responder claim'ini KENDİ msg3'ünü
       * yazmadan önce doğrular. Aksi halde aktif MITM, msg3'ü (initiator
       * onion + static key claim'i) alıp sonra reddedilse bile kimlik
       * sızdırırdı. Responder msg3'ü aşağıdaki ortak yolda doğrular. */
      if (ps->hs->initiator && ps->hs->msg_index == 2) {
        nox_err_t claim_err =
            verify_peer_claim(ps, state, pl, pl_len, peer_onion);
        if (claim_err != NOX_OK) {
          sm_dispatch(ps, state, EV_HANDSHAKE_ERROR);
          sodium_free(payload);
          break;
        }
        claim_verified = true;
      }

      if (ps->hs->msg_index < 3) {
        uint8_t hsbuf[NOISE_MAX_HANDSHAKE_LEN];
        size_t hslen = sizeof(hsbuf);
        /* H-1/H-2: claim payload v1 [ver|onion|sig] — imza başarısızsa
         * handshake'i bitir (fail-closed, peer'a bilgi gitmez). */
        uint8_t hs_pl[NOX_HS_PAYLOAD_V1_LEN];
        nox_err_t claim_err = hs_build_claim_payload(hs_pl, state);
        if (claim_err != NOX_OK) {
          NOX_ERROR(LOG_MOD_NOISE,
                    "claim payload imzalanamadı: %s", nox_strerror(claim_err));
          ui_print_error(state, "Kimlik imzası oluşturulamadı");
          sm_dispatch(ps, state, EV_HANDSHAKE_ERROR);
          sodium_free(payload);
          break;
        }
        nox_err_t hs_write_err = handshake_write(ps->hs,
                            hs_pl, NOX_HS_PAYLOAD_V1_LEN, hsbuf, &hslen);
        sodium_memzero(hs_pl, sizeof(hs_pl));
        if (hs_write_err != NOX_OK) {
          NOX_ERROR(LOG_MOD_NOISE, "handshake_write hatası: %s",
                    nox_strerror(hs_write_err));
          ui_print_error(state, "Handshake yanıtı oluşturulamadı");
          sm_dispatch(ps, state, EV_HANDSHAKE_ERROR);
          sodium_free(payload);
          break;
        }

        struct frame_header rfh = {
            .magic = NOX_FRAME_MAGIC,
            .type = NOX_MSG_CTRL,
            .seq = ps->tx_seq,
            .len = (uint32_t)hslen,
        };
        uint8_t rwire[FRAME_HEADER_WIRE_SIZE];
        frame_header_encode(&rfh, rwire);
        struct iovec iov[2] = {
            { .iov_base = (void *)rwire, .iov_len = FRAME_HEADER_WIRE_SIZE },
            { .iov_base = (void *)hsbuf, .iov_len = hslen },
        };
        ssize_t written = writev(fd, iov, 2);
        if (written != (ssize_t)(FRAME_HEADER_WIRE_SIZE + hslen)) {
          NOX_ERROR(LOG_MOD_NOISE, "handshake yanıtı gönderilemedi");
          ui_print_error(state, "Handshake yanıtı gönderilemedi");
          sm_dispatch(ps, state, EV_HANDSHAKE_ERROR);
          sodium_free(payload);
          break;
        }
        ps->tx_seq++;
        clock_gettime(CLOCK_MONOTONIC, &ps->last_active);
        NOX_INFO(LOG_MOD_NOISE, "handshake yanıt (tx_seq→%u)", ps->tx_seq);
      }

      if (ps->hs->msg_index >= 3) {
        /* Initiator yolu yukarıda doğruladı; responder yolu msg3'ü
         * okuduktan sonra burada doğrular. Doğrulanmış adres TOFU ve
         * session kurulumunda yeniden verify edilmez. */
        if (!claim_verified) {
          nox_err_t claim_err =
              verify_peer_claim(ps, state, pl, pl_len, peer_onion);
          if (claim_err != NOX_OK) {
            sm_dispatch(ps, state, EV_HANDSHAKE_ERROR);
            sodium_free(payload);
            break;
          }
          claim_verified = true;
        }

        char name[NOX_CONTACT_NAME_LEN + 1];
        uint8_t stored_key[NOX_KEY_LEN];
        sodium_memzero(name, sizeof(name));
        sodium_memzero(stored_key, sizeof(stored_key));

        nox_err_t db_err = NOX_ERR_DB;
        if (!state->ghost_mode) {
          db_err = db_get_contact(peer_onion, name, sizeof(name), stored_key);
        }
        memcpy(remote_pub, ps->hs->rs, NOX_KEY_LEN);

        char fp_str[NOX_KEY_LEN * 2 + 1];
        for (size_t k = 0; k < NOX_KEY_LEN; k++) {
          if (k * 2 + 3 > sizeof(fp_str)) break;
          snprintf(&fp_str[k * 2], sizeof(fp_str) - (k * 2), "%02x", remote_pub[k]);
        }

        bool zero_key = true;
        for (size_t k = 0; k < NOX_KEY_LEN; k++) {
          if (stored_key[k] != 0) {
            zero_key = false;
            break;
          }
        }

        if (db_err == NOX_OK && !zero_key) {
          /* E-1 FIX: sodium_memcmp — sabit zamanlı karşılaştırma, timing saldırısı koruması */
          if (sodium_memcmp(stored_key, remote_pub, NOX_KEY_LEN) == 0) {
            ps->session = sodium_malloc(sizeof(struct noise_session));
            if (ps->session) {
              /* sodium_malloc 0xdb doldurur; hardbool(0)'da 0xdb trap,
               * fallback bool'da true olur. Deterministik zero-init
               * (handshake_split de sıfırlar). */
              sodium_memzero(ps->session, sizeof(*ps->session));
              if (handshake_split(ps->hs, ps->session) != NOX_OK) {
                ui_print_error(state, "session split başarısız");
                sm_dispatch(ps, state, EV_HANDSHAKE_ERROR);
                sodium_free(payload);
                continue;
              }
              sodium_free(ps->hs);
              ps->hs = NULL; /* handshake tüketildi — timeout tetiklemesin */
              ps->tx_seq = 0;
              ps->rx_seq = 0;
              ps->queue_flushed = false;
              ps->peer_verified = true; /* H-1 FIX: doğrulanmış peer — kuyruk flush serbest */
              ps->tofu_was_zero_key = false;
              clock_gettime(CLOCK_MONOTONIC, &ps->last_active);
              NOX_DEBUG(LOG_MOD_NOISE,
                        "session setup: tx_seq=0 rx_seq=0 queue_flushed=false verified=1");
              sm_dispatch(ps, state, EV_SESSION_READY);

              /* M-3 FIX: bilinen-peer inbound yolunda peer_onion hiç
               * set edilmiyordu → db_process_queue("") hiç eşleşmez,
               * çevrimdışı mesajlar iletilmezdi. TOFU yoluyla aynı
               * desen: session hazır olunca onion'u peer slotuna yaz. */
              snprintf(ps->peer_onion, sizeof(ps->peer_onion), "%s", peer_onion);

              strncpy(state->active_peer_onion, ps->peer_onion, NOX_ONION_LEN);
              state->active_peer_onion[NOX_ONION_LEN] = '\0';

              NOX_INFO(LOG_MOD_NOISE,
                       "session kuruldu — mesajlaşma hazır");
              ui_print_system(state, "[✓] şifreli kanal kuruldu (%s)",
                              name);
              ui_reset_sender();
            } else {
              ui_print_error(state, "Arena bellek hatası");
              sm_dispatch(ps, state, EV_ARENA_FAIL);
            }
          } else {
            /* G-2 madde 0: tofu_pending guard'ı print bloğundan önce aktif et —
             * clear_prompt_area içindeki early-return ancak böyle devreye girer. */
            ps->tofu_pending = true;
            ps->tofu_peer_fd = fd;
            ps->tofu_was_zero_key = false; /* H-1 FIX: mevcut key değişimi */
            ps->peer_verified = false;
            strncpy(ps->tofu_onion, peer_onion, NOX_ONION_LEN);
            ps->tofu_onion[NOX_ONION_LEN] = '\0';
            strncpy(ps->tofu_name, name, NOX_CONTACT_NAME_LEN);
            ps->tofu_name[NOX_CONTACT_NAME_LEN] = '\0';
            memcpy(ps->tofu_new_key, remote_pub, NOX_KEY_LEN);
            /* Atomic ANSI: cursor hide → clear → print warning → prompt */
            if (tui_is_active()) {
              ui_print_error(state, "[!] UYARI: AKRANIN ANAHTARI DEĞİŞMİŞ! (MITM RİSKİ)");
              ui_print_error(state, "      Adres: %s", peer_onion);
              ui_print_error(state, "      Kayıtlı İsim: %s", name);
              ui_print_error(state, "      Yeni Fingerprint: %s", fp_str);
              ui_print_error(state, "  [?] Yeni anahtarı onaylıyor musunuz? (y/n): ");
            } else {
            fprintf(stderr, "\033[?25l");
            clear_prompt_area(state);
            fprintf(stderr, "\n\033[31m  [!] UYARI: AKRANIN ANAHTARI "
                            "DEĞİŞMİŞ! (MITM RİSKİ)\033[0m\n");
            fprintf(stderr, "      Adres: %s\n", peer_onion);
            fprintf(stderr, "      Kayıtlı İsim: %s\n", name);
            fprintf(stderr, "      \033[1;31mYeni Fingerprint: %s\033[0m\n", fp_str);
            fprintf(stderr,
                    "  [?] Yeni anahtarı onaylıyor musunuz? (y/n): ");
            fflush(stderr);
            fprintf(stderr, "\033[?25h");
            fflush(stderr);
            }

            /* State geçişi: HANDSHAKE → TOFU_PENDING */
            clock_gettime(CLOCK_MONOTONIC, &ps->tofu_start);
            sm_dispatch(ps, state, EV_HANDSHAKE_DONE);
          }
          } else {
           /* G-2 madde 0: default_name önce hesaplanmalı — tofu_name ona bağlı */
           char default_name[NOX_CONTACT_NAME_LEN + 1];
           bool is_placeholder = (db_err == NOX_OK && zero_key);
           if (is_placeholder && name[0] != '\0') {
             snprintf(default_name, sizeof(default_name), "%s", name);
           } else {
             snprintf(default_name, sizeof(default_name), "peer_%.8s",
                      peer_onion);
           }
           default_name[NOX_CONTACT_NAME_LEN] = '\0';
           /* G-2 madde 0: guard print bloğundan önce aktif — clear_prompt_area artık no-op */
           ps->tofu_pending = true;
           ps->tofu_peer_fd = fd;
           ps->tofu_was_zero_key = is_placeholder; /* H-1 FIX: kuyruk flush kontrolü için */
           ps->peer_verified = false;
           strncpy(ps->tofu_onion, peer_onion, NOX_ONION_LEN);
           ps->tofu_onion[NOX_ONION_LEN] = '\0';
           strncpy(ps->tofu_name, default_name, NOX_CONTACT_NAME_LEN);
           ps->tofu_name[NOX_CONTACT_NAME_LEN] = '\0';
           memcpy(ps->tofu_new_key, remote_pub, NOX_KEY_LEN);
           if (tui_is_active()) {
             ui_print_system(state, "[!] TOFU: Yeni peer bağlantısı");
             ui_print_system(state, "      Adres: %s", peer_onion);
             ui_print_system(state, "      Fingerprint: %s", fp_str);
             ui_print_system(state, "  [?] Bu bağlantıyı onaylıyor ve rehbere "
                             "kaydediyor musunuz? (y/n): ");
           } else {
           fprintf(stderr, "\033[?25l");
           clear_prompt_area(state);
           fprintf(stderr,
                   "\n\033[33m  [!] TOFU: Yeni peer bağlantısı\033[0m\n");
           fprintf(stderr, "      Adres: %s\n", peer_onion);
           fprintf(stderr, "      \033[1;36mFingerprint: %s\033[0m\n", fp_str);
           fprintf(stderr, "  [?] Bu bağlantıyı onaylıyor ve rehbere "
                           "kaydediyor musunuz? (y/n): ");
           fflush(stderr);
           fprintf(stderr, "\033[?25h");
           fflush(stderr);
           }

           /* H-1 FIX: zero_key placeholder için ek uyarı — rehber zehirlenmesi
            * riski: /add ile sıfır key eklenmiş kişiye saldırgan ilk bağlanan
            * olursa slot'u zehirler. Kullanıcıya bağlam ver. */
           if (is_placeholder) {
             if (tui_is_active()) {
               ui_print_error(state, "[!] DİKKAT: Bu onion rehberinizde '%s' olarak kayıtlı ama anahtarı henüz doğrulanmadı.", default_name);
               ui_print_error(state, "    İlk bağlantı anahtarı kalıcı olarak bağlayacak — bu işlemi SİZ başlatmadıysanız MITM olabilir.");
             } else {
               fprintf(stderr, "\033[?25l");
               clear_prompt_area(state);
               fprintf(stderr, "\n\033[33m  [!] DİKKAT: Bu onion rehberinizde '%s' olarak kayıtlı ama anahtarı henüz doğrulanmadı.\033[0m\n", default_name);
               fprintf(stderr, "      İlk bağlantı anahtarı kalıcı olarak bağlayacak — bu işlemi SİZ başlatmadıysanız MITM olabilir.\n");
               fflush(stderr);
               fprintf(stderr, "\033[?25h");
               fflush(stderr);
             }
           }

           /* State geçişi: HANDSHAKE → TOFU_PENDING */
           clock_gettime(CLOCK_MONOTONIC, &ps->tofu_start);
           sm_dispatch(ps, state, EV_HANDSHAKE_DONE);
         }
      }
      sodium_memzero(remote_pub, NOX_KEY_LEN);
    } else if ((fh.type == NOX_MSG_TEXT || fh.type == NOX_MSG_FILE) &&
               ps->session) {
      /* H2/P0 defense-in-depth: handshake_split öncesi/yarım session'da
       * rx.has_key yoktur; transport decrypt'e hiç girmeden kapat. */
      if (!ps->session->rx.has_key) {
        peer_proto_fatal(ps, state, "transport anahtarı yok");
        sodium_free(payload);
        break;
      }

      /* H3: peer'ın tek RX tamponuna çözülür (sodium_malloc ile swap
       * koruması); serbest bırakma action_cleanup'a aittir. */
      uint8_t *pt = peer_rx_pt(ps);
      if (!pt) {
        peer_proto_fatal(ps, state, "RX plaintext tamponu ayrılamadı");
        sodium_free(payload);
        break;
      }

      ssize_t pt_len =
          noise_decrypt(ps->session, ad, sizeof(ad), payload, fh.len, pt);
      if (pt_len < 0) {
        sodium_memzero(pt, NOX_MAX_MSG_LEN + 1);
        peer_proto_fatal(ps, state, "AEAD doğrulaması başarısız");
        sodium_free(payload);
        break;
      }

      /* Savunmalı sanity: AD artık seq'i kimlikler; yine de decrypt
       * sonrası beklenen sayaçla eşleşmeyen frame kabul edilmez. */
      if ((uint32_t)fh.seq != ps->rx_seq) {
        sodium_memzero(pt, NOX_MAX_MSG_LEN + 1);
        peer_proto_fatal(ps, state, "doğrulanmış seq beklenenle uyuşmuyor");
        sodium_free(payload);
        break;
      }

      /* Başarılı decrypt = koşulsuz tüket (boş pt dahil). Bu, AEAD
       * nonce'u ile AD seq'inin ayrışmasını önler; UI/empty kararından
       * ÖNCE yapılır. */
      ps->rx_seq++;

      if (pt_len == 0) {
        sodium_memzero(pt, NOX_MAX_MSG_LEN + 1);
        peer_proto_fatal(ps, state, "boş TEXT/FILE payload");
        sodium_free(payload);
        break;
      }
      if ((size_t)pt_len > NOX_MAX_MSG_LEN) {
        sodium_memzero(pt, NOX_MAX_MSG_LEN + 1);
        peer_proto_fatal(ps, state, "plaintext boyutu sınırı aşıyor");
        sodium_free(payload);
        break;
      }

      size_t pt_used = (size_t)pt_len;
      /* Yalnız non-empty geçerli payload yaşam belirtisidir; boş/fail
       * yolları yukarıda cleanup'a gider. */
      clock_gettime(CLOCK_MONOTONIC, &ps->last_active);

      if (fh.type == NOX_MSG_TEXT) {
        pt[pt_used] = '\0';
        ui_print_incoming(state, (const char *)pt);

        /* H3: kullan → sıfırla → dispatch. Kuyruk flush callback'i
         * writev hatasında EV_PEER_DISCONNECTED dispatch eder ve
         * action_cleanup tamponu serbest bırakır; metin kopyalandı. */
        sodium_memzero(pt, NOX_MAX_MSG_LEN + 1);

        /* BUG-1 FIX: İlk mesaj alındı → kuyruğu gönder
         * H-1 FIX: kuyruk sızıntısı — eğer session TOFU ile kurulduysa
         * (peer_verified==false) ve özellikle zero_key placeholder ise,
         * kuyruktaki mesajlar doğrulanmamış anahtara gidecek. Bu durumda
         * otomatik flush YAPILMAZ — kullanıcıya uyarı basılır ve bir sonraki
         * doğrulanmış SESSION_READY bağlantısında flush edilir. */
        if (!ps->queue_flushed && !state->ghost_mode) {
          if (!ps->peer_verified) {
            if (ps->tofu_was_zero_key) {
              NOX_WARN(LOG_MOD_DB,
                "H-1: zero_key TOFU peer için kuyruk flush atlandı — anahtar ilk kez bağlandı, kuyruk bir sonraki doğrulanmış oturumda gönderilecek");
              ui_print_system(state, "[!] Kuyruktaki mesajlar bu ilk TOFU onayı için GÖNDERİLMEDİ (güvenlik). Bir sonraki doğrulanmış bağlantıda iletilecek.");
            } else {
              NOX_WARN(LOG_MOD_DB,
                "TOFU ile kurulmuş oturum için kuyruk flush atlandı — doğrulanmamış anahtar");
              ui_print_system(state, "[!] Kuyruktaki mesajlar doğrulanmamış peer için bekletiliyor.");
            }
            ps->queue_flushed = true; /* tekrar denememek için işaretle, ama gönderme */
          } else {
            ps->queue_flushed = true;
            struct queue_flush_ctx qctx = { .state = state, .ps = ps };
            db_process_queue(ps->peer_onion,
                             send_queued_callback, &qctx);
          }
        }
      } else {
        /* H3: plaintext'i event_loop çözer; handle_rx yalnız tüketir.
         * pt_len==0 yukarıda empty-payload fatal olarak yakalandı; 0'ı
         * "decrypt fail" diye handle_rx'e geçirme. */
        nox_hardbool_t handled = file_transfer_handle_rx(
            state, ps, pt, (uint32_t)pt_used);

        /* Kullan → sıfırla → dispatch: handle_rx içindeki dispatch'ler
         * tamponu serbest bırakabilir; cleanup NULL'lamışsa no-op. */
        if (ps->rx_pt_buf)
          sodium_memzero(ps->rx_pt_buf, NOX_MAX_MSG_LEN + 1);

        if (!handled) {
          peer_proto_fatal(ps, state, "FILE payload işlenemedi");
          sodium_free(payload);
          break;
        }
      }
    }

    /* Payload Cleanup — Tüm mesaj tipleri için çalışır */
    sodium_free(payload);

  } /* while frame processing loop */
}

/* ================================================================
 * EVENT LOOP — epoll tabanlı async I/O
 * ================================================================ */
// Real attack surface in practice: untrusted Tor peer, multiplexed epoll
void event_loop(struct app_state *state) {
  /* 1 (stdin) + 2*NOX_MAX_PEERS (listener + data per peer) */
  struct epoll_event events[1 + 2 * NOX_MAX_PEERS];

  /* ── Landlock sandbox — open/openat/creat'i kısıtla ──────────────
   * Landlock ÖNCE yüklenmeli (seccomp'tan önce).
   * Sadece downloads dizini okunabilir/yazılabilir.
   * Kernel 5.13+ gerektirir, desteklemiyorsa hata döner.
   * no_new_privs ayarlanır — seccomp yüklemesi bundan etkilenmez. */
  if (state->config_dir_fd >= 0 && state->downloads_dir_fd >= 0) {
    nox_err_t ll_err = landlock_sandbox_init(state->config_dir_fd,
                                             state->downloads_dir_fd);

    if (ll_err == NOX_ERR_LANDLOCK_UNSUPPORTED) {
      if (!state->allow_unsandboxed_fs) {
        /* C-2 FIX: varsayılan fail-closed — seccomp ile simetrik.
         * Sandbox'sız çalışmak açık bayrak gerektiren bilinçli bir tercih. */
        ui_print_error(state,
            "Bu çekirdek Landlock desteklemiyor (Linux 5.13+ gerekli). "
            "Dosya sistemi sandbox'ı olmadan çalışmak engellendi. "
            "Bilinçli olarak devam etmek için --allow-unsandboxed-fs kullanın.");
        NOX_FATAL(LOG_MOD_MAIN,
                  "landlock kurulamadı — kullanıcı onayı yok, çıkılıyor");
        state->running = false;
        return;
      }
      /* Kullanıcı bilerek onayladıysa: devam et ama görünür şekilde uyar —
       * sadece log'a değil, TUI/terminal ekranına da. */
      NOX_WARN(LOG_MOD_MAIN,
               "landlock devre dışı — KULLANICI ONAYIYLA sandbox'sız çalışılıyor");
      ui_print_error(state, "Dosya sistemi sandbox'ı KAPALI "
                            "(--allow-unsandboxed-fs ile onaylandı).");
    } else if (ll_err != NOX_OK) {
      NOX_ERROR(LOG_MOD_MAIN, "landlock: yapılandırma hatası");
      ui_print_error(state, "Sandbox yapılandırma hatası.");
      state->running = false;
      return;
    }

    /* C-2 FIX: landlock_is_active() artık ölü kod değil — sandbox
     * gerçekten uygulanmadıysa (herhangi bir nedenle) görünür uyarı. */
    if (!landlock_is_active()) {
      NOX_WARN(LOG_MOD_MAIN, "landlock: sandbox aktif DEĞİL — dosya erişimi kısıtsız");
      ui_print_error(state, "⚠ Dosya sistemi sandbox'ı AKTİF DEĞİL.");
    }
  }

  /* ── Stage 3: Sıfır ağ sızıntısı garantisi ────────────────────
   * Tüm mevcut bağlantılar AF_UNIX (Tor control, SOCKS, peer).
   * Event loop tek thread — clone tamamen yasak.
   * TCP/UDP/NETLINK socket oluşturulamaz.
   * open/openat/creat seccomp tarafından engellenmez —
   * Landlock path-based filtering sağlar (yoksa openat serbest). */
  if (seccomp_policy_load(3) != NOX_OK) {
    NOX_ERROR(LOG_MOD_MAIN, "seccomp stage 3 yüklenemedi");
    ui_print_error(state, "Güvenlik politikası yüklenemedi.");
    state->running = false;
    return;
  }

  /* ── Hoşgeldiniz + Komutlar — stage 3 sonrası ────────────────
   * Hem TUI hem terminal modunda hoşgeldiniz ve komut listesi basılır.
   * Stage 3'ten sonra basılır: clone/TCP/UDP/NETLINK zaten engellenmiş. */
  if (tui_is_active()) {
    tui_print_welcome(state);
    if (state->ghost_mode) {
      ui_print_system(state, "[👻] GHOST MOD — hiçbir veri kaydedilmez, rehber ve kuyruk devre dışı");
    }

    tui_refresh_all(state);
  } else {
    if (state->ghost_mode) {
      fprintf(
          stderr,
          "\n  [👻] GHOST MOD — hiçbir veri kaydedilmez, rehber ve kuyruk devre dışı\n\n"
          "  Komutlar:\n"
          "    \033[38;2;210;24;38m/help               — bu yardımı "
          "göster\033[0m\n"
          "    \033[38;2;210;24;38m/quit               — "
          "uygulamadan çık\033[0m\n"
          "    \033[38;2;210;24;38m/addr               — .onion adresini "
          "göster\033[0m\n"
          "    \033[38;2;224;126;20m/connect <onion>    — peer'a "
          "bağlan\033[0m\n"
          "    \033[38;2;210;24;38m/disconnect          — aktif peer "
          "bağlantısını kes\033[0m\n"
          "    \033[38;2;31;65;117m/file <dosya_yolu>  — peer'a dosya gönder "
          "(aktif bağlantı gerektirir)\033[0m\n"
          "    \033[38;2;31;65;117m/status              — "
          "bağlantı durumunu göster\033[0m\n"
          "    \033[38;2;133;60;153mCtrl+P              — "
          "çıkış\033[0m\n"
          "  Bağlantı kurulduktan sonra yazdığınız her şey doğrudan mesaj olarak "
          "gönderilir.\n\n");
    } else {
      fprintf(
          stderr,
          "\n  Komutlar:\n"
          "    \033[38;2;210;24;38m/help               — bu yardımı "
          "göster\033[0m\n"
          "    \033[38;2;210;24;38m/quit               — "
          "uygulamadan çık\033[0m\n"
          "    \033[38;2;210;24;38m/addr               — .onion adresini "
          "göster\033[0m\n"
          "    \033[38;2;210;115;15m/connect <onion>    — peer'a "
          "bağlan\033[0m\n"
          "    \033[38;2;210;115;15m/disconnect          — aktif peer "
          "bağlantısını kes\033[0m\n"
          "    \033[38;2;240;170;20m/add <onion> <isim> — rehbere kişi "
          "ekle\033[0m\n"
          "    \033[38;2;240;170;20m/list               — rehberi ve "
          "çevrimiçi durumu listele\033[0m\n"
          "    \033[38;2;240;170;20m/switch <isim|onion>— aktif peer'ı "
          "değiştir\033[0m\n"
          "    \033[38;2;38;162;105m/msg <onion> <msj>  — çevrimdışı/kuyruklu "
          "mesaj gönder\033[0m\n"
          "    \033[38;2;31;65;117m/file <dosya_yolu>  — peer'a dosya gönder "
          "(aktif bağlantı gerektirir)\033[0m\n"
          "    \033[38;2;31;65;117m/status              — "
          "bağlantı durumunu göster\033[0m\n"
          "    \033[38;2;31;65;117m/history             — "
          "mesaj geçmişini göster\033[0m\n"
          "    \033[38;2;133;60;153mCtrl+P              — "
          "çıkış\033[0m\n"
          "  Bağlantı kurulduktan sonra yazdığınız her şey doğrudan mesaj olarak "
          "gönderilir.\n\n");
    }
  }

  /* ── Linenoise editör (Faz E — TTY multiplexing) ─────────────
   * Komut listesinden SONRA başlatılır: prompt en altta çizilir,
   * imleç o satırda kalır (stderr'den sonra bulunduğu satıra `\r`
   * ile çizilir). isatty değilse no-op (pipe/script mevcut yol). */
  ln_edit_init(state);

  while (state->running && !g_shutdown) {
    /* ── Per-peer timeout kontrolları ── */
    for (unsigned pi = 0; pi < NOX_MAX_PEERS; pi++) {
      struct peer_session *ps = &state->peers[pi];
      if (ps->fd == -1 && ps->state == ST_IDLE)
        continue;

      /* Handshake timeout — NOX_HANDSHAKE_TIMEOUT_SEC */
      if (ps->state == ST_HANDSHAKE_INIT ||
          ps->state == ST_HANDSHAKE_RESP) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - ps->handshake_start.tv_sec > NOX_HANDSHAKE_TIMEOUT_SEC) {
          NOX_WARN(LOG_MOD_NOISE, "Handshake zaman aşımına uğradı");
          ui_print_error(state, "Akran ile handshake zaman aşımına uğradı.");
          sm_dispatch(ps, state, EV_HANDSHAKE_TIMEOUT);
        }
      }

      /* TOFU timeout — NOX_TOFU_TIMEOUT_SEC */
      if (ps->state == ST_TOFU_PENDING) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - ps->tofu_start.tv_sec > NOX_TOFU_TIMEOUT_SEC) {
          NOX_WARN(LOG_MOD_NET, "TOFU timeout — süresinde onaylanmadı");
          ui_print_error(state, "TOFU onay zaman aşımı — bağlantı temizlendi.");
          sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
        }
      }

      /* Dosya transferi timeout — NOX_FILE_CHUNK_TIMEOUT_SEC
       * A FIX: CLOCK_MONOTONIC (M-12 kalıbı) — duvar saati atlaması
       * (suspend/resume, NTP) aktif transferi haksız yere öldürmemeli;
       * ayrıca timeout predikati saf ve test edilebilir (test_time_expiry). */
      if (ps->rx_file.active) {
        struct timespec now_ts;
        clock_gettime(CLOCK_MONOTONIC, &now_ts);
        if (file_transfer_chunk_expired(&ps->rx_file.last_chunk_ts, &now_ts,
                                        NOX_FILE_CHUNK_TIMEOUT_SEC)) {
          NOX_WARN(LOG_MOD_MAIN, "Dosya transferi zaman aşımı: %s", ps->rx_file.filename);
          ui_print_error(state, "Dosya transferi zaman aşımı — sender sessiz.");
          if (state->downloads_dir_fd >= 0 && ps->rx_file.local_name[0] != '\0') {
            unlinkat(state->downloads_dir_fd, ps->rx_file.local_name, 0);
          }
          if (ps->rx_file.fd >= 0) {
            close(ps->rx_file.fd);
          }
          sodium_memzero(&ps->rx_file, sizeof(ps->rx_file));
          ps->rx_file.fd = -1;
          /* F9 FIX: chunk-timeout SM'yi FILE_RX'te asılı bırakıyordu.
           * rx_abort yolu EV_FILE_DONE dispatch ederken timeout etmiyordu;
           * state FILE_RX + active=false hayaleti /switch'i 3600sn blokluyordu. */
          if (ps->state == ST_FILE_RX) {
            sm_dispatch(ps, state, EV_FILE_DONE);
          }
        }
      }

      /* M-2 FIX: ST_ACTIVE / ST_FILE idle timeout — 16 slot tükenmesini önler
       * Yarım frame gönderen veya sessizleşen peer slot'u sonsuza dek işgal
       * edemez. Idle: NOX_PEER_IDLE_TIMEOUT_SEC; yarım frame:
       * NOX_HALFFRAME_TIMEOUT_SEC (dosya RX chunk ayrıca yukarıda). */
      if (ps->state == ST_ACTIVE || ps->state == ST_FILE_TX || ps->state == ST_FILE_RX) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long idle = (long)(now.tv_sec - ps->last_active.tv_sec);
        if (idle > NOX_PEER_IDLE_TIMEOUT_SEC) {
          NOX_WARN(LOG_MOD_NET, "Peer idle timeout (%lds) — slot %u disconnect", idle, pi);
          ui_print_error(state, "Bağlantı zaman aşımı — peer sessiz (idle).");
          sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
        } else if (ps->recv_pos > 0 && idle > NOX_HALFFRAME_TIMEOUT_SEC &&
                   ps->recv_pos < RECV_BUF_CAPACITY) {
          /* Yarım frame beklemesi — M-2 ikinci yarısı */
          NOX_WARN(LOG_MOD_NET, "Yarım frame timeout (%lds, recv_pos=%zu) — disconnect", idle, ps->recv_pos);
          sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
        }
      }
    }

    /* ── TOR HEALTH CHECK — Defense-in-Depth ──────────────────────
     * İki mekanizma:
     *   1. SIGCHLD handler — Tor child öldüğünde anında flag set eder
     *   2. Periyodik kill(pid, 0) — SIGCHLD kaybolursa yedek tespit
     * Her ikisi de sm_dispatch(EV_TOR_DIED) ile state machine'i
     * tetikler → her state ST_IDLE'a düşer, temizlik yapılır. */
    {
      static time_t last_tor_check = 0;
      time_t now = time(NULL);
      bool tor_dead = false;

      /* SIGCHLD flag kontrolü — en hızlı yol */
      if (g_tor_died) {
        g_tor_died = 0;
        tor_dead = true;
      }
      /* Periyodik kill(pid, 0) — SIGCHLD yedek */
      else if (state->tor_pid > 0 && (now - last_tor_check >= 5)) {
        last_tor_check = now;
        int kres = kill(state->tor_pid, 0);
        int kerr = errno; /* K-2 FIX: errno'yu hemen değişkene al —
                             SIGCHLD handler araya girebilir (C5 deseni) */
        if (kres != 0 && kerr == ESRCH) {
          tor_dead = true;
        }
      }

      if (tor_dead && state->tor_pid > 0) {
        NOX_ERROR(LOG_MOD_NET, "Tor process öldü (PID=%d)", state->tor_pid);

        /* Aktif tüm peer'lar için EV_TOR_DIED gönder */
        for (unsigned pi = 0; pi < NOX_MAX_PEERS; pi++) {
          struct peer_session *ps = &state->peers[pi];
          if (ps->fd >= 0 || ps->state != ST_IDLE)
            sm_dispatch(ps, state, EV_TOR_DIED);
        }

        /* L-5 FIX: control fd close edilmeden -1 yapılıyordu — fd sızıntısı */
        if (state->tor_ctrl_fd >= 0) {
          close(state->tor_ctrl_fd);
          state->tor_ctrl_fd = -1;
        }
        state->tor_pid = 0;
        g_tor_pid = 0; /* K-2: stale PID eşleşmesini sıfırla */

        /* Tüm arena'yı güvenli şekilde sil — Tor gitti, key'ler
         * işe yaramaz. Yeniden başlatmada PIN ile yeniden türetilir.
         * Y-5 FIX: arena munmap sonrası g_state.db_key dangling kalırdı —
         * db_close ile pointer sıfırlanır, sonraki /msg SIGSEGV yerine
         * NOX_ERR_STATE döner. */
        if (!state->ghost_mode) {
          db_close();
        }
        arena_destroy(&state->arena);
        state->master_key = NULL;
        state->db_key = NULL;
        state->session_key = NULL;
        state->my_static_priv = NULL;
        state->my_static_pub = NULL;
        /* H-1/H-2: onion seed de gitti — onion kimliği artık imzalanamaz,
         * yeni handshake'ler fail-closed (hs_build_claim_payload
         * NOX_ERR_STATE döner). cleanup()'ta sodium_free tekrar NULL
         * görür (double-free yok). */
        if (state->my_onion_seed) {
          sodium_free(state->my_onion_seed);
          state->my_onion_seed = NULL;
        }

        ui_print_error(state,
          "Tor bağlantısı koptu — tüm anahtarlar silindi. "
          "Uygulamayı kapatıp yeniden başlatın.");
      }
    }

    /* ── Recv_buf drain — TOFU sonrası bekleyen frame'leri işle ── */
    {
      int has_frames = 0;
      for (unsigned pi = 0; pi < NOX_MAX_PEERS; pi++) {
        struct peer_session *ps = &state->peers[pi];
        if (ps->session && ps->fd >= 0 &&
            ps->recv_pos >= FRAME_HEADER_WIRE_SIZE) {
          has_frames = 1;
          break;
        }
      }
      if (has_frames) ui_line_suspend(state);
      for (unsigned pi = 0; pi < NOX_MAX_PEERS; pi++) {
        struct peer_session *ps = &state->peers[pi];
        if (ps->session && ps->fd >= 0 &&
            ps->recv_pos >= FRAME_HEADER_WIRE_SIZE) {
          process_peer_frames(ps, state, ps->fd);
        }
      }
      if (has_frames) ui_line_resume(state);
    }

    int nfds = epoll_wait(state->epoll_fd, events,
                          1 + 2 * NOX_MAX_PEERS, 2000);

    if (nfds < 0) {
      if (errno == EINTR)
        continue;
      NOX_ERROR(LOG_MOD_MAIN, "epoll_wait: %s", strerror(errno));
      break;
    }

    for (int i = 0; i < nfds; i++) {
      int fd = events[i].data.fd;

      if (fd == STDIN_FILENO) {
        process_stdin_events(state);
        continue;
      }

      /* ── Gelen peer bağlantısı — tek global listener ── */
      if (fd == state->listen_fd) {
        ui_line_suspend(state);
        int peer_fd =
            accept4(fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (peer_fd < 0) {
          ui_line_resume(state);
          continue;
        }

        /* Boş peer slotu bul */
        struct peer_session *listener_ps = NULL;
        for (unsigned pi = 0; pi < NOX_MAX_PEERS; pi++) {
          if (state->peers[pi].fd == -1 && state->peers[pi].state == ST_IDLE) {
            listener_ps = &state->peers[pi];
            break;
          }
        }

        if (!listener_ps) {
          NOX_WARN(LOG_MOD_MAIN, "maksimum peer sayısına ulaşıldı — bağlantı reddedildi");
          close(peer_fd);
          ui_line_resume(state);
          continue;
        }

        /* Handshake rate limiting — inbound 60s/5 (Y-4 FIX: outbound'dan ayrı) */
        /* M-12 FIX: duvar saati değil CLOCK_MONOTONIC */
        {
          struct timespec hs_ts;
          clock_gettime(CLOCK_MONOTONIC, &hs_ts);
          time_t now = (time_t)hs_ts.tv_sec;
          if (now - state->hs_inbound_window_start >= 60) {
            state->hs_inbound_count = 0;
            state->hs_inbound_window_start = now;
          }
          if (state->hs_inbound_count >= 5) {
            NOX_WARN(LOG_MOD_NOISE,
                     "Inbound handshake rate limit aşıldı (5/60s) — bağlantı reddedildi");
            ui_print_error(state, "Çok fazla gelen handshake denemesi — biraz bekleyin.");
            close(peer_fd);
            ui_line_resume(state);
            continue;
          }
        }

        listener_ps->fd = peer_fd;
          if (epoll_add_fd(state->epoll_fd, peer_fd) != NOX_OK) {
            NOX_ERROR(LOG_MOD_MAIN, "epoll_ctl ADD başarısız — bağlantı reddedildi");
            close(peer_fd);
            listener_ps->fd = -1;
            ui_line_resume(state);
            continue;
          }

          listener_ps->hs = sodium_malloc(sizeof(struct noise_handshake));
          if (!listener_ps->hs) {
            close(peer_fd);
            listener_ps->fd = -1;
            ui_line_resume(state);
            continue;
          }

          /* H-1/H-2 (M-5): return kontrolü — Tor-death sonrası static
           * key'ler NULL ise init başarısız; hs GARBAGE kalırdı ve
           * msg1 msg_index'siz write'a giderdi. Fail-closed: slot'a
           * hiç dokunmadan reddet (state hâlâ ST_IDLE). */
          nox_err_t hi_err = handshake_init(listener_ps->hs, false,
                 state->my_static_priv, state->my_static_pub);
          if (hi_err != NOX_OK) {
            NOX_ERROR(LOG_MOD_NOISE, "handshake_init başarısız: %s",
                      nox_strerror(hi_err));
            sodium_memzero(listener_ps->hs, sizeof(struct noise_handshake));
            sodium_free(listener_ps->hs);
            listener_ps->hs = NULL;
            close(peer_fd);
            listener_ps->fd = -1;
            ui_line_resume(state);
            continue;
          }
          clock_gettime(CLOCK_MONOTONIC, &listener_ps->handshake_start);
          clock_gettime(CLOCK_MONOTONIC, &listener_ps->last_active);
          state->hs_inbound_count++;

          /* State geçişi: IDLE → HANDSHAKE_RESP */
          sm_dispatch(listener_ps, state, EV_PEER_ACCEPTED);

          /* Aktif peer olarak ata — eğer başka aktif peer yoksa */
          if (state->active_peer_idx < 0) {
            for (unsigned pi = 0; pi < NOX_MAX_PEERS; pi++) {
              if (&state->peers[pi] == listener_ps) {
                state->active_peer_idx = (int)pi;
                break;
              }
            }
          }

          NOX_INFO(LOG_MOD_MAIN, "gelen peer kabul edildi (slot %lu, toplam %d)",
                   (unsigned long)(listener_ps - state->peers),
                   active_peer_count(state));
          ui_print_system(state, "[*] gelen bağlantı — handshake bekleniyor");
          ui_line_resume(state);
          continue;
        }

      /* ── Peer'dan veri — EPOLLOUT veya EPOLLIN ── */
      struct peer_session *ps = find_peer_by_fd(state, fd);
      if (!ps)
        continue;

      /* Peer'a Veri Gönderimi (EPOLLOUT) */
      if (events[i].events & EPOLLOUT) {
        if (ps->tx_file.active) {
          file_transfer_handle_tx(state, ps);
        } else {
          epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
        }
      }

      /* Peer'dan Veri Alımı (EPOLLIN) */
      if (events[i].events & EPOLLIN) {
        int avail = 0;
        if (ioctl(fd, FIONREAD, &avail) < 0) avail = 0;
        size_t space = sizeof(ps->recv_buf) - ps->recv_pos;
        size_t to_read = (space > (size_t)avail && avail > 0) ? (size_t)avail : space;
        if (to_read == 0) {
          /* Buffer dolu — önce tamamlanmış frame'leri processing et */
          size_t pos_before = ps->recv_pos;
          ui_line_suspend(state);
          process_peer_frames(ps, state, fd);
          ui_line_resume(state);
          /* K-10: drain ilerleme sağladıysa (recv_pos azaldıysa) tampon
           * artık dolu değildir; koşulsuz koparma. Yalnız hâlâ dolu ve
           * ilerleme yoksa peer gerçekten tıkanmıştır. */
          if (ps->fd >= 0 && peer_recv_buf_full(ps) &&
              ps->recv_pos == pos_before) {
            NOX_WARN(LOG_MOD_NET, "recv_buf dolu — peer tıkanmış, disconnect");
            sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
          }
          continue;
        }

        ssize_t r = recv(fd, ps->recv_buf + ps->recv_pos, to_read, MSG_DONTWAIT);
        if (r <= 0) {
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
          if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
#else
          if (r < 0 && (errno == EAGAIN))
#endif
            continue;
          if (r < 0 && errno == EINTR)
            continue;

          NOX_INFO(LOG_MOD_MAIN, "peer bağlantısı kapandı");
          ui_print_system(state, "[*] peer ayrıldı");
          sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
          continue;
        }
        ps->recv_pos += (size_t)r;
        clock_gettime(CLOCK_MONOTONIC, &ps->last_active);

        ui_line_suspend(state);
        process_peer_frames(ps, state, fd);
        ui_line_resume(state);
      }
    }
  }
}
