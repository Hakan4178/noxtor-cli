/* SPDX-License-Identifier: GPL-3.0-or-later
 * event_loop.c — noxtor-cli epoll tabanlı olay döngüsü
 */

#include "event_loop.h"
#include "arena.h"
#include "common.h"
#include "landlock_sandbox.h"
#include "seccomp_policy.h"
#include "ui.h"
#include "tui.h"
#include "state_machine.h"
#include "stdin_handler.h"
#include "file_transfer.h"
#include "database.h"
#include "noise.h"
#include "network.h"

#include <sys/epoll.h>
#include <sys/ioctl.h>
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
static struct peer_session *find_peer_by_fd(struct app_state *state, int fd)
{
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        struct peer_session *ps = &state->peers[i];
        if (ps->fd == fd)
            return ps;
    }
    return NULL;
}

/* ================================================================
 * FRAME PROCESSING — recv_buf'daki frame'leri işle
 *
 * Hem EPOLLIN handler'dan hem de epoll_wait öncesi drain'den
 * çağrılır. Bu sayede TOFU_PENDING sonrası bekleyen frame'ler
 * session kurulduktan sonra işlenebilir.
 * ================================================================ */
static void process_peer_frames(struct peer_session *ps, struct app_state *state,
                                int fd) {
  while (ps->recv_pos >= FRAME_HEADER_WIRE_SIZE) {

    struct frame_header fh;
    if (frame_header_decode(ps->recv_buf, &fh) != NOX_OK) {
      ps->recv_pos = 0; /* bozuk header — buffer'ı sıfırla */
      break;
    }

    /* A-1 FIX: Boyut sınırı kontrolü */
    if (fh.len == 0 || fh.len > 4096 + NOX_MAC_LEN) {
      NOX_WARN(LOG_MOD_NET, "geçersiz frame boyutu: %u", fh.len);
      ps->recv_pos = 0;
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

    if (fh.type == NOX_MSG_CTRL && ps->hs) {
      uint8_t pl[64];
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

      if (ps->hs->msg_index < 3) {
        uint8_t hsbuf[NOISE_MAX_HANDSHAKE_LEN];
        size_t hslen = sizeof(hsbuf);
        nox_err_t hs_write_err = handshake_write(ps->hs,
                            (const uint8_t *)state->onion_addr,
                            NOX_ONION_LEN + 1, hsbuf, &hslen);
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
        NOX_INFO(LOG_MOD_NOISE, "handshake yanıt (tx_seq→%u)", ps->tx_seq);
      }

      if (ps->hs->msg_index >= 3) {
        char peer_onion[NOX_ONION_LEN + 1];
        sodium_memzero(peer_onion, sizeof(peer_onion));

        if (pl_len == NOX_ONION_LEN + 1 && pl[NOX_ONION_LEN] == '\0') {
          memcpy(peer_onion, pl, NOX_ONION_LEN + 1);
        } else {
          NOX_ERROR(LOG_MOD_NOISE,
                    "Handshake payload geçersiz veya eksik");
          ui_print_error(state, "Akran geçerli bir adres iletmedi");
          sm_dispatch(ps, state, EV_HANDSHAKE_ERROR);
          sodium_free(payload);
          continue;
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
              NOX_DEBUG(LOG_MOD_NOISE,
                        "session setup: tx_seq=0 rx_seq=0 queue_flushed=false");
              sm_dispatch(ps, state, EV_SESSION_READY);

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

            ps->tofu_pending = true;
            ps->tofu_peer_fd = fd;
            strncpy(ps->tofu_onion, peer_onion, NOX_ONION_LEN);
            ps->tofu_onion[NOX_ONION_LEN] = '\0';
            strncpy(ps->tofu_name, name, NOX_CONTACT_NAME_LEN);
            ps->tofu_name[NOX_CONTACT_NAME_LEN] = '\0';
            memcpy(ps->tofu_new_key, remote_pub, NOX_KEY_LEN);
            /* State geçişi: HANDSHAKE → TOFU_PENDING */
            clock_gettime(CLOCK_MONOTONIC, &ps->tofu_start);
            sm_dispatch(ps, state, EV_HANDSHAKE_DONE);
          }
         } else {
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

          char default_name[NOX_CONTACT_NAME_LEN + 1];
          if (db_err == NOX_OK && zero_key && name[0] != '\0') {
            snprintf(default_name, sizeof(default_name), "%s", name);
          } else {
            snprintf(default_name, sizeof(default_name), "peer_%.8s",
                     peer_onion);
          }
          default_name[NOX_CONTACT_NAME_LEN] = '\0';

          ps->tofu_pending = true;
          ps->tofu_peer_fd = fd;
          strncpy(ps->tofu_onion, peer_onion, NOX_ONION_LEN);
          ps->tofu_onion[NOX_ONION_LEN] = '\0';
          strncpy(ps->tofu_name, default_name, NOX_CONTACT_NAME_LEN);
          ps->tofu_name[NOX_CONTACT_NAME_LEN] = '\0';
          memcpy(ps->tofu_new_key, remote_pub, NOX_KEY_LEN);
          /* State geçişi: HANDSHAKE → TOFU_PENDING */
          clock_gettime(CLOCK_MONOTONIC, &ps->tofu_start);
          sm_dispatch(ps, state, EV_HANDSHAKE_DONE);
        }
      }
      sodium_memzero(remote_pub, NOX_KEY_LEN);
    } else if ((fh.type == NOX_MSG_TEXT || fh.type == NOX_MSG_FILE) &&
               ps->session) {
      /* Sequence Number Doğrulaması (Y1) */
      if (fh.seq != ps->rx_seq) {
        NOX_WARN(LOG_MOD_NET,
                 "SEQ_MISMATCH: frame type=%u seq=%u beklenen=%u "
                 "tx_seq=%u recv_pos=%zu",
                 fh.type, fh.seq, ps->rx_seq,
                 ps->tx_seq, ps->recv_pos);
        ui_print_error(state,
                       "Hata: Akran bağlantısında geçersiz sıra numarası "
                       "algılandı (Replay Attack veya paket kaybı)!");
        sm_dispatch(ps, state, EV_SEQ_MISMATCH);
        sodium_free(payload);
        break;
      }

      if (fh.type == NOX_MSG_TEXT) {
        /* A-1 FIX: sodium_malloc ile swap koruması */
        size_t max_pt = fh.len; /* MAC çıkarılmadan üst sınır */
        uint8_t *pt = sodium_malloc(max_pt + 1);
        if (pt) {
          ssize_t pt_len =
              noise_decrypt(ps->session, payload, fh.len, pt);
          /* A-1 FIX: pt_len overflow kontrolü */
          if (pt_len > 0 && (size_t)pt_len <= max_pt) {
            pt[pt_len] = '\0';
            ui_print_incoming(state, (const char *)pt);

            /* BUG-1 FIX: İlk mesaj alındı → kuyruğu gönder */
            if (!ps->queue_flushed && !state->ghost_mode) {
              ps->queue_flushed = true;
              struct queue_flush_ctx qctx = { .state = state, .ps = ps };
              db_process_queue(ps->peer_onion,
                               send_queued_callback, &qctx);
            }
            /* EVT-1 FIX: rx_seq++ only after successful decryption */
            ps->rx_seq++;
          }
          sodium_free(pt); /* otomatik sıfırlar */
        }
      } else if (fh.type == NOX_MSG_FILE) {
        /* EVT-1 FIX: rx_seq++ only if file processing succeeded */
        if (file_transfer_handle_rx(state, ps, payload, fh.len))
          ps->rx_seq++;
      }
    }

    /* Payload Cleanup — Tüm mesaj tipleri için çalışır */
    sodium_free(payload);

  } /* while frame processing loop */
}

/* ================================================================
 * EVENT LOOP — epoll tabanlı async I/O
 * ================================================================ */
void event_loop(struct app_state *state) {
  /* 1 (stdin) + 2*NOX_MAX_PEERS (listener + data per peer) */
  struct epoll_event events[1 + 2 * NOX_MAX_PEERS];

  /* ── Landlock sandbox — open/openat/creat'i kısıtla ──────────────
   * Landlock ÖNCE yüklenmeli (seccomp'tan önce).
   * Sadece downloads dizini okunabilir/yazılabilir.
   * Kernel 5.13+ gerektirir, desteklemiyorsa hata döner.
   * no_new_privs ayarlanır — seccomp yüklemesi bundan etkilenmez. */
  if (state->downloads_dir_fd >= 0) {
    nox_err_t ll_err = landlock_sandbox_init(state->downloads_dir_fd);
    if (ll_err != NOX_OK) {
      NOX_WARN(LOG_MOD_MAIN, "landlock devre dışı — dosya erişimi kısıtsız "
               "(kernel 5.13+ gerekli)");
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
          "gönderilir.\n\n"
          "> ");
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
          "gönderilir.\n\n"
          "> ");
    }
  }

  while (state->running && !g_shutdown) {
    /* ── Per-peer timeout kontrolları ── */
    for (unsigned pi = 0; pi < NOX_MAX_PEERS; pi++) {
      struct peer_session *ps = &state->peers[pi];
      if (ps->fd == -1 && ps->state == ST_IDLE)
        continue;

      /* Handshake timeout — 30 saniye */
      if (ps->state == ST_HANDSHAKE_INIT ||
          ps->state == ST_HANDSHAKE_RESP) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - ps->handshake_start.tv_sec > 30) {
          NOX_WARN(LOG_MOD_NOISE, "Handshake zaman aşımına uğradı");
          ui_print_error(state, "Akran ile handshake zaman aşımına uğradı.");
          sm_dispatch(ps, state, EV_HANDSHAKE_TIMEOUT);
        }
      }

      /* TOFU timeout — 2 dakika */
      if (ps->state == ST_TOFU_PENDING) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - ps->tofu_start.tv_sec > 120) {
          NOX_WARN(LOG_MOD_NET, "TOFU timeout — 2 dakikada onaylanmadı");
          ui_print_error(state, "TOFU onay zaman aşımı — bağlantı temizlendi.");
          sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
        }
      }

      /* Dosya transferi timeout — 60 saniye */
      if (ps->rx_file.active) {
        time_t now = time(NULL);
        if (now - ps->rx_file.last_chunk_time > 60) {
          NOX_WARN(LOG_MOD_MAIN, "Dosya transferi zaman aşımı: %s", ps->rx_file.filename);
          ui_print_error(state, "Dosya transferi zaman aşımı — sender sessiz.");
          if (state->downloads_dir_fd >= 0 && ps->rx_file.local_name[0] != '\0') {
            unlinkat(state->downloads_dir_fd, ps->rx_file.local_name, 0);
          }
          if (ps->rx_file.fd >= 0) {
            close(ps->rx_file.fd);
          }
          explicit_bzero(&ps->rx_file, sizeof(ps->rx_file));
          ps->rx_file.fd = -1;
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
        if (kill(state->tor_pid, 0) != 0 && errno == ESRCH) {
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

        state->tor_pid = 0;
        state->tor_ctrl_fd = -1;

        /* Tüm arena'yı güvenli şekilde sil — Tor gitti, key'ler
         * işe yaramaz. Yeniden başlatmada PIN ile yeniden türetilir. */
        arena_destroy(&state->arena);
        state->master_key = NULL;
        state->db_key = NULL;
        state->session_key = NULL;
        state->my_static_priv = NULL;
        state->my_static_pub = NULL;

        ui_print_error(state,
          "Tor bağlantısı koptu — tüm anahtarlar silindi. "
          "Uygulamayı kapatıp yeniden başlatın.");
      }
    }

    /* ── Recv_buf drain — TOFU sonrası bekleyen frame'leri işle ── */
    for (unsigned pi = 0; pi < NOX_MAX_PEERS; pi++) {
      struct peer_session *ps = &state->peers[pi];
      if (ps->session && ps->fd >= 0 &&
          ps->recv_pos >= FRAME_HEADER_WIRE_SIZE) {
        process_peer_frames(ps, state, ps->fd);
      }
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
        int peer_fd =
            accept4(fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (peer_fd < 0)
          continue;

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
          continue;
        }

        /* Handshake rate limiting — 60 saniyede max 5 deneme. */
        {
          time_t now = time(NULL);
          if (now - state->hs_window_start >= 60) {
            state->hs_attempt_count = 0;
            state->hs_window_start = now;
          }
          if (state->hs_attempt_count >= 5) {
            NOX_WARN(LOG_MOD_NOISE,
                     "Handshake rate limit aşıldı (5/60s) — bağlantı reddedildi");
            ui_print_error(state, "Çok fazla handshake denemesi — biraz bekleyin.");
            close(peer_fd);
            continue;
          }
        }

        listener_ps->fd = peer_fd;
          if (epoll_add_fd(state->epoll_fd, peer_fd) != NOX_OK) {
            NOX_ERROR(LOG_MOD_MAIN, "epoll_ctl ADD başarısız — bağlantı reddedildi");
            close(peer_fd);
            listener_ps->fd = -1;
            continue;
          }

          listener_ps->hs = sodium_malloc(sizeof(struct noise_handshake));
          if (!listener_ps->hs) {
            close(peer_fd);
            listener_ps->fd = -1;
            continue;
          }

          handshake_init(listener_ps->hs, false,
                 state->my_static_priv,
                 state->my_static_pub);
          clock_gettime(CLOCK_MONOTONIC, &listener_ps->handshake_start);
          state->hs_attempt_count++;

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
        if (to_read == 0) continue;

        ssize_t r = recv(fd, ps->recv_buf + ps->recv_pos, to_read, MSG_DONTWAIT);
        if (r <= 0) {
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
          if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
#else
          if (r < 0 && (errno == EAGAIN))
#endif
            break;
          if (r < 0 && errno == EINTR)
            continue;

          NOX_INFO(LOG_MOD_MAIN, "peer bağlantısı kapandı");
          ui_print_system(state, "[*] peer ayrıldı");
          sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
          continue;
        }
        ps->recv_pos += (size_t)r;

        process_peer_frames(ps, state, fd);
      }
    }
  }
}
