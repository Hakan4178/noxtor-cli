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
 * FRAME PROCESSING — recv_buf'daki frame'leri işle
 *
 * Hem EPOLLIN handler'dan hem de epoll_wait öncesi drain'den
 * çağrılır. Bu sayede TOFU_PENDING sonrası bekleyen frame'ler
 * session kurulduktan sonra işlenebilir.
 * ================================================================ */
static void process_peer_frames(struct app_state *state, int fd) {
  while (state->recv_pos >= FRAME_HEADER_WIRE_SIZE) {

    struct frame_header fh;
    if (frame_header_decode(state->recv_buf, &fh) != NOX_OK) {
      state->recv_pos = 0; /* bozuk header — buffer'ı sıfırla */
      break;
    }

    /* A-1 FIX: Boyut sınırı kontrolü */
    if (fh.len == 0 || fh.len > 4096 + NOX_MAC_LEN) {
      NOX_WARN(LOG_MOD_NET, "geçersiz frame boyutu: %u", fh.len);
      state->recv_pos = 0;
      break;
    }

    size_t frame_total = FRAME_HEADER_WIRE_SIZE + fh.len;
    if (state->recv_pos < frame_total)
      break; /* payload henüz tamamlanmadı, bir sonraki EPOLLIN'de devam */

    /* FIX: Session henüz kurulmadıysa TEXT/FILE frame'leri tüketme —
     * recv_buf'da beklesin, session sonrası drain ile işlenecek.
     * TOFU_PENDING sırasında peer mesaj gönderirse bunlar drop edilirdi,
     * bu da seq mismatch'e yol açardı. */
    if ((fh.type == NOX_MSG_TEXT || fh.type == NOX_MSG_FILE) && !state->session) {
      NOX_DEBUG(LOG_MOD_NET,
               "session henüz yok — frame bekletiliyor (type=%u seq=%u recv_pos=%zu)",
               fh.type, fh.seq, state->recv_pos);
      break;
    }

    /* Frame tamamlandı — payload'ı ayıkla */
    assert(fh.len > 0 && fh.len <= 4096 + NOX_MAC_LEN);
    uint8_t *payload = sodium_malloc(fh.len);
    if (!payload) {
      state->recv_pos = 0;
      break;
    }
    memcpy(payload, state->recv_buf + FRAME_HEADER_WIRE_SIZE, fh.len);
    /* M-3 FIX: Frame sonrasındaki kalan byte'ları koru */
    size_t remaining = state->recv_pos - frame_total;
    if (remaining > 0) {
      memmove(state->recv_buf, state->recv_buf + frame_total, remaining);
    }
    state->recv_pos = remaining;

    if (fh.type == NOX_MSG_CTRL && state->hs) {
      uint8_t pl[64];
      size_t pl_len = sizeof(pl);
      nox_err_t hs_err =
          handshake_read(state->hs, payload, fh.len, pl, sizeof(pl), &pl_len);
      if (hs_err != NOX_OK) {
        NOX_ERROR(LOG_MOD_NOISE, "Handshake okuma hatası: %s",
                  nox_strerror(hs_err));
        ui_print_error(
            state, "Akran ile handshake el sıkışması başarısız oldu.");
        sm_dispatch(state, EV_HANDSHAKE_ERROR);
        sodium_free(payload);
        break;
      }

      if (state->hs->msg_index < 3) {
        uint8_t hsbuf[NOISE_MAX_HANDSHAKE_LEN];
        size_t hslen = sizeof(hsbuf);
        nox_err_t hs_write_err = handshake_write(state->hs,
                            (const uint8_t *)state->onion_addr,
                            NOX_ONION_LEN + 1, hsbuf, &hslen);
        if (hs_write_err != NOX_OK) {
          NOX_ERROR(LOG_MOD_NOISE, "handshake_write hatası: %s",
                    nox_strerror(hs_write_err));
          ui_print_error(state, "Handshake yanıtı oluşturulamadı");
          sm_dispatch(state, EV_HANDSHAKE_ERROR);
          sodium_free(payload);
          break;
        }

        struct frame_header rfh = {
            .magic = NOX_FRAME_MAGIC,
            .type = NOX_MSG_CTRL,
            .seq = state->tx_seq,
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
          sm_dispatch(state, EV_HANDSHAKE_ERROR);
          sodium_free(payload);
          break;
        }
        state->tx_seq++;
        NOX_INFO(LOG_MOD_NOISE, "handshake yanıt (tx_seq→%u)", state->tx_seq);
      }

      if (state->hs->msg_index >= 3) {
        char peer_onion[NOX_ONION_LEN + 1];
        sodium_memzero(peer_onion, sizeof(peer_onion));

        if (pl_len == NOX_ONION_LEN + 1 && pl[NOX_ONION_LEN] == '\0') {
          memcpy(peer_onion, pl, NOX_ONION_LEN + 1);
        } else {
          NOX_ERROR(LOG_MOD_NOISE,
                    "Handshake payload geçersiz veya eksik");
          ui_print_error(state, "Akran geçerli bir adres iletmedi");
          sm_dispatch(state, EV_HANDSHAKE_ERROR);
          sodium_free(payload);
          continue;
        }

        char name[NOX_CONTACT_NAME_LEN + 1];
        uint8_t stored_key[NOX_KEY_LEN];
        sodium_memzero(name, sizeof(name));
        sodium_memzero(stored_key, sizeof(stored_key));

        nox_err_t db_err = NOX_ERR_DB;
        if (!state->ghost_mode) {
          db_err = db_get_contact(peer_onion, name, sizeof(name), stored_key, NULL, 0, NULL, NULL);
        }
        uint8_t remote_pub[NOX_KEY_LEN];
        memcpy(remote_pub, state->hs->rs, NOX_KEY_LEN);

        char fp_str[NOX_KEY_LEN * 2 + 1];
        for (size_t k = 0; k < NOX_KEY_LEN; k++) {
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
            state->session =
                arena_alloc(&state->arena, sizeof(struct noise_session));
            if (state->session) {
              if (handshake_split(state->hs, state->session) != NOX_OK) {
                ui_print_error(state, "session split başarısız");
                sm_dispatch(state, EV_HANDSHAKE_ERROR);
                sodium_free(payload);
                continue;
              }
              state->hs = NULL; /* handshake tüketildi — timeout tetiklemesin */
              state->tx_seq = 0;
              state->rx_seq = 0;
              state->queue_flushed = false;
              NOX_DEBUG(LOG_MOD_NOISE,
                        "session setup: tx_seq=0 rx_seq=0 queue_flushed=false");
              state->hs_attempt_count = 0; /* başarılı handshake — sayacı sıfırla */
              strncpy(state->active_peer_onion, peer_onion,
                      NOX_ONION_LEN);
              state->active_peer_onion[NOX_ONION_LEN] = '\0';

              /* State geçişi: HANDSHAKE → ACTIVE */
              state->peer_state = ST_ACTIVE;

              NOX_INFO(LOG_MOD_NOISE,
                       "session kuruldu — mesajlaşma hazır");
              ui_print_system(state, "[✓] şifreli kanal kuruldu (%s)",
                              name);
              ui_reset_sender();
            } else {
              ui_print_error(state, "Arena bellek hatası");
              sm_dispatch(state, EV_ARENA_FAIL);
            }
          } else {
            /* Atomic ANSI: cursor hide → clear → print warning → prompt */
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

            state->tofu_pending = true;
            state->tofu_peer_fd = fd;
            strncpy(state->tofu_onion, peer_onion, NOX_ONION_LEN);
            state->tofu_onion[NOX_ONION_LEN] = '\0';
            strncpy(state->tofu_name, name, NOX_CONTACT_NAME_LEN);
            state->tofu_name[NOX_CONTACT_NAME_LEN] = '\0';
            memcpy(state->tofu_new_key, remote_pub, NOX_KEY_LEN);
            state->tofu_arena_mark = state->session_arena_mark;
            /* State geçişi: HANDSHAKE → TOFU_PENDING */
            state->peer_state = ST_TOFU_PENDING;
          }
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

          char default_name[NOX_CONTACT_NAME_LEN + 1];
          if (db_err == NOX_OK && zero_key && name[0] != '\0') {
            snprintf(default_name, sizeof(default_name), "%s", name);
          } else {
            snprintf(default_name, sizeof(default_name), "peer_%.8s",
                     peer_onion);
          }
          default_name[NOX_CONTACT_NAME_LEN] = '\0';

          state->tofu_pending = true;
          state->tofu_peer_fd = fd;
          strncpy(state->tofu_onion, peer_onion, NOX_ONION_LEN);
          state->tofu_onion[NOX_ONION_LEN] = '\0';
          strncpy(state->tofu_name, default_name, NOX_CONTACT_NAME_LEN);
          state->tofu_name[NOX_CONTACT_NAME_LEN] = '\0';
          memcpy(state->tofu_new_key, remote_pub, NOX_KEY_LEN);
          state->tofu_arena_mark = state->session_arena_mark;
          /* State geçişi: HANDSHAKE → TOFU_PENDING */
          state->peer_state = ST_TOFU_PENDING;
        }
      }
    } else if ((fh.type == NOX_MSG_TEXT || fh.type == NOX_MSG_FILE) &&
               state->session) {
      /* Sequence Number Doğrulaması (Y1) */
      if (fh.seq != state->rx_seq) {
        NOX_WARN(LOG_MOD_NET,
                 "SEQ_MISMATCH: frame type=%u seq=%u beklenen=%u "
                 "tx_seq=%u recv_pos=%zu",
                 fh.type, fh.seq, state->rx_seq,
                 state->tx_seq, state->recv_pos);
        ui_print_error(state,
                       "Hata: Akran bağlantısında geçersiz sıra numarası "
                       "algılandı (Replay Attack veya paket kaybı)!");
        sm_dispatch(state, EV_SEQ_MISMATCH);
        sodium_free(payload);
        break;
      }
      state->rx_seq++;

      if (fh.type == NOX_MSG_TEXT) {
        /* A-1 FIX: sodium_malloc ile swap koruması */
        size_t max_pt = fh.len; /* MAC çıkarılmadan üst sınır */
        uint8_t *pt = sodium_malloc(max_pt + 1);
        if (pt) {
          ssize_t pt_len =
              noise_decrypt(state->session, payload, fh.len, pt);
          /* A-1 FIX: pt_len overflow kontrolü */
          if (pt_len > 0 && (size_t)pt_len <= max_pt) {
            pt[pt_len] = '\0';
            ui_print_incoming(state, (const char *)pt);

            /* BUG-1 FIX: İlk mesaj alındı → kuyruğu gönder */
            if (!state->queue_flushed && !state->ghost_mode) {
              state->queue_flushed = true;
              db_process_queue(state->active_peer_onion,
                               send_queued_callback, state);
            }
          }
          sodium_free(pt); /* otomatik sıfırlar */
        }
      } else if (fh.type == NOX_MSG_FILE) {
        file_transfer_handle_rx(state, payload, fh.len);
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
  struct epoll_event events[4];

  /* ── Landlock sandbox — open/openat/creat'i kısıtla ──────────────
   * Landlock ÖNCE yüklenmeli (seccomp'tan önce).
   * Sadece downloads dizini okunabilir/yazılabilir.
   * Kernel 5.13+ gerektirir, desteklemiyorsa sessizce atlar.
   * no_new_privs ayarlanır — seccomp yüklemesi bundan etkilenmez. */
  bool landlock_active = false;
  if (state->downloads_dir_fd >= 0) {
    if (landlock_sandbox_init(state->downloads_dir_fd) == NOX_OK) {
      landlock_active = true;
    }
  }

  /* ── Stage 3: Sıfır ağ sızıntısı garantisi ────────────────────
   * Tüm mevcut bağlantılar AF_UNIX (Tor control, SOCKS, peer).
   * Event loop tek thread — clone tamamen yasak.
   * TCP/UDP/NETLINK socket oluşturulamaz.
   * open/openat/creat Landlock tarafından kısıtlandıysa, seccomp
   * tarafından da engellenir (defense in depth). */
  if (seccomp_policy_load(3) != NOX_OK) {
    NOX_ERROR(LOG_MOD_MAIN, "seccomp stage 3 yüklenemedi");
    ui_print_error(state, "Güvenlik politikası yüklenemedi.");
    state->running = false;
    return;
  }

  /* ── Komutlar banner'ı — stage 3 sonrası ──────────────────────
   * Banner stage 3'ten sonra basılır: clone/TCP/UDP/NETLINK
   * zaten engellenmiş, sadece fprintf() çalışır. */
  if (!tui_is_active()) {
    if (state->ghost_mode) {
      fprintf(
          stderr,
          "\n  [👻] GHOST MOD — hiçbir veri kaydedilmez, rehber ve kuyruk devre dışı\n\n"
          "  Komutlar:\n"
          "    \033[38;2;210;24;38m/addr               — .onion adresini "
          "göster\033[0m\n"
          "    \033[38;2;224;126;20m/connect <onion>    — peer'a bağlan\033[0m\n"
          "    \033[38;2;31;65;117m/file <dosya_yolu>  — peer'a dosya gönder "
          "(aktif bağlantı gerektirir)\033[0m\n"
          "    \033[38;2;133;60;153mCtrl+P              — çıkış\033[0m\n"
          "  Bağlantı kurulduktan sonra yazdığınız her şey doğrudan mesaj olarak "
          "gönderilir.\n\n"
          "> ");
    } else {
      fprintf(
          stderr,
          "\n  Komutlar:\n"
          "    \033[38;2;210;24;38m/addr               — .onion adresini "
          "göster\033[0m\n"
          "    \033[38;2;224;126;20m/connect <onion>    — peer'a bağlan\033[0m\n"
          "    \033[38;2;202;151;15m/add <onion> <isim> — rehbere kişi "
          "ekle\033[0m\n"
          "    \033[38;2;38;162;105m/msg <onion> <msj>  — çevrimdışı/kuyruklu "
          "mesaj gönder\033[0m\n"
          "    \033[38;2;31;65;117m/file <dosya_yolu>  — peer'a dosya gönder "
          "(aktif bağlantı gerektirir)\033[0m\n"
          "    \033[38;2;133;60;153mCtrl+P              — çıkış\033[0m\n"
          "  Bağlantı kurulduktan sonra yazdığınız her şey doğrudan mesaj olarak "
          "gönderilir.\n\n"
          "> ");
    }
  }

  while (state->running && !g_shutdown) {
    /* Handshake timeout kontrolü (slot yorulması ve kilitlenmeyi önler) */
    if (state->peer_state == ST_HANDSHAKE_INIT ||
        state->peer_state == ST_HANDSHAKE_RESP) {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (now.tv_sec - state->handshake_start.tv_sec > 30) {
        NOX_WARN(LOG_MOD_NOISE, "Handshake zaman aşımına uğradı");
        ui_print_error(state, "Akran ile handshake zaman aşımına uğradı.");
        sm_dispatch(state, EV_HANDSHAKE_TIMEOUT);
      }
    }

    /* C-5 FIX: Dosya transferi timeout — sender sessiz kalırsa 60sn sonra abort */
    if (state->rx_file.active) {
      time_t now = time(NULL);
      if (now - state->rx_file.last_chunk_time > 60) {
        NOX_WARN(LOG_MOD_MAIN, "Dosya transferi zaman aşımı: %s", state->rx_file.filename);
        ui_print_error(state, "Dosya transferi zaman aşımı — sender sessiz.");
        /* Kısmi dosyayı disk'ten sil */
        if (state->downloads_dir_fd >= 0 && state->rx_file.local_name[0] != '\0') {
          unlinkat(state->downloads_dir_fd, state->rx_file.local_name, 0);
        }
        if (state->rx_file.fd >= 0) {
          close(state->rx_file.fd);
        }
        explicit_bzero(&state->rx_file, sizeof(state->rx_file));
        state->rx_file.fd = -1;
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
        sm_dispatch(state, EV_TOR_DIED);
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

    /* ── Recv_buf drain — TOFU sonrası bekleyen frame'leri işle ──
     * TOFU_PENDING sırasında TEXT frame'ler recv_buf'da bekletilmişti.
     * Session oluşturulduktan sonra bunları burada işliyoruz.
     * process_peer_frames while loop'u zaten session kontrolü yapıyor. */
    if (state->session && state->peer_fd >= 0 &&
        state->recv_pos >= FRAME_HEADER_WIRE_SIZE) {
      process_peer_frames(state, state->peer_fd);
    }

    int nfds = epoll_wait(state->epoll_fd, events, 4, 2000);

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
      } else if (fd == state->listen_fd) {
        /* ── Gelen peer bağlantısı ───────── */
        int peer_fd =
            accept4(state->listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (peer_fd < 0)
          continue;

        if (state->peer_state != ST_IDLE) {
          NOX_WARN(LOG_MOD_MAIN, "zaten peer var — reddedildi");
          close(peer_fd);
          continue;
        }

        /* Handshake rate limiting — 60 saniyede max 5 deneme.
         * Sadece yeni bağlantı kabulunda kontrol et, aktif oturumu
         * kesmesin. */
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

        state->peer_fd = peer_fd;
        if (epoll_add_fd(state->epoll_fd, peer_fd) != NOX_OK) {
          /* S2: epoll_ctl başarısız (örn. EMFILE) — fd sızıntısını
           * engelle, "bağlandı" yanılsamasını kır. */
          NOX_ERROR(LOG_MOD_MAIN, "epoll_ctl ADD başarısız — bağlantı reddedildi");
          close(peer_fd);
          state->peer_fd = -1;
          continue;
        }

        state->session_arena_mark = arena_save(&state->arena);
        state->hs = arena_alloc(&state->arena, sizeof(struct noise_handshake));
        if (!state->hs) {
          close(peer_fd);
          state->peer_fd = -1;
          continue;
        }

        handshake_init(state->hs, false,
               state->my_static_priv,
               state->my_static_pub);    
        clock_gettime(CLOCK_MONOTONIC, &state->handshake_start);
        state->hs_attempt_count++;

        /* State geçişi: IDLE → HANDSHAKE_RESP */
        state->peer_state = ST_HANDSHAKE_RESP;

        NOX_INFO(LOG_MOD_MAIN, "gelen peer kabul edildi");
        ui_print_system(state, "[*] gelen bağlantı — handshake bekleniyor");

      } else if (fd == state->peer_fd) {
        /* ── Peer'a Veri Gönderimi (EPOLLOUT) ────── */
        if (events[i].events & EPOLLOUT) {
          if (state->tx_file.active) {
            file_transfer_handle_tx(state);
          } else {
            epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
          }
        }

        /* ── Peer'dan Veri Alımı (EPOLLIN) ───────── */
        if (events[i].events & EPOLLIN) {
          /*
           * TODO (gelecek refactor): Gerçek bir ring buffer + state machine.
           *   State: RECV_MAGIC → RECV_HEADER → RECV_PAYLOAD
           *   Her EPOLLIN'de recv() ile hazır olan kadar oku,
           *   state makinesinde ilerle, eksikse bir sonraki event'e dön.
           *
           * Pragmatik fix: state->recv_buf ile biriktirme.
           * Bloke eden read_full() kaldırıldı — eksik veri gelirse
           * EPOLLIN tekrar tetiklenir ve kaldığı yerden devam eder.
           * recv_buf state struct'ında yaşar — cleanup'ta sıfırlanır.
           */

          /* Buffer'a mümkün olduğunca çok oku */
          int avail = 0;
          if (ioctl(fd, FIONREAD, &avail) < 0) avail = 0;
          size_t space = sizeof(state->recv_buf) - state->recv_pos;
          size_t to_read = (space > (size_t)avail && avail > 0) ? (size_t)avail : space;
          if (to_read == 0) continue; /* buffer dolu — bir sonraki epoll event'ine dön */

          ssize_t r = recv(fd, state->recv_buf + state->recv_pos, to_read, MSG_DONTWAIT);
          if (r <= 0) {
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
#else
            if (r < 0 && (errno == EAGAIN))
#endif
              break; /* veri henüz hazır değil, bir sonraki epoll event'ine dön */
            if (r < 0 && errno == EINTR)
              continue;

            NOX_INFO(LOG_MOD_MAIN, "peer bağlantısı kapandı");
            ui_print_system(state, "[*] peer ayrıldı");
            sm_dispatch(state, EV_PEER_DISCONNECTED);
            continue;
          }
          state->recv_pos += (size_t)r;

          process_peer_frames(state, fd);

        }
      }
    }
  }
}
