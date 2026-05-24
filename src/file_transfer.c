/* SPDX-License-Identifier: GPL-3.0-or-later
 * file_transfer.c — Dosya transfer yönetimi implementasyonu
 */

#include "file_transfer.h"
#include "common.h"
#include "network.h"
#include "noise.h"
#include "ui.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/stat.h>

/* ================================================================
 * YARDIMCI METOTLAR
 * ================================================================ */

/* Dosya adını güvenli hale getirir (path traversal koruması) */
static void sanitize_filename(char *name, size_t max_len) {
  if (!name || max_len == 0)
    return;

  /* 1. Yol ayırıcılarını kes — sadece basename'i al */
  char *slash = strrchr(name, '/');
  if (slash) {
    size_t remain = strlen(slash + 1) + 1;
    memmove(name, slash + 1, remain);
  }

  /* 2. Whitelist filtresi — izin verilmeyen her karakter '_' olur */
  size_t len = strlen(name);
  for (size_t i = 0; i < len; i++) {
    char c = name[i];
    bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    if (!allowed) {
      name[i] = '_';
    }
  }

  /* 3. Ardışık nokta ("..") engelle — her ".." → "__" */
  for (size_t i = 0; i + 1 < len; i++) {
    if (name[i] == '.' && name[i + 1] == '.') {
      name[i] = '_';
      name[i + 1] = '_';
    }
  }

  /* 4. Baştaki nokta ("gizli dosya" veya "." / "..") engelle */
  if (len > 0 && name[0] == '.') {
    name[0] = '_';
  }

  /* 5. Boş ad kontrolü — rastgele hex ID ata */
  len = strlen(name);
  if (len == 0) {
    uint32_t rnd = randombytes_random();
    snprintf(name, max_len, "file_%08x", rnd);
  }
}

/* ================================================================
 * DOSYA TRANSFER BAŞLANGICI (TX)
 * ================================================================ */

void file_transfer_start(struct app_state *state, const char *filepath) {
  /* Çevrimdışı dosya gönderimi desteklenmiyor */
  if (state->peer_fd < 0 || !state->session) {
    ui_print_error(
        state,
        "Çevrimdışı dosyalar kuyruğa alınamaz. Aktif bir bağlantı gerekir.");
    return;
  }

  /* Zaten aktif bir dosya transferi var mı? */
  if (state->tx_file.active) {
    ui_print_error(state, "Zaten aktif bir dosya transferi var.");
    return;
  }

  /* Dosya path kopyası oluştur (basename mutate edebilir) */
  char path_copy[NOX_PATH_MAX];
  size_t path_len = strlen(filepath);
  if (path_len == 0 || path_len >= sizeof(path_copy)) {
    ui_print_error(state, "Geçersiz dosya yolu.");
    return;
  }
  memcpy(path_copy, filepath, path_len + 1);

  /* Dosya var mı, okunabilir mi? */
  struct stat st;
  if (stat(path_copy, &st) != 0) {
    ui_print_error(state, "Dosya bulunamadı: %s", strerror(errno));
    return;
  }
  if (!S_ISREG(st.st_mode)) {
    ui_print_error(state, "Düzenli dosya değil.");
    return;
  }
  if (st.st_size == 0) {
    ui_print_error(state, "Boş dosya gönderilemez.");
    return;
  }

  /* Dosyayı aç */
  int file_fd = open(path_copy, O_RDONLY | O_CLOEXEC);
  if (file_fd < 0) {
    ui_print_error(state, "Dosya açılamadı: %s", strerror(errno));
    return;
  }

  /* basename al, sonra mutlak yolu hemen sil (crash/coredump koruması) */
  char *bname = basename(path_copy);
  char safe_name[256];
  size_t bname_len = strlen(bname);
  if (bname_len >= sizeof(safe_name))
    bname_len = sizeof(safe_name) - 1;
  memcpy(safe_name, bname, bname_len);
  safe_name[bname_len] = '\0';
  explicit_bzero(path_copy, sizeof(path_copy));

  /* Streaming BLAKE2b hash — dosyayı 4KB parçalarla hash'le */
  crypto_generichash_state hash_st;
  crypto_generichash_init(&hash_st, NULL, 0, 32);

  uint8_t hash_buf[4096];
  for (;;) {
    ssize_t r = read(file_fd, hash_buf, sizeof(hash_buf));
    if (r < 0) {
      if (errno == EINTR)
        continue;
      ui_print_error(state, "Dosya okuma hatası: %s", strerror(errno));
      explicit_bzero(hash_buf, sizeof(hash_buf));
      close(file_fd);
      return;
    }
    if (r == 0)
      break;
    crypto_generichash_update(&hash_st, hash_buf, (size_t)r);
  }
  explicit_bzero(hash_buf, sizeof(hash_buf));

  uint8_t file_hash[32];
  crypto_generichash_final(&hash_st, file_hash, 32);

  /* Dosya başına geri sar */
  if (lseek(file_fd, 0, SEEK_SET) != 0) {
    ui_print_error(state, "lseek başarısız.");
    close(file_fd);
    return;
  }

  /* tx_file state'ini kur */
  explicit_bzero(&state->tx_file, sizeof(state->tx_file));
  state->tx_file.active = true;
  state->tx_file.fd = file_fd;
  state->tx_file.total_size = (uint64_t)st.st_size;
  state->tx_file.sent_bytes = 0;
  memcpy(state->tx_file.hash, file_hash, 32);
  memcpy(state->tx_file.filename, safe_name, bname_len + 1);

  /*
   * METADATA frame gönder:
   *   "METADATA\0" (9) + filename (256) + size (8) + hash (32) = 305 byte
   */
  uint8_t meta[305];
  memset(meta, 0, sizeof(meta));
  memcpy(meta, "METADATA", 9);
  memcpy(meta + 9, safe_name, bname_len + 1);
  uint64_t net_size = state->tx_file.total_size;
  /* Big-endian encode */
  meta[265] = (uint8_t)(net_size >> 56);
  meta[266] = (uint8_t)(net_size >> 48);
  meta[267] = (uint8_t)(net_size >> 40);
  meta[268] = (uint8_t)(net_size >> 32);
  meta[269] = (uint8_t)(net_size >> 24);
  meta[270] = (uint8_t)(net_size >> 16);
  meta[271] = (uint8_t)(net_size >> 8);
  meta[272] = (uint8_t)(net_size);
  memcpy(meta + 273, file_hash, 32);

  /* Şifrele ve gönder */
  uint8_t meta_ct[305 + NOX_MAC_LEN];
  ssize_t meta_ct_len =
      noise_encrypt(state->session, meta, sizeof(meta), meta_ct);
  explicit_bzero(meta, sizeof(meta));
  if (meta_ct_len < 0) {
    ui_print_error(state, "Metadata şifreleme hatası.");
    close(file_fd);
    explicit_bzero(&state->tx_file, sizeof(state->tx_file));
    return;
  }

  struct frame_header mfh = {
      .magic = NOX_FRAME_MAGIC,
      .type = NOX_MSG_FILE,
      .seq = state->tx_seq++,
      .len = (uint32_t)meta_ct_len,
  };
  uint8_t mwire[FRAME_HEADER_WIRE_SIZE];
  frame_header_encode(&mfh, mwire);

  if (write_full(state->peer_fd, mwire, FRAME_HEADER_WIRE_SIZE) != NOX_OK ||
      write_full(state->peer_fd, meta_ct, (size_t)meta_ct_len) != NOX_OK) {
    ui_print_error(state, "Metadata gönderim hatası.");
    close(file_fd);
    explicit_bzero(&state->tx_file, sizeof(state->tx_file));
    return;
  }

  /* peer_fd'yi EPOLLIN | EPOLLOUT olarak değiştir */
  epoll_modify_fd(state->epoll_fd, state->peer_fd, EPOLLIN | EPOLLOUT);

  ui_print_system(state, "[*] Dosya transferi başlatıldı: %s (%lu byte)",
                  safe_name, (unsigned long)state->tx_file.total_size);
}

/* ================================================================
 * DOSYA PARÇASI GÖNDERİMİ (TX HANDLER)
 * ================================================================ */

void file_transfer_handle_tx(struct app_state *state) {
  int fd = state->peer_fd;
  if (fd < 0 || !state->tx_file.active) {
    return;
  }

  /* Buffer'da kalan veri varsa önce onu gönder */
  if (state->tx_file.tx_len > 0) {
    ssize_t w =
        write(fd, state->tx_file.tx_buf + state->tx_file.tx_offset,
              state->tx_file.tx_len - state->tx_file.tx_offset);
    if (w > 0) {
      state->tx_file.tx_offset += (size_t)w;
      if (state->tx_file.tx_offset == state->tx_file.tx_len) {
        state->tx_file.tx_len = 0;
        state->tx_file.tx_offset = 0;
        state->tx_file.sent_bytes += state->tx_file.current_chunk_size;
        state->tx_file.current_chunk_size = 0;

        if (state->tx_file.sent_bytes >= state->tx_file.total_size) {
          ui_print_system(state, "[✓] Dosya gönderimi tamamlandı (%lu byte)",
                          (unsigned long)state->tx_file.total_size);
          close(state->tx_file.fd);
          explicit_bzero(&state->tx_file, sizeof(state->tx_file));
          epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
        } else {
          ui_print_progress(state, state->tx_file.filename,
                            state->tx_file.sent_bytes,
                            state->tx_file.total_size, true);
        }
      }
    } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      ui_print_error(state, "Dosya gönderimi koptu (%s)", strerror(errno));
      close(state->tx_file.fd);
      explicit_bzero(&state->tx_file, sizeof(state->tx_file));
      epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
    }
  } else {
    /* Yeni chunk oku ve şifrele */
    uint8_t plain[4096];
    ssize_t r = read(state->tx_file.fd, plain, sizeof(plain));
    if (r > 0) {
      state->tx_file.current_chunk_size = (size_t)r;
      ssize_t ct_len = noise_encrypt(state->session, plain, (size_t)r,
                                     state->tx_file.tx_buf + FRAME_HEADER_WIRE_SIZE);
      explicit_bzero(plain, sizeof(plain));

      if (ct_len > 0) {
        struct frame_header fh = {
            .magic = NOX_FRAME_MAGIC,
            .type = NOX_MSG_FILE,
            .seq = state->tx_seq++,
            .len = (uint32_t)ct_len,
        };
        frame_header_encode(&fh, state->tx_file.tx_buf);
        state->tx_file.tx_len = FRAME_HEADER_WIRE_SIZE + (size_t)ct_len;
        state->tx_file.tx_offset = 0;
      } else {
        ui_print_error(state, "Chunk şifreleme başarısız");
        close(state->tx_file.fd);
        explicit_bzero(&state->tx_file, sizeof(state->tx_file));
        epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
      }
    } else if (r < 0 && errno != EINTR) {
      ui_print_error(state, "Yerel dosya okuma başarısız");
      close(state->tx_file.fd);
      explicit_bzero(&state->tx_file, sizeof(state->tx_file));
      epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
    }
  }
}

/* ================================================================
 * DOSYA ALIMI VE YAZIMI (RX HANDLER)
 * ================================================================ */

void file_transfer_handle_rx(struct app_state *state, const uint8_t *payload, uint32_t len) {
  uint8_t *pt = malloc(4096);
  if (!pt) {
    return;
  }

  ssize_t pt_len = noise_decrypt(state->session, payload, len, pt);
  if (pt_len > 0) {
    if (!state->rx_file.active && pt_len == 305 && memcmp(pt, "METADATA", 9) == 0) {
      /* Yeni dosya transferi (Metadata) */
      char safe_name[256];
      memcpy(safe_name, pt + 9, 256);
      safe_name[255] = '\0';
      sanitize_filename(safe_name, sizeof(safe_name));

      uint64_t net_size =
          ((uint64_t)pt[265] << 56) | ((uint64_t)pt[266] << 48) |
          ((uint64_t)pt[267] << 40) | ((uint64_t)pt[268] << 32) |
          ((uint64_t)pt[269] << 24) | ((uint64_t)pt[270] << 16) |
          ((uint64_t)pt[271] << 8) | ((uint64_t)pt[272]);

      /* Dosya boyut sınırı kontrolü (O1) — NOX_MAX_FILE_SIZE */
      if (net_size == 0 || net_size > NOX_MAX_FILE_SIZE) {
        ui_print_error(state,
                       "Gelen dosya reddedildi: Geçersiz veya çok büyük dosya boyutu (%lu byte)",
                       (unsigned long)net_size);
      } else {
        uint8_t file_hash[32];
        memcpy(file_hash, pt + 273, 32);

        /* Dosyayı diske aç (received_ öneki ile) */
        char recv_path[NOX_PATH_MAX];
        snprintf(recv_path, sizeof(recv_path), "received_%s", safe_name);

        int file_fd = open(recv_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (file_fd >= 0) {
          explicit_bzero(&state->rx_file, sizeof(state->rx_file));
          state->rx_file.active = true;
          state->rx_file.fd = file_fd;
          state->rx_file.expected_size = net_size;
          state->rx_file.received_bytes = 0;
          memcpy(state->rx_file.expected_hash, file_hash, 32);
          strncpy(state->rx_file.filename, safe_name, 255);
          state->rx_file.filename[255] = '\0';

          crypto_generichash_init(&state->rx_file.hash_state, NULL, 0, 32);

          ui_print_system(state, "[⬇] Gelen dosya: %s (%lu byte)", safe_name,
                          (unsigned long)net_size);
        } else {
          ui_print_error(state, "Gelen dosya (%s) oluşturulamadı", safe_name);
        }
      }
    } else if (state->rx_file.active) {
      /* Dosya verisi chunk'ı — beklenen boyuttan fazla veri yazılmasını önle (O3) */
      size_t remaining = state->rx_file.expected_size - state->rx_file.received_bytes;
      if ((size_t)pt_len > remaining) {
        pt_len = (ssize_t)remaining;
      }

      ssize_t w = write(state->rx_file.fd, pt, (size_t)pt_len);
      if (w == pt_len) {
        crypto_generichash_update(&state->rx_file.hash_state, pt, (size_t)pt_len);
        state->rx_file.received_bytes += (size_t)pt_len;

        if (state->rx_file.received_bytes >= state->rx_file.expected_size) {
          uint8_t final_hash[32];
          crypto_generichash_final(&state->rx_file.hash_state, final_hash, 32);

          close(state->rx_file.fd);

          if (memcmp(final_hash, state->rx_file.expected_hash, 32) == 0) {
            ui_print_system(state, "[✓] Dosya başarıyla alındı: %s",
                            state->rx_file.filename);
          } else {
            char bad_path[NOX_PATH_MAX];
            snprintf(bad_path, sizeof(bad_path), "received_%s", state->rx_file.filename);
            unlink(bad_path);
            ui_print_error(state,
                           "HATA: Alınan dosyanın (%s) hash'i uyuşmuyor! Dosya silindi (bütünlük doğrulaması başarısız).",
                           state->rx_file.filename);
          }

          explicit_bzero(&state->rx_file, sizeof(state->rx_file));
        } else {
          ui_print_progress(state, state->rx_file.filename,
                            state->rx_file.received_bytes,
                            state->rx_file.expected_size, false);
        }
      } else {
        char bad_path[NOX_PATH_MAX];
        snprintf(bad_path, sizeof(bad_path), "received_%s", state->rx_file.filename);
        close(state->rx_file.fd);
        unlink(bad_path);
        ui_print_error(state, "Dosyaya yazılamadı, transfer iptal edildi ve yarım kalan dosya silindi.");
        explicit_bzero(&state->rx_file, sizeof(state->rx_file));
      }
    }
  }
  explicit_bzero(pt, 4096);
  free(pt);
}

/* ================================================================
 * TEMİZLİK (CLEANUP)
 * ================================================================ */

void file_transfer_cleanup(struct app_state *state) {
  if (state->tx_file.active) {
    close(state->tx_file.fd);
    explicit_bzero(&state->tx_file, sizeof(state->tx_file));
    ui_print_error(state, "Bağlantı koptuğu için dosya gönderimi iptal edildi.");
  }

  if (state->rx_file.active) {
    char bad_path[NOX_PATH_MAX];
    snprintf(bad_path, sizeof(bad_path), "received_%s", state->rx_file.filename);
    close(state->rx_file.fd);
    unlink(bad_path);
    explicit_bzero(&state->rx_file, sizeof(state->rx_file));
    ui_print_error(state, "Bağlantı koptuğu için dosya alımı iptal edildi ve yarım kalan dosya silindi.");
  }
}
