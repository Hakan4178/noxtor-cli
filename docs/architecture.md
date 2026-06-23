# noxtor-cli Mimari Dokümanı

> Kapsamlı sistem mimarisi: RX/TX yolları, durum makinesi, kripto katmanı, güvenlik savunma katmanları, test kapsamı.

---

## İçindekiler

1. [Genel Bakış](#1-genel-bakış)
2. [Sistem Bileşenleri](#2-sistem-bileşenleri)
3. [RX Yolu (Alma)](#3-rx-yolu-alma)
4. [TX Yolu (Gönderme)](#4-tx-yolu-gönderme)
5. [Durum Makinesi](#5-durum-makinesi)
6. [Kripto Katmanı](#6-kripto-katmanı)
7. [Noise Protokolü](#7-noise-protokolü)
8. [Dosya Transferi](#8-dosya-transferi)
9. [TUI Katmanı](#9-tui-katmanı)
10. [Güvenlik Savunma Katmanları](#10-güvenlik-savunma-katmanları)
11. [Test Kapsamı](#11-test-kapsamı)
12. [Dosya Haritası](#12-dosya-haritası)

---

## 1. Genel Bakış

noxtor-cli, Tor üzerinden anonim mesajlaşma uygulaması. Tek peer bağlantısı, Noise XX protokolü ile şifreli kanal, AF_UNIX socket.

```
┌─────────────────────────────────────────────────────────────┐
│                        noxtor-cli                           │
├─────────┬──────────┬──────────┬──────────┬─────────────────┤
│  TUI/   │  State   │  Noise   │  Frame   │    Network      │
│  stdin  │  Machine │  Crypto  │  Codec   │  (AF_UNIX+Tor)  │
├─────────┴──────────┴──────────┴──────────┴─────────────────┤
│                     Crypto Layer                            │
│  PIN → Argon2id → master_key → subkeys → ChaChaPoly-1305  │
├─────────────────────────────────────────────────────────────┤
│                  Security Layers                            │
│  Seccomp (3-stage) │ Landlock LSM │ Arena (mmap+guards)    │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Sistem Bileşenleri

### 2.1 Kaynak Dosyaları (15 adet)

| Dosya | Satır | Görev |
|-------|-------|-------|
| `src/arena.c` | 640 | mmap tabanlı güvenli bellek havuzu |
| `src/crypto.c` | 697 | Argon2id, Ed25519, Curve25519 dönüşümü |
| `src/database.c` | 1028 | SQLite: kontakt, mesaj kuyruğu, geçmiş |
| `src/event_loop.c` | 639 | Ana epoll event loop, frame işleme |
| `src/file_transfer.c` | 677 | Dosya gönderme/alma (BLAKE2b) |
| `src/landlock_sandbox.c` | 150 | Landlock LSM dosya erişim kontrolü |
| `src/log.c` | 284 | Modül bazlı loglama (TUI entegre) |
| `src/main.c` | 1168 | Başlatma, PIN, key derivation, args |
| `src/network.c` | 1354 | Tor spawn, SOCKS5, epoll, frame encode/decode |
| `src/noise.c` | 912 | Noise XX protocol implementasyonu |
| `src/seccomp.c` | 197 | 3 aşamalı seccomp-bpf loading |
| `src/state_machine.c` | 369 | Peer durum makinesi (8 durum, 16 olay) |
| `src/stdin_handler.c` | 532 | Komut işleme, mesaj segmentasyonu |
| `src/tui.c` | 660 | termbox2 tabanlı TUI (3 panel) |
| `src/ui.c` | 552 | Terminal/ANSI çıktı katmanı |

### 2.2 Header Dosyaları

| Dosya | Görev |
|-------|-------|
| `include/arena.h` | Arena public API |
| `include/common.h` | Sabitler, hata kodları, log makroları |
| `include/types.h` | `app_state`, tüm enum'lar, struct'lar |
| `include/state_machine.h` | State/event enum'ları, SM API |
| `include/tui.h` | TUI API (termbox2 ile compile) |
| `include/ui.h` | UI çıktı API |
| `include/termbox2.h` | Header-only TUI kütüphanesi |

---

## 3. RX Yolu (Alma)

Tor'dan veri gelişi → ekrana mesaj display. Tam yol:

```
Tor daemon
  ↓ (Tor SOCKS5 → AF_UNIX socket)
event_loop.c:347  event_loop()           ← epoll_wait()
  ↓
event_loop.c:120  peer_fd ready          ← EPOLLIN
  ↓
event_loop.c:127  recv(peer_fd)          ← recv_buf'a biriktir
  ↓
event_loop.c:39   process_peer_frames()  ← frame parsing döngüsü
  ↓
network.c:1354    frame_header_decode()  ← 13-byte header decode
  ↓
  ├─ CTRL frame (handshake) ──→ noise.c:765 handshake_read()
  │                               ↓
  │                          noise.c:347 symmetric_decrypt_and_hash()
  │                               ↓
  │                          State: ST_HANDSHAKE_INIT/RESP
  │
  ├─ TEXT frame (mesaj) ────→ noise.c:853 noise_decrypt()
  │                               ↓
  │                          event_loop.c:83 sodium_memcmp(tofu_new_key)
  │                               ↓
  │                          ui.c:396 ui_print_incoming()
  │                               ↓
  │                          tui.c:360 tui_chat_append() veya
  │                          stdout'a atomik yazdırma
  │
  └─ FILE frame (dosya) ───→ file_transfer.c:483 file_transfer_handle_rx()
                                  ↓
                             BLAKE2b hash doğrulama
                             disk'e yazma (O_EXCL, O_NOFOLLOW)
```

### 3.1 RX Anahtar Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `event_loop()` | `event_loop.c:347` | Ana döngü, epoll_wait |
| `process_peer_frames()` | `event_loop.c:39` | Frame parsing + routing |
| `frame_header_decode()` | `network.c:1354` | 13-byte header → struct |
| `recv()` | system call | Ham veri okuma |
| `noise_decrypt()` | `noise.c:853` | ChaChaPoly-1305 AEAD decrypt |
| `handshake_read()` | `noise.c:765` | Noise XX mesaj okuma |
| `file_transfer_handle_rx()` | `file_transfer.c:483` | Dosya frame işleme |
| `ui_print_incoming()` | `ui.c:396` | Mesajı ekrana yazdır |
| `tui_chat_append()` | `tui.c:360` | TUI chat buffer'a ekle |

### 3.2 RX Veri Akışı Detayı

```
1. event_loop() → epoll_wait() → peer_fd EPOLLIN
2. recv(peer_fd, recv_buf + recv_pos, remaining)
   - recv_pos: recv_buf'daki mevcut byte sayısı
   - remaining: RECV_BUF_CAPACITY - recv_pos
   - partial read: sadece mevcut veri kadar okunur
3. process_peer_frames() döngüsü:
   a. recv_pos < sizeof(frame_header)? → break (yetersiz veri)
   b. frame_header_decode() → magic, payload_len kontrolü
   c. recv_pos < 13 + payload_len? → break (yarım frame)
   d. payload = recv_buf + 13
   e. Frame tipine göre routing:
      - CTRL (0x01): handshake_read()
      - TEXT (0x02): noise_decrypt() → display
      - FILE (0x03): file_transfer_handle_rx()
   f. recv_pos -= (13 + payload_len) → kalan frame'leri işle
   g. goto a (döngü devam)
```

---

## 4. TX Yolu (Gönderme)

Kullanıcı girdisi → Tor'a veri gönderme. Tam yol:

```
Kullanıcı (stdin veya TUI)
  ↓
stdin_handler.c:532  process_stdin_events()
  ↓
stdin_handler.c:249  process_line()         ← komut routing
  ↓
  ├─ /connect ──→ state_machine.c:271 action_connect()
  │                    ↓
  │               network.c:1152 socks5_connect()
  │                    ↓
  │               Tor SOCKS5 → onion adresi
  │
  ├─ /add ─────→ database.c:375 db_upsert_contact()
  │
  ├─ /msg ─────→ stdin_handler.c:154 send_segmented_message()
  │                    ↓
  │               stdin_handler.c:34 get_next_chunk_size()
  │               (4000 byte UTF-8 güvenli chunk'lar)
  │                    ↓
  │               noise.c:846 noise_encrypt()
  │                    ↓
  │               network.c:1338 frame_header_encode()
  │                    ↓
  │               writev() ile atomic gönderme
  │
  └─ /file ────→ file_transfer.c:98 file_transfer_start()
                       ↓
                  BLAKE2b hash hesapla
                  METADATA frame gönder
                  EPOLLOUT aktif et
                       ↓
                  file_transfer.c:322 file_transfer_handle_tx()
                  (4KB chunk'lar halinde gönderim)
```

### 4.1 TX Anahtar Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `process_stdin_events()` | `stdin_handler.c:532` | stdin/TUI girdisi oku |
| `process_line()` | `stdin_handler.c:249` | Komut ayrıştır ve yönlendir |
| `send_segmented_message()` | `stdin_handler.c:154` | Uzun mesajı chunk'lara böl |
| `get_next_chunk_size()` | `stdin_handler.c:34` | UTF-8 güvenli chunk noktası bul |
| `noise_encrypt()` | `noise.c:846` | ChaChaPoly-1305 AEAD encrypt |
| `frame_header_encode()` | `network.c:1338` | struct → 13-byte wire format |
| `write_full()` | `network.c:94` | EINTR retry ile tam yazma |
| `file_transfer_start()` | `file_transfer.c:98` | Dosya transferini başlat |
| `file_transfer_handle_tx()` | `file_transfer.c:322` | 4KB chunk gönderimi |

### 4.2 TX Frame Yapısı

```
┌──────────────────────────────────────────┐
│ Frame Header (13 byte)                   │
│  magic:   4 byte (0xDEADC0DE)           │
│  type:    1 byte (CTRL/TEXT/FILE)        │
│  seq:     4 byte (sequence number)       │
│  payload_len: 4 byte (big-endian)        │
├──────────────────────────────────────────┤
│ Payload (0-4096 byte)                    │
│  şifrelenmiş: ChaChaPoly-1305 AEAD      │
├──────────────────────────────────────────┤
│ MAC (16 byte)                            │
│  Poly1305 authentication tag             │
└──────────────────────────────────────────┘
```

### 4.3 Atomic Gönderim (writev)

```
struct iovec iov[2];
iov[0].iov_base = header;    // 13 byte
iov[0].iov_len  = 13;
iov[1].iov_base = ciphertext; // payload + MAC
iov[1].iov_len  = payload_len + NOX_MAC_LEN;
writev(peer_fd, iov, 2);     // kernel atomik garantisi (AF_UNIX)
```

---

## 5. Durum Makinesi

### 5.1 Durumlar (peer_state_t)

```c
ST_IDLE              // Bağlantı yok, listener aktif
ST_CONNECTING        // SOCKS5 bağlantısı kuruluyor (outbound)
ST_HANDSHAKE_INIT    // Noise XX handshake başlatıcı (outbound)
ST_HANDSHAKE_RESP    // Noise XX handshake yanıtlayıcı (inbound)
ST_TOFU_PENDING      // Kullanıcı TOFU onayı bekliyor
ST_ACTIVE            // Şifreli kanal aktif — mesajlaşma hazır
ST_FILE_TX           // Dosya gönderimi devam ediyor
ST_FILE_RX           // Dosya alımı devam ediyor
```

### 5.2 Olaylar (peer_event_t)

```c
EV_CONNECT_CMD         // /connect komutu
EV_PEER_ACCEPTED       // accept4() başarılı (inbound)
EV_HANDSHAKE_MSG       // Handshake mesajı alındı
EV_HANDSHAKE_DONE      // Noise XX tamamlandı — TOFU gerekli
EV_SESSION_READY       // Bilinen peer — doğrudan session kur
EV_TOFU_ACCEPTED       // Kullanıcı 'y' dedi
EV_TOFU_REJECTED       // Kullanıcı 'n' dedi
EV_PEER_DISCONNECTED   // Soket kapandı / hata
EV_HANDSHAKE_TIMEOUT   // 30s timeout
EV_HANDSHAKE_ERROR     // Handshake okuma/yazma hatası
EV_FILE_START          // /file komutu veya METADATA frame
EV_FILE_DONE           // Transfer tamamlandı
EV_RATE_LIMIT          // Rate limit aşıldı
EV_SEQ_MISMATCH        // Beklenmeyen sequence number
EV_ARENA_FAIL          // Arena allocation başarısız
EV_TOR_DIED            // Tor process öldü
```

### 5.3 Geçiş Tablosu (39 geçiş)

```
┌──────────────────┬─────────────────────┬──────────────────┬─────────────────────┐
│ Kaynak Durum     │ Olay                │ Hedef Durum      │ Action              │
├──────────────────┼─────────────────────┼──────────────────┼─────────────────────┤
│ ST_IDLE          │ EV_CONNECT_CMD      │ ST_HANDSHAKE_INIT│ action_connect      │
│ ST_IDLE          │ EV_PEER_ACCEPTED    │ ST_HANDSHAKE_RESP│ action_accept       │
│ ST_CONNECTING    │ EV_PEER_ACCEPTED    │ ST_HANDSHAKE_INIT│ action_connect      │
│ ST_HANDSHAKE_INIT│ EV_HANDSHAKE_MSG    │ ST_HANDSHAKE_INIT│ action_hs_process   │
│ ST_HANDSHAKE_INIT│ EV_HANDSHAKE_DONE   │ ST_TOFU_PENDING  │ action_tofu_prompt  │
│ ST_HANDSHAKE_INIT│ EV_SESSION_READY    │ ST_ACTIVE        │ action_session_up   │
│ ST_HANDSHAKE_INIT│ EV_HANDSHAKE_TIMEOUT│ ST_IDLE          │ action_cleanup      │
│ ST_HANDSHAKE_INIT│ EV_HANDSHAKE_ERROR  │ ST_IDLE          │ action_cleanup      │
│ ST_HANDSHAKE_INIT│ EV_PEER_DISCONNECTED│ ST_IDLE          │ action_cleanup      │
│ ST_HANDSHAKE_INIT│ EV_TOR_DIED         │ ST_IDLE          │ action_cleanup      │
│ ST_HANDSHAKE_RESP│ EV_HANDSHAKE_MSG    │ ST_HANDSHAKE_RESP│ action_hs_process   │
│ ST_HANDSHAKE_RESP│ EV_HANDSHAKE_DONE   │ ST_TOFU_PENDING  │ action_tofu_prompt  │
│ ST_HANDSHAKE_RESP│ EV_SESSION_READY    │ ST_ACTIVE        │ action_session_up   │
│ ST_HANDSHAKE_RESP│ EV_HANDSHAKE_TIMEOUT│ ST_IDLE          │ action_cleanup      │
│ ST_HANDSHAKE_RESP│ EV_HANDSHAKE_ERROR  │ ST_IDLE          │ action_cleanup      │
│ ST_HANDSHAKE_RESP│ EV_PEER_DISCONNECTED│ ST_IDLE          │ action_cleanup      │
│ ST_HANDSHAKE_RESP│ EV_TOR_DIED         │ ST_IDLE          │ action_cleanup      │
│ ST_TOFU_PENDING  │ EV_TOFU_ACCEPTED    │ ST_ACTIVE        │ action_tofu_accept  │
│ ST_TOFU_PENDING  │ EV_TOFU_REJECTED    │ ST_IDLE          │ action_cleanup      │
│ ST_TOFU_PENDING  │ EV_PEER_DISCONNECTED│ ST_IDLE          │ action_cleanup      │
│ ST_TOFU_PENDING  │ EV_TOR_DIED         │ ST_IDLE          │ action_cleanup      │
│ ST_ACTIVE        │ EV_FILE_START       │ ST_FILE_TX       │ action_file_begin   │
│ ST_ACTIVE        │ EV_PEER_DISCONNECTED│ ST_IDLE          │ action_cleanup      │
│ ST_ACTIVE        │ EV_SEQ_MISMATCH     │ ST_IDLE          │ action_cleanup      │
│ ST_ACTIVE        │ EV_TOR_DIED         │ ST_IDLE          │ action_cleanup      │
│ ST_FILE_TX       │ EV_FILE_DONE        │ ST_ACTIVE        │ action_file_end     │
│ ST_FILE_TX       │ EV_PEER_DISCONNECTED│ ST_IDLE          │ action_cleanup      │
│ ST_FILE_TX       │ EV_TOR_DIED         │ ST_IDLE          │ action_cleanup      │
│ ST_FILE_RX       │ EV_FILE_DONE        │ ST_ACTIVE        │ action_file_end     │
│ ST_FILE_RX       │ EV_PEER_DISCONNECTED│ ST_IDLE          │ action_cleanup      │
│ ST_FILE_RX       │ EV_TOR_DIED         │ ST_IDLE          │ action_cleanup      │
│ ... (tüm durumlar için EV_PEER_DISCONNECTED → ST_IDLE)                       │
└──────────────────┴─────────────────────┴──────────────────┴─────────────────────┘
```

### 5.4 Yaşam Döngüsü Diyagramı

```
Outbound (biz bağlanıyoruz):
  ST_IDLE ──EV_CONNECT_CMD──→ ST_HANDSHAKE_INIT
                                    │
                    ┌───────────────┼───────────────┐
                    ↓               ↓               ↓
            EV_HANDSHAKE_MSG  EV_SESSION_READY  EV_HANDSHAKE_DONE
            (devam)           (bilinen peer)    (yeni peer)
                    ↓               ↓               ↓
            ST_HANDSHAKE_INIT  ST_ACTIVE      ST_TOFU_PENDING
                    ↓                               │
            EV_HANDSHAKE_DONE               ┌───────┼───────┐
                    ↓                       ↓               ↓
            ST_TOFU_PENDING          EV_TOFU_ACCEPTED  EV_TOFU_REJECTED
                    ↓                       ↓               ↓
               (kullanıcı onayı)       ST_ACTIVE         ST_IDLE

Inbound (bize bağlanılıyor):
  ST_IDLE ──EV_PEER_ACCEPTED──→ ST_HANDSHAKE_RESP
                                    │
                    ┌───────────────┼───────────────┐
                    ↓               ↓               ↓
            EV_HANDSHAKE_MSG  EV_SESSION_READY  EV_HANDSHAKE_DONE
                    ↓               ↓               ↓
            ST_HANDSHAKE_RESP  ST_ACTIVE      ST_TOFU_PENDING

Herhangi bir durumda:
  EV_PEER_DISCONNECTED → action_cleanup() → ST_IDLE
  EV_TOR_DIED → action_cleanup() → ST_IDLE
```

### 5.5 Action Fonksiyonları

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `sm_dispatch()` | `state_machine.c:181` | Ana dispatch motoru |
| `action_cleanup()` | `state_machine.c:216` | fd kapat, key sıfırla, arena restore |
| `action_connect()` | `state_machine.c:271` | Outbound connect (stub) |
| `action_accept()` | `state_machine.c:278` | Inbound accept (stub) |
| `action_hs_process()` | `state_machine.c:285` | Handshake işleme (stub) |
| `action_tofu_prompt()` | `state_machine.c:292` | TOFU onayı iste |
| `action_tofu_accept()` | `state_machine.c:299` | TOFU onayla: DB'ye kaydet, session kur |
| `action_session_up()` | `state_machine.c:355` | Session hazır (stub) |
| `action_file_begin()` | `state_machine.c:362` | Dosya transferi başlat (stub) |
| `action_file_end()` | `state_machine.c:369` | Dosya transferi bitir (stub) |

---

## 6. Kripto Katmanı

### 6.1 Key Hiyerarşisi

```
PIN (8-128 byte, kullanıcı girdisi)
  ↓
Argon2id (OPSLIMIT_MODERATE, MEMLIMIT_MODERATE)
  ↓ salt: 16 byte (dosyadan veya yeni üretilen)
  ↓
master_key (32 byte) ───→ sodium_malloc guard
  ↓
crypto_kdf_derive_from_key (BLAKE2b)
  ↓
  ├─ db_key (32 byte)            ← NOX_SUBKEY_DB = 1
  ├─ identity_unlock (32 byte)   ← NOX_SUBKEY_IDENTITY_UNLOCK = 2
  └─ session_key (32 byte)       ← NOX_SUBKEY_SESSION = 3
```

### 6.2 Identity Key Çözümü

```
identity.key (disk, XChaCha20-Poly1305 şifreli)
  ↓
crypto_load_identity() ile unlock_key ile çöz
  ↓
Ed25519 secret key (64 byte)
  ↓
crypto_ed25519_to_curve25519() dönüştür
  ↓
my_static_priv (32 byte, Curve25519) → arena'da
my_static_pub  (32 byte, Curve25519) → arena'da
```

### 6.3 Transport Şifreleme

```
Session established:
  session->tx: CipherState (gönderme)
  session->rx: CipherState (alma)

noise_encrypt(session, plaintext):
  ChaChaPoly-1305 AEAD
  nonce: atomic counter (8→12 byte encoding)
  key: session->tx.k
  AD: boş
  → ciphertext + 16 byte MAC

noise_decrypt(session, ciphertext):
  ChaChaPoly-1305 AEAD decrypt
  nonce: atomic counter
  key: session->rx.k
  → plaintext veya ERROR
```

### 6.4 Kripto Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `crypto_global_init()` | `crypto.c:147` | libsodium init |
| `crypto_derive_master_key()` | `crypto.c:184` | PIN → Argon2id → master_key |
| `crypto_derive_subkeys()` | `crypto.c:235` | master_key → 3 subkey |
| `crypto_load_or_create_salt()` | `crypto.c:281` | Salt yönetimi (atomic write) |
| `crypto_generate_identity()` | `crypto.c:413` | Ed25519 keypair üret + şifrele |
| `crypto_load_identity()` | `crypto.c:544` | identity.key çöz ve yükle |
| `crypto_ed25519_to_curve25519()` | `crypto.c:632` | Ed25519 → Curve25519 dönüştür |
| `cipher_encrypt()` | `noise.c:66` | ChaChaPoly-1305 AEAD encrypt |
| `cipher_decrypt()` | `noise.c:99` | ChaChaPoly-1305 AEAD decrypt |

---

## 7. Noise Protokolü

### 7.1 Pattern: XX_25519_ChaChaPoly_BLAKE2b

```
Prologue: "Mustafa Kemal Ataturk" (sabit, her iki taraf için aynı)

Msg0 (Initiator → Responder):
  e (ephemeral key, 32 byte)
  payload: boş

Msg1 (Responder → Initiator):
  e (ephemeral key, 32 byte)
  ee (DH: re_re)
  s (static key, 32 byte, encrypted)
  es (DH: re_si)
  payload: boş

Msg2 (Initiator → Responder):
  se (DH: si_re)
  s (static key, 32 byte, encrypted)
  payload: boş
```

### 7.2 SymmetricState İşlemleri

```
Init:  h = BLAKE2b("Noise_XX_25519_ChaChaPoly_BLAKE2b")
       ck = h

MixHash(data):    h = BLAKE2b(h || data)
MixKey(ikm):      (ck, k) = HKDF(ck, ikm)
EncryptAndHash(plaintext):
  ciphertext = ChaPoly(k, nonce++, AD=h, plaintext)
  h = BLAKE2b(h || ciphertext)
  return ciphertext

Split():  (tx, rx) = HKDF(ck, "")
          → iki bağımsız CipherState
```

### 7.3 Noise Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `handshake_init()` | `noise.c:459` | XX handshake başlat |
| `handshake_write()` | `noise.c:615` | Sıradaki handshake mesajını yaz |
| `handshake_read()` | `noise.c:765` | Gelen handshake mesajını oku |
| `handshake_is_complete()` | `noise.c:807` | Handshake tamamlandı mı? |
| `handshake_split()` | `noise.c:811` | Session'a dönüştür |
| `noise_encrypt()` | `noise.c:846` | Transport encrypt |
| `noise_decrypt()` | `noise.c:853` | Transport decrypt |
| `symmetric_init()` | `noise.c:142` | SymmetricState başlat |
| `symmetric_mix_hash()` | `noise.c:164` | MixHash |
| `symmetric_mix_key()` | `noise.c:314` | MixKey (HKDF) |
| `symmetric_encrypt_and_hash()` | `noise.c:335` | EncryptAndHash |
| `symmetric_decrypt_and_hash()` | `noise.c:347` | DecryptAndHash |
| `symmetric_split()` | `noise.c:384` | Split → tx/rx CipherState |

---

## 8. Dosya Transferi

### 8.1 TX Akışı

```
/file /path/to/file
  ↓
file_transfer_start()                    [file_transfer.c:98]
  ├─ open(filepath, O_RDONLY)
  ├─ fstat() → dosya boyutu
  ├─ BLAKE2b hash hesapla (boyut dahil)
  ├─ METADATA frame gönder:
  │    type=FILE, subtype=METADATA
  │    payload: filename_len(1) + filename + filesize(8) + hash(32)
  └─ EPOLLOUT aktif et
  ↓
file_transfer_handle_tx()                [file_transfer.c:322]
  ├─ read(fd, chunk, 4096)
  ├─ noise_encrypt(chunk)
  ├─ frame_header_encode() + writev()
  └─ devam ederse EPOLLOUT tekrar tetiklenir
  ↓
Tamamlandı:
  ├─ EOF → son frame gönder
  ├─ EPOLLOUT deaktif et
  └─ State: ST_FILE_TX → ST_ACTIVE
```

### 8.2 RX Akışı

```
FILE frame geldi → process_peer_frames()
  ↓
file_transfer_handle_rx()                [file_transfer.c:483]
  ├─ METADATA frame?
  │    ├─ dosya adını sanitize et (whitelist filter)
  │    ├─ downloads_dir_fd ile openat() (TOCTOU koruması)
  │    ├─ O_EXCL + O_NOFOLLOW ile aç
  │    ├─ hash_obj = BLAKE2b_init()
  │    └─ State: ST_ACTIVE → ST_FILE_RX
  │
  └─ DATA frame?
       ├─ write_to_file(fd, data, len)
       ├─ BLAKE2b_update(hash_obj, data, len)
       └─ chunk sayacı × 4096 ≥ filesize?
            ├─ Hayır → devam
            └─ Evet → BLAKE2b_final()
                      hash eşleşiyor mu?
                      ├─ Evet → dosya tamam
                      ├─ Hayır → dosyayı sil, hata
                      └─ State: ST_FILE_TX → ST_ACTIVE
```

### 8.3 Dosya Transferi Güvenlik Önlemleri

| Önlem | Açıklama |
|-------|----------|
| `sanitize_filename()` | Path traversal engeli, whitelist karakter |
| `O_EXCL` | Yarış koşulu: dosya zaten varsa hata |
| `O_NOFOLLOW` | Symlink izleme engeli |
| `openat()` | TOCTOU koruması: fd-based erişim |
| `verify_downloads_dir()` | Downloads dizini symlink değil, UID eşleşmesi |
| BLAKE2b hash | Dosya bütünlük doğrulaması |
| `file_transfer_cleanup()` | Kısmi dosyaları sil |

### 8.4 Dosya Transferi Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `file_transfer_start()` | `file_transfer.c:98` | TX başlat |
| `file_transfer_handle_tx()` | `file_transfer.c:322` | TX chunk gönder |
| `file_transfer_handle_rx()` | `file_transfer.c:483` | RX frame işle |
| `file_transfer_cleanup()` | `file_transfer.c:677` | Temizlik |
| `sanitize_filename()` | `file_transfer.c:28` | Dosya adı temizleme |
| `verify_downloads_dir()` | `file_transfer.c:81` | Downloads dizin doğrulama |
| `open_recv_file()` | `file_transfer.c:433` | Güvenli dosya açma |
| `write_to_file()` | `file_transfer.c:417` | Kısmi yazma yardımı |

---

## 9. TUI Katmanı

### 9.1 İki Mod

| Mod | Derleme | Kullanım |
|-----|---------|----------|
| ANSI Terminal | `make` (varsayılan) | stdout/stdin, ANSI escape |
| termbox2 TUI | `make TUI=1` | 3 panel layout, truecolor |

### 9.2 TUI Layout

```
┌─────────────────┬──────────────────────────────────────┐
│   KONTAKTLAR    │              SOHBET                   │
│                 │                                      │
│  ● alice (ON)   │  [20:30:15] alice: Merhaba!          │
│  ○ bob          │  [20:30:20] Sen: Nasılsın?           │
│  ○ charlie      │  [20:30:25] alice: İyiyim, teşekkür │
│                 │                                      │
│                 │                                      │
├─────────────────┴──────────────────────────────────────┤
│ nox> ▌                                                 │
└────────────────────────────────────────────────────────┘
```

### 9.3 TUI Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `tui_init()` | `tui.c:159` | termbox2 başlat |
| `tui_shutdown()` | `tui.c:204` | Temizlik |
| `tui_resize()` | `tui.c:219` | Terminal yeniden boyutlandırma |
| `tui_draw_sidebar()` | `tui.c:276` | Kontakt listesi çiz |
| `tui_draw_chat()` | `tui.c:473` | Sohbet paneli çiz |
| `tui_draw_input()` | `tui.c:525` | Giriş paneli çiz |
| `tui_refresh_all()` | `tui.c:563` | Tam yeniden çizim |
| `tui_chat_append()` | `tui.c:360` | Chat buffer'a ekle |
| `tui_chat_append_colored()` | `tui.c:365` | Renkli chat buffer |
| `tui_handle_input()` | `tui.c:581` | Klavye girdisi işle |
| `tui_print_welcome()` | `tui.c:187` | Hoşgeldin mesajı |
| `tui_load_contacts()` | `tui.c:250` | DB'den kontakt yükle |

### 9.4 UI Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `ui_init()` | `ui.c:77` | Tema ayarla |
| `ui_print_incoming()` | `ui.c:396` | Gelen mesaj yazdır |
| `ui_print_outgoing()` | `ui.c:416` | Giden mesaj yazdır |
| `ui_print_system()` | `ui.c:438` | Sistem mesajı yazdır |
| `ui_print_error()` | `ui.c:480` | Hata mesajı yazdır |
| `ui_print_progress()` | `ui.c:552` | Dosya transfer ilerleme çubuğu |
| `ui_print_prompt()` | `ui.c:239` | Prompt çiz |
| `atomic_message()` | `ui.c:361` | Atomik terminal çıktısı |
| `clear_prompt_area()` | `ui.c:132` | Prompt alanını temizle |

---

## 10. Güvenlik Savunma Katmanları

### 10.1 Katman Haritası

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Uygulama Güvenliği                             │
│  • Arena honeypot canaries (key'ler arası sahte keyler) │
│  • sodium_memzero() ile hassas veri sıfırlama           │
│  • PR_SET_DUMPABLE=0 (core dump engeli)                 │
├─────────────────────────────────────────────────────────┤
│ Layer 6: Kripto Güvenliği                               │
│  • Argon2id (memory-hard KDF)                           │
│  • ChaChaPoly-1305 AEAD (transport)                     │
│  • Ed25519 → Curve25519 dönüşümü                        │
│  • Sabit zamanlı karşılaştırma (sodium_memcmp)          │
├─────────────────────────────────────────────────────────┤
│ Layer 5: Bellek Güvenliği                               │
│  • Arena: mmap + MAP_LOCKED + guard pages (PROT_NONE)   │
│  • MADV_DONTFORK (fork'ta kopyalanma)                   │
│  • MADV_DONTDUMP (core dump'ta gizleme)                 │
│  • Canary: arena bütünlük kontrolü                      │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Dosya Güvenliği                                │
│  • Landlock LSM:RW: erişilebilir dizinler beyaz liste   │
│  • O_NOFOLLOW: symlink izleme engeli                    │
│  • O_EXCL: yarış koşulu koruması                        │
│  • TOCTOU: openat() + fd-based erişim                   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Ağ Güvenliği                                  │
│  • AF_UNIX socket (AF_INET engelli)                     │
│  • Tor SOCKS5 proxy üzerinden iletişim                  │
│  • Seccomp stage 3: AF_INET, AF_INET6, TCP, UDP engelli│
│  • writev() atomic gönderim (AF_UNIX kernel garantisi)  │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Sistem Çağrısı Kısıtlamaları                  │
│  • Seccomp stage 1 (constructor):                       │
│    io_uring, ptrace, process_vm_readv, kexec, bpf,      │
│    mount, umount2, pivot_root, personality, unshare     │
│  • Seccomp stage 2 (key_derive sonrası):                │
│    fork, clone, vfork, execve, execveat, umount,        │
│    swapon, swapoff, mount, sethostname, setdomainname,  │
│    init_module, finit_module, delete_module,            │
│    capset, capget, ptrace (tekrar), keyctl              │
│  • Seccomp stage 3 (Tor spawn sonrası):                 │
│    AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM,          │
│    DNS resolution (getaddrinfo)                          │
├─────────────────────────────────────────────────────────┤
│ Layer 1: Process İzolasyonu                             │
│  • TSYNC: 32-bit seccomp bypass engeli                  │
│  • NO_NEW_PRIVS: setuid escalation engeli               │
│  • PR_SET_DUMPABLE=0: /proc/PID/mem engeli              │
└─────────────────────────────────────────────────────────┘
```

### 10.2 Seccomp Aşamaları

```
Stage 1 (constructor, main'den bile önce):
  ├─ time, clock_gettime, nanosleep           ← izinli
  ├─ mmap, munmap, mprotect, mremap           ← izinli
  ├─ read, write, close, fstat, lseek         ← izinli
  ├─ ioctl, fcntl, dup, dup2                  ← izinli
  ├─ rt_sigaction, rt_sigprocmask             ← izinli
  ├─ madvise, mlock, prctl (sadece PR_SET_VMA)← izinli
  ├─ io_uring_* → SIGSYS                      ← engelli
  ├─ ptrace → SIGSYS                          ← engelli
  ├─ process_vm_readv/writev → SIGSYS         ← engelli
  ├─ kexec_file_load → SIGSYS                 ← engelli
  ├─ bpf → SIGSYS                             ← engelli
  ├─ mount, umount2, pivot_root → SIGSYS      ← engelli
  ├─ personality → SIGSYS                     ← engelli
  └─ unshare → SIGSYS                         ← engelli

Stage 2 (key_derive sonrası):
  ├─ fork, clone, vfork → SIGSYS              ← engelli
  ├─ execve, execveat → SIGSYS                ← engelli
  ├─ umount, umount2 → SIGSYS                 ← engelli
  ├─ swapon, swapoff → SIGSYS                 ← engelli
  ├─ mount → SIGSYS                           ← engelli
  ├─ sethostname, setdomainname → SIGSYS      ← engelli
  ├─ init_module, finit_module → SIGSYS       ← engelli
  ├─ delete_module → SIGSYS                   ← engelli
  ├─ capset, capget → SIGSYS                  ← engelli
  ├─ ptrace → SIGSYS                          ← engelli
  └─ keyctl → SIGSYS                          ← engelli

Stage 3 (Tor spawn sonrası):
  ├─ AF_INET, AF_INET6 → SIGSYS               ← engelli
  ├─ SOCK_STREAM, SOCK_DGRAM (non-AF_UNIX)    ← engelli
  ├─ getaddrinfo(DNS) → SIGSYS                ← engelli
  ├─ AF_NETLINK → SIGSYS                      ← engelli
  └─ AF_UNIX → izinli (peer bağlantısı)
```

### 10.3 Arena Bellek Topolojisi

```
┌──────────────────────────────────┐
│ Lower Guard Page (PROT_NONE)     │ ← SIGSEGV (underflow)
├──────────────────────────────────┤
│ Usable Area (RW)                 │
│  master_key        32 byte       │ ← gerçek key
│  ─── canary        32 byte       │ ← honeypot (rastgele)
│  db_key            32 byte       │ ← gerçek key
│  ─── canary        32 byte       │ ← honeypot
│  identity_unlock   32 byte       │ ← gerçek key
│  ─── canary        32 byte       │ ← honeypot
│  session_key       32 byte       │ ← gerçek key
│  ─── canary        32 byte       │ ← honeypot
│  my_static_priv    32 byte       │ ← gerçek key
│  ─── canary        32 byte       │ ← honeypot
│  my_static_pub     32 byte       │ ← gerçek key
│  ... (handshake/session structs) │
├──────────────────────────────────┤
│ Canary Zone (16 byte)            │ ← arena bütünlük
├──────────────────────────────────┤
│ Upper Guard Page (PROT_NONE)     │ ← SIGSEGV (overflow)
└──────────────────────────────────┘
```

---

## 11. Test Kapsamı

### 11.1 Unit Testler (67/67)

| Test Dosyası | Test Sayısı | Kapsadığı Fonksiyonlar |
|--------------|-------------|------------------------|
| `test_arena.c` | 14 | arena_init, arena_alloc, arena_alloc_canary, arena_destroy, canary check |
| `test_crypto.c` | 10 | Argon2id, subkey derivation, salt, identity roundtrip, Ed25519→Curve25519 |
| `test_database.c` | 5 | DB open/close, contacts, wrong key, queue, history |
| `test_network.c` | 7 | Frame encode/decode, listener create, UTF-8 chunking |
| `test_noise.c` | 8 | Null safety, loopback handshake, transport roundtrip, MAC tamper, spec vectors |
| `test_pin.c` | 12 | PIN validation (min, max, empty, null, control chars, UTF-8, spaces) |
| `test_seccomp_stage3.c` | 11 | AF_INET, AF_INET6, clone, DNS, connect, AF_NETLINK, AF_UNIX, prctl |

### 11.2 Formal Doğrulama (CBMC + ESBMC)

| Kaynak | CBMC | ESBMC | Assertion | Durum |
|--------|------|-------|-----------|-------|
| `arena.c` | ✅ | ✅ | 956 | VERIFICATION SUCCESSFUL |
| `state_machine.c` | ✅ | ✅ | 678 | VERIFICATION SUCCESSFUL |
| `log.c` | ✅ | ✅ | — | VERIFICATION SUCCESSFUL |
| `stdin_handler.c` | ✅ | ✅ | — | VERIFICATION SUCCESSFUL |
| `noise.c` (easy) | ✅ | ✅ | — | VERIFICATION SUCCESSFUL |
| `crypto.c` | ✅ | ✅ | — | VERIFICATION SUCCESSFUL |

### 11.3 Fuzz Testler

| Fuzz Hedefi | Dosya | Kapsadığı |
|-------------|-------|-----------|
| `fuzz_frame_decode` | `fuzz/fuzz_frame_decode.c` | frame_header_decode |
| `fuzz_sanitize` | `fuzz/fuzz_sanitize.c` | sanitize_filename |
| `fuzz_arena` | `fuzz/fuzz_arena.c` | arena_alloc |
| `fuzz_stdin` | `fuzz/fuzz_stdin.c` | process_line |
| `fuzz_file_transfer` | `fuzz/fuzz_file_transfer.c` | file_transfer_handle_rx |
| `fuzz_stdin_events` | `fuzz/fuzz_stdin_events.c` | process_stdin_events |
| `fuzz_ctrl` | `fuzz/fuzz_ctrl.c` | tor_control |
| `fuzz_socks5` | `fuzz/fuzz_socks5.c` | socks5_connect |
| `fuzz_handshake` | `fuzz/fuzz_handshake.c` | handshake_read |
| `fuzz_noise_differential` | `tests/fuzz_noise_differential.c` | Noise-c referans kütüphane ile differential testing |

### 11.4 Çalıştırma

```bash
# Unit testler
make test                    # 67/67, ASan+UBSan altında

# Formal doğrulama
./tests/formal-verify.sh     # Tümü (CBMC + ESBMC)
./tests/formal-verify.sh arena    # Sadece arena
./tests/formal-verify.sh sm       # Sadece state machine

# Fuzz testler
make fuzz                    # Tüm fuzz hedefleri
```

---

## 12. Dosya Haritası

```
noxtor-cli/
├── include/
│   ├── arena.h              # Arena API
│   ├── common.h             # Sabitler, hata kodları
│   ├── event_loop.h         # Event loop API
│   ├── file_transfer.h      # Dosya transfer API
│   ├── landlock_sandbox.h   # Landlock API
│   ├── log.h                # Log API
│   ├── network.h            # Network API
│   ├── noise.h              # Noise API
│   ├── seccomp.h            # Seccomp API
│   ├── state_machine.h      # State machine API
│   ├── stdin_handler.h      # Stdin handler API
│   ├── termbox2.h           # Header-only TUI kütüphanesi
│   ├── tui.h                # TUI API
│   ├── types.h              # app_state, enum'lar
│   └── ui.h                 # UI API
├── src/
│   ├── arena.c              # mmap + guard pages + canary
│   ├── crypto.c             # Argon2id + Ed25519 + Curve25519
│   ├── database.c           # SQLite + encryption
│   ├── event_loop.c         # epoll + frame processing
│   ├── file_transfer.c      # BLAKE2b + streaming
│   ├── landlock_sandbox.c   # Landlock LSM
│   ├── log.c                # Module-based logging
│   ├── main.c               # Entry point + key derivation
│   ├── network.c            # Tor + SOCKS5 + frame codec
│   ├── noise.c              # Noise XX protocol
│   ├── seccomp.c            # 3-stage seccomp
│   ├── state_machine.c      # 8 states, 16 events
│   ├── stdin_handler.c      # Command processing
│   ├── tui.c                # termbox2 TUI
│   └── ui.c                 # ANSI terminal UI
├── tests/
│   ├── cbmc_arena.c         # CBMC harness (arena)
│   ├── cbmc_crypto.c        # CBMC harness (crypto)
│   ├── cbmc_log.c           # CBMC harness (log)
│   ├── cbmc_noise_easy.c    # CBMC harness (noise)
│   ├── cbmc_state_machine.c # CBMC harness (state machine)
│   ├── cbmc_stdin.c         # CBMC harness (stdin)
│   ├── formal-verify.sh     # Dual formal verification script
│   ├── test_arena.c         # Arena unit tests (14)
│   ├── test_crypto.c        # Crypto unit tests (10)
│   ├── test_database.c      # Database unit tests (5)
│   ├── test_network.c       # Network unit tests (7)
│   ├── test_noise.c         # Noise unit tests (8)
│   ├── test_pin.c           # PIN unit tests (12)
│   └── test_seccomp_stage3.c # Seccomp tests (11)
├── fuzz/
│   ├── fuzz_arena.c
│   ├── fuzz_ctrl.c
│   ├── fuzz_file_transfer.c
│   ├── fuzz_frame_decode.c
│   ├── fuzz_handshake.c
│   ├── fuzz_sanitize.c
│   ├── fuzz_socks5.c
│   ├── fuzz_stdin.c
│   ├── fuzz_stdin_events.c
│   └── fuzz_noise_differential.c
│
├── Makefile
├── README.md
└── noxtor-cli       - Binary
```

---

