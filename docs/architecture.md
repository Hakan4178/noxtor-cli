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

noxtor-cli, Tor üzerinden anonim mesajlaşma uygulaması. Çoklu peer bağlantısı (`NOX_MAX_PEERS = 16`), Noise XX protokolü ile şifreli kanal, AF_UNIX socket.

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
| `src/arena.c` | 668 | mmap tabanlı güvenli bellek havuzu |
| `src/crypto.c` | 698 | Argon2id, Ed25519, Curve25519 dönüşümü |
| `src/database.c` | 1008 | SQLite: kontakt, mesaj kuyruğu, geçmiş |
| `src/event_loop.c` | 773 | Ana epoll event loop, frame işleme |
| `src/file_transfer.c` | 727 | Dosya gönderme/alma (BLAKE2b) |
| `src/landlock_sandbox.c` | 245 | Landlock LSM dosya erişim kontrolü |
| `src/log.c` | 337 | Modül bazlı loglama (TUI entegre) |
| `src/main.c` | 1291 | Başlatma, PIN, key derivation, args |
| `src/network.c` | 1470 | Tor spawn, SOCKS5, epoll, frame encode/decode |
| `src/noise.c` | 944 | Noise XX protocol implementasyonu |
| `src/seccomp.c` | 412 | 3 aşamalı seccomp-bpf loading |
| `src/state_machine.c` | 447 | Peer durum makinesi (8 durum, 17 olay, 40 geçiş) |
| `src/stdin_handler.c` | 949 | Komut işleme, mesaj segmentasyonu |
| `src/tui.c` | 797 | termbox2 tabanlı TUI (3 panel) |
| `src/ui.c` | 632 | Terminal/ANSI çıktı katmanı |

### 2.2 Header Dosyaları

| Dosya | Görev |
|-------|-------|
| `include/arena.h` | Arena public API |
| `include/asm_utils.h` | strub/asembly yardımcıları (ZeroCallUsedRegs) |
| `include/common.h` | Sabitler, hata kodları, log makroları |
| `include/crypto.h` | Kripto API (KDF, identity, salt) |
| `include/database.h` | SQLite DB API |
| `include/event_loop.h` | Event loop API |
| `include/file_transfer.h` | Dosya transfer API |
| `include/landlock_sandbox.h` | Landlock API |
| `include/network.h` | Network API + frame sabitleri |
| `include/noise.h` | Noise API |
| `include/seccomp_policy.h` | Seccomp API |
| `include/state_machine.h` | State/event enum'ları, SM API |
| `include/stdin_handler.h` | Stdin handler API |
| `include/termbox2.h` | Header-only TUI kütüphanesi |
| `include/tui.h` | TUI API (termbox2 ile compile) |
| `include/types.h` | `app_state`, tüm enum'lar, struct'lar |
| `include/ui.h` | UI çıktı API |

---

## 3. RX Yolu (Alma)

Tor'dan veri gelişi → ekrana mesaj display. Tam yol:

```
Tor daemon
  ↓ (Tor SOCKS5 → AF_UNIX socket)
event_loop.c:377  event_loop()           ← epoll_wait()
  ↓
event_loop.c:720  peer_fd ready          ← EPOLLIN (epoll_wait sonrası)
  ↓
event_loop.c:55   process_peer_frames()  ← frame parsing döngüsü
  ↓
network.c:1450    frame_header_decode()  ← 13-byte header decode
  ↓
  ├─ CTRL frame (handshake) ──→ event_loop.c:105 handshake_read()
  │                               ↓
  │                          noise.c:371 symmetric_decrypt_and_hash()
  │                               ↓
  │                          event_loop.c:121 handshake_write() → yanıt
  │                          State: ST_HANDSHAKE_INIT/RESP
  │
  ├─ TEXT frame (mesaj) ────→ event_loop.c:323 seq doğrulaması
  │                               ↓
  │                          noise.c:881 noise_decrypt()
  │                               ↓
  │                          ui.c:426 ui_print_incoming()
  │                               ↓
  │                          tui.c:380 tui_chat_append() veya
  │                          stdout'a atomik yazdırma (atomic_message)
  │
  └─ FILE frame (dosya) ───→ file_transfer.c:496 file_transfer_handle_rx()
                                  ↓
                             BLAKE2b hash doğrulama
                             disk'e yazma (O_EXCL, O_NOFOLLOW)
```

### 3.1 RX Anahtar Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `event_loop()` | `event_loop.c:377` | Ana döngü, epoll_wait |
| `process_peer_frames()` | `event_loop.c:55` | Frame parsing + routing (static) |
| `frame_header_decode()` | `network.c:1450` | 13-byte header → struct |
| `recv()` | system call | Ham veri okuma |
| `noise_decrypt()` | `noise.c:881` | ChaCha20-Poly1305 IETF AEAD decrypt |
| `handshake_read()` | `noise.c:791` | Noise XX mesaj okuma |
| `file_transfer_handle_rx()` | `file_transfer.c:496` | Dosya frame işleme |
| `ui_print_incoming()` | `ui.c:426` | Mesajı ekrana yazdır |
| `tui_chat_append()` | `tui.c:380` | TUI chat buffer'a ekle |

### 3.2 RX Veri Akışı Detayı

```
1. event_loop() → epoll_wait() → peer_fd EPOLLIN
2. recv(peer_fd, recv_buf + recv_pos, remaining)
   - recv_pos: recv_buf'daki mevcut byte sayısı
   - remaining: RECV_BUF_CAPACITY - recv_pos
   - partial read: sadece mevcut veri kadar okunur
3. process_peer_frames() döngüsü:
   a. recv_pos < sizeof(frame_header)? → break (yetersiz veri)
   b. frame_header_decode() → magic, payload_len kontrolü (len == 0 veya
      len > 4096 + 16 ise buffer sıfırlanır — A-1 fix)
   c. recv_pos < 13 + payload_len? → break (yarım frame)
   d. Session henüz yoksa TEXT/FILE frame'leri tüketme — recv_buf'da
      bekletilir (TOFU_PENDING sırasında drop edilmez)
   e. payload = recv_buf + 13 (sodium_malloc kopya — swap koruması)
   f. Frame tipine göre routing:
      - CTRL (0x04): handshake_read() → msg_index < 3 ise
        handshake_write() + writev() ile yanıt gönder
      - TEXT (0x01): noise_decrypt() → ui_print_incoming()
      - FILE (0x02): file_transfer_handle_rx()
      - ACK (0x03): alındı onayı
   g. recv_pos -= (13 + payload_len) → kalan frame'leri işle
   h. goto a (döngü devam)
```

---

## 4. TX Yolu (Gönderme)

Kullanıcı girdisi → Tor'a veri gönderme. Tam yol:

```
Kullanıcı (stdin veya TUI)
  ↓
stdin_handler.c:772  process_stdin_events()
  ↓
stdin_handler.c:352  process_line()         ← komut routing
  ↓
  ├─ /connect ──→ stdin_handler.c:615 socks5_connect()
  │                    ↓
  │               network.c:1243 socks5_connect()
  │                    ↓
  │               Tor SOCKS5 → onion adresi (rate limit + self-connect
  │               + duplicate kontrolünden sonra)
  │
  ├─ /add ─────→ database.c:339 db_add_contact()
  │
  ├─ /msg ─────→ stdin_handler.c:249 send_segmented_message()
  │                    ↓
  │               stdin_handler.c:254 send_segmented_message_to()
  │                    ↓
  │               stdin_handler.c:34 get_next_chunk_size()
  │               (4000 byte UTF-8 güvenli chunk'lar)
  │                    ↓
  │               noise.c:874 noise_encrypt()
  │                    ↓
  │               network.c:1434 frame_header_encode()
  │                    ↓
  │               writev() ile atomic gönderme
  │
  └─ /file ────→ file_transfer.c:100 file_transfer_start()
                       ↓
                  BLAKE2b hash hesapla
                  METADATA frame gönder
                  EPOLLOUT aktif et
                       ↓
                  file_transfer.c:330 file_transfer_handle_tx()
                  (4KB chunk'lar halinde gönderim)
```

### 4.1 TX Anahtar Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `process_stdin_events()` | `stdin_handler.c:772` | stdin/TUI girdisi oku |
| `process_line()` | `stdin_handler.c:352` | Komut ayrıştır ve yönlendir |
| `send_segmented_message()` | `stdin_handler.c:249` | Uzun mesajı chunk'lara böl |
| `send_segmented_message_to()` | `stdin_handler.c:254` | Belirli peer'a segmentli gönder |
| `get_next_chunk_size()` | `stdin_handler.c:34` | UTF-8 güvenli chunk noktası bul |
| `noise_encrypt()` | `noise.c:874` | ChaCha20-Poly1305 IETF AEAD encrypt |
| `frame_header_encode()` | `network.c:1434` | struct → 13-byte wire format |
| `write_full()` | `network.c:92` | EINTR retry ile tam yazma |
| `socks5_connect()` | `network.c:1243` | Tor SOCKS5 bağlantısı |
| `file_transfer_start()` | `file_transfer.c:100` | Dosya transferini başlat |
| `file_transfer_handle_tx()` | `file_transfer.c:330` | 4KB chunk gönderimi |

### 4.2 TX Frame Yapısı

```
┌──────────────────────────────────────────┐
│ Frame Header (13 byte)                   │
│  magic:   4 byte (0xDEADC0DE)           │
│  type:    1 byte (TEXT=1, FILE=2, ACK=3,│
│                   CTRL=4)                │
│  seq:     4 byte (sequence number)       │
│  payload_len: 4 byte (big-endian)        │
├──────────────────────────────────────────┤
│ Payload (0-4112 byte)                    │
│  şifrelenmiş: ChaCha20-Poly1305 IETF    │
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
EV_FILE_START          // /file komutu → TX başlat
EV_FILE_RX_START       // METADATA frame alındı → RX başlat
EV_FILE_DONE           // Transfer tamamlandı
EV_RATE_LIMIT          // Rate limit aşıldı
EV_SEQ_MISMATCH        // Beklenmeyen sequence number
EV_ARENA_FAIL          // Arena allocation başarısız
EV_TOR_DIED            // Tor process öldü
```

### 5.3 Geçiş Tablosu (40 geçiş — `transitions[]`, state_machine.c:122)

Gerçek geçiş tablosu kaynak koddan (`src/state_machine.c:122-190`):

```
{ ST_IDLE,           EV_CONNECT_CMD,        ST_HANDSHAKE_INIT, action_connect      }
{ ST_IDLE,           EV_PEER_ACCEPTED,      ST_HANDSHAKE_RESP, action_accept       }
{ ST_HANDSHAKE_INIT, EV_HANDSHAKE_MSG,      ST_HANDSHAKE_INIT, action_hs_process   }
{ ST_HANDSHAKE_RESP, EV_HANDSHAKE_MSG,      ST_HANDSHAKE_RESP, action_hs_process   }
{ ST_HANDSHAKE_INIT, EV_SESSION_READY,      ST_ACTIVE,         action_session_up   }
{ ST_HANDSHAKE_RESP, EV_SESSION_READY,      ST_ACTIVE,         action_session_up   }
{ ST_HANDSHAKE_INIT, EV_HANDSHAKE_DONE,     ST_TOFU_PENDING,   action_tofu_prompt  }
{ ST_HANDSHAKE_RESP, EV_HANDSHAKE_DONE,     ST_TOFU_PENDING,   action_tofu_prompt  }
{ ST_TOFU_PENDING,   EV_TOFU_ACCEPTED,      ST_ACTIVE,         action_tofu_accept  }
{ ST_TOFU_PENDING,   EV_TOFU_REJECTED,      ST_IDLE,           action_cleanup      }
{ ST_ACTIVE,         EV_FILE_START,         ST_FILE_TX,        action_file_begin   }
{ ST_ACTIVE,         EV_FILE_RX_START,      ST_FILE_RX,        action_file_begin_rx}
{ ST_FILE_TX,        EV_FILE_DONE,          ST_ACTIVE,         action_file_end     }
{ ST_FILE_RX,        EV_FILE_DONE,          ST_ACTIVE,         action_file_end     }
{ ST_CONNECTING,     EV_PEER_DISCONNECTED,  ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_INIT, EV_PEER_DISCONNECTED,  ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_RESP, EV_PEER_DISCONNECTED,  ST_IDLE,           action_cleanup      }
{ ST_TOFU_PENDING,   EV_PEER_DISCONNECTED,  ST_IDLE,           action_cleanup      }
{ ST_ACTIVE,         EV_PEER_DISCONNECTED,  ST_IDLE,           action_cleanup      }
{ ST_FILE_TX,        EV_PEER_DISCONNECTED,  ST_IDLE,           action_cleanup      }
{ ST_FILE_RX,        EV_PEER_DISCONNECTED,  ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_INIT, EV_HANDSHAKE_TIMEOUT,  ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_RESP, EV_HANDSHAKE_TIMEOUT,  ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_INIT, EV_HANDSHAKE_ERROR,    ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_RESP, EV_HANDSHAKE_ERROR,    ST_IDLE,           action_cleanup      }
{ ST_ACTIVE,         EV_SEQ_MISMATCH,       ST_IDLE,           action_cleanup      }
{ ST_FILE_TX,        EV_SEQ_MISMATCH,       ST_IDLE,           action_cleanup      }
{ ST_FILE_RX,        EV_SEQ_MISMATCH,       ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_INIT, EV_ARENA_FAIL,         ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_RESP, EV_ARENA_FAIL,         ST_IDLE,           action_cleanup      }
{ ST_IDLE,           EV_TOR_DIED,           ST_IDLE,           action_cleanup      }
{ ST_CONNECTING,     EV_TOR_DIED,           ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_INIT, EV_TOR_DIED,           ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_RESP, EV_TOR_DIED,           ST_IDLE,           action_cleanup      }
{ ST_TOFU_PENDING,   EV_TOR_DIED,           ST_IDLE,           action_cleanup      }
{ ST_ACTIVE,         EV_TOR_DIED,           ST_IDLE,           action_cleanup      }
{ ST_FILE_TX,        EV_TOR_DIED,           ST_IDLE,           action_cleanup      }
{ ST_FILE_RX,        EV_TOR_DIED,           ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_INIT, EV_RATE_LIMIT,         ST_IDLE,           action_cleanup      }
{ ST_HANDSHAKE_RESP, EV_RATE_LIMIT,         ST_IDLE,           action_cleanup      }
```

Not: `ST_IDLE + EV_PEER_DISCONNECTED` geçişi tanımlı değildir (ST_IDLE'da zaten bağlantı yok); geçersiz geçişler `NOX_WARN("SM: geçersiz geçiş ...")` ile yok sayılır.

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

ST_IDLE dışındaki tüm durumlarda:
  EV_PEER_DISCONNECTED → action_cleanup() → ST_IDLE
  EV_TOR_DIED → action_cleanup() → ST_IDLE (ST_IDLE'da kalır)
```

### 5.5 Action Fonksiyonları

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `sm_dispatch()` | `state_machine.c:196` | Ana dispatch motoru (linear search) |
| `sm_dispatch_active()` | `state_machine.c:222` | Aktif peer'a event dispatch |
| `action_cleanup()` | `state_machine.c:240` | fd kapat, key sıfırla, arena restore |
| `action_connect()` | `state_machine.c:322` | Outbound connect (stub — /connect stdin_handler.c'de) |
| `action_accept()` | `state_machine.c:330` | Inbound accept (stub — main.c accept4'te) |
| `action_hs_process()` | `state_machine.c:338` | Handshake işleme (stub) |
| `action_tofu_prompt()` | `state_machine.c:346` | TOFU onayı iste |
| `action_tofu_accept()` | `state_machine.c:354` | TOFU onayla: DB'ye kaydet, session kur |
| `action_session_up()` | `state_machine.c:417` | Session hazır (stub) |
| `action_file_begin()` | `state_machine.c:425` | Dosya TX başlat (stub) |
| `action_file_end()` | `state_machine.c:433` | Dosya transferi bitir (stub) |
| `action_file_begin_rx()` | `state_machine.c:441` | Dosya RX başlat (stub) |

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
identity.key (disk, XSalsa20-Poly1305 şifreli — crypto_secretbox)
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
  ChaCha20-Poly1305 IETF AEAD (crypto_aead_chacha20poly1305_ietf)
  nonce: atomic counter (UINT64_MAX taşmasında session yenilenmeli)
         12 byte'a encode_nonce() ile kodlanır
  key: session->tx.k
  AD: boş
  → ciphertext + 16 byte MAC

noise_decrypt(session, ciphertext):
  ChaCha20-Poly1305 IETF AEAD decrypt
  nonce: atomic counter
  key: session->rx.k
  → plaintext veya ERROR
```

### 6.4 Kripto Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `crypto_global_init()` | `crypto.c:142` | libsodium init |
| `crypto_derive_master_key()` | `crypto.c:180` | PIN → Argon2id → master_key |
| `crypto_derive_subkeys()` | `crypto.c:232` | master_key → 3 subkey (NOX_SUBKEY_DB=1, IDENTITY_UNLOCK=2, SESSION=3) |
| `crypto_load_or_create_salt()` | `crypto.c:279` | Salt yönetimi (atomic write) |
| `crypto_generate_identity()` | `crypto.c:412` | Ed25519 keypair üret + şifrele |
| `crypto_load_identity()` | `crypto.c:544` | identity.key çöz ve yükle (secretbox) |
| `crypto_ed25519_to_curve25519()` | `crypto.c:633` | Ed25519 → Curve25519 dönüştür |
| `cipher_encrypt()` | `noise.c:79` | ChaCha20-Poly1305 IETF AEAD encrypt |
| `cipher_decrypt()` | `noise.c:112` | ChaCha20-Poly1305 IETF AEAD decrypt |

---

## 7. Noise Protokolü

### 7.1 Pattern: XX_25519_ChaChaPoly_BLAKE2b

```
Prologue: "Mustafa Kemal Atatürk" (sabit, her iki taraf için aynı — noise.c:505)

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
| `handshake_init()` | `noise.c:485` | XX handshake başlat |
| `handshake_write()` | `noise.c:641` | Sıradaki handshake mesajını yaz |
| `handshake_read()` | `noise.c:791` | Gelen handshake mesajını oku |
| `handshake_is_complete()` | `noise.c:833` | Handshake tamamlandı mı? |
| `handshake_split()` | `noise.c:839` | Session'a dönüştür |
| `noise_encrypt()` | `noise.c:874` | Transport encrypt |
| `noise_decrypt()` | `noise.c:881` | Transport decrypt |
| `symmetric_init()` | `noise.c:155` | SymmetricState başlat |
| `symmetric_mix_hash()` | `noise.c:179` | MixHash |
| `symmetric_mix_key()` | `noise.c:337` | MixKey (HKDF) |
| `symmetric_encrypt_and_hash()` | `noise.c:359` | EncryptAndHash |
| `symmetric_decrypt_and_hash()` | `noise.c:371` | DecryptAndHash |
| `symmetric_split()` | `noise.c:408` | Split → tx/rx CipherState |

---

## 8. Dosya Transferi

### 8.1 TX Akışı

```
/file /path/to/file
  ↓
file_transfer_start()                    [file_transfer.c:100]
  ├─ open(filepath, O_RDONLY)
  ├─ fstat() → dosya boyutu
  ├─ BLAKE2b hash hesapla (boyut dahil)
  ├─ METADATA frame gönder:
  │    type=FILE, subtype=METADATA
  │    payload: filename_len(1) + filename + filesize(8) + hash(32)
  └─ EPOLLOUT aktif et
  ↓
file_transfer_handle_tx()                [file_transfer.c:330]
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
file_transfer_handle_rx()                [file_transfer.c:496]
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
                      └─ State: ST_FILE_RX → ST_ACTIVE
```

### 8.3 Dosya Transferi Güvenlik Önlemleri

| Önlem | Açıklama |
|-------|----------|
| `sanitize_filename()` | Path traversal engeli, whitelist karakter |
| `O_EXCL` | Yarış koşulu: dosya zaten varsa hata |
| `O_NOFOLLOW` | Symlink izleme engeli |
| `openat()` | TOCTOU koruması: fd-based erişim |
| `verify_downloads_dir_fd()` | Downloads dizini symlink değil, UID eşleşmesi |
| BLAKE2b hash | Dosya bütünlük doğrulaması |
| `file_transfer_cleanup()` | Kısmi dosyaları sil |

### 8.4 Dosya Transferi Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `file_transfer_start()` | `file_transfer.c:100` | TX başlat |
| `file_transfer_handle_tx()` | `file_transfer.c:330` | TX chunk gönder |
| `file_transfer_handle_rx()` | `file_transfer.c:496` | RX frame işle |
| `file_transfer_cleanup()` | `file_transfer.c:697` | Temizlik |
| `sanitize_filename()` | `file_transfer.c:29` | Dosya adı temizleme |
| `verify_downloads_dir_fd()` | `file_transfer.c:83` | Downloads dizin doğrulama (fd tabanlı) |
| `open_recv_file()` | `file_transfer.c:446` | Güvenli dosya açma |
| `write_to_file()` | `file_transfer.c:429` | Kısmi yazma yardımı |

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
| `tui_shutdown()` | `tui.c:218` | Temizlik |
| `tui_resize()` | `tui.c:233` | Terminal yeniden boyutlandırma |
| `tui_draw_sidebar()` | `tui.c:295` | Kontakt listesi çiz |
| `tui_draw_chat()` | `tui.c:494` | Sohbet paneli çiz |
| `tui_draw_input()` | `tui.c:546` | Giriş paneli çiz |
| `tui_refresh_all()` | `tui.c:586` | Tam yeniden çizim |
| `tui_chat_append()` | `tui.c:380` | Chat buffer'a ekle |
| `tui_chat_append_colored()` | `tui.c:385` | Renkli chat buffer |
| `tui_handle_input()` | `tui.c:604` | Klavye girdisi işle |
| `tui_print_welcome()` | `tui.c:187` | Hoşgeldin mesajı |
| `tui_load_contacts()` | `tui.c:268` | DB'den kontakt yükle (static) |

### 9.4 UI Fonksiyonlar

| Fonksiyon | Dosya:Satr | Görev |
|-----------|-----------|-------|
| `ui_init()` | `ui.c:77` | Tema ayarla |
| `clear_prompt_area()` | `ui.c:132` | Prompt alanını temizle |
| `ui_print_prompt()` | `ui.c:243` | Prompt çiz |
| `atomic_message()` | `ui.c:391` | Atomik terminal çıktısı (static) |
| `ui_print_incoming()` | `ui.c:426` | Gelen mesaj yazdır |
| `ui_print_outgoing()` | `ui.c:446` | Giden mesaj yazdır |
| `ui_print_system()` | `ui.c:468` | Sistem mesajı yazdır |
| `ui_print_error()` | `ui.c:510` | Hata mesajı yazdır |
| `ui_print_progress()` | `ui.c:582` | Dosya transfer ilerleme çubuğu |

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
│  • Seccomp stage 1 (constructor, main.c:121):          │
│    process_vm_readv/writev, ptrace, io_uring_setup/    │
│    enter/register, userfaultfd, perf_event_open, bpf,  │
│    kexec_file_load, finit_module, personality          │
│  • Seccomp stage 2 (Tor spawn sonrası, main.c:1272):   │
│    fork, vfork, execve, execveat, mount, umount2,      │
│    pivot_root, swapon, swapoff, init_module,           │
│    delete_module, sethostname, setdomainname, keyctl,  │
│    unshare, setns, reboot + fs api + clone (thread     │
│    filter) + prctl (8 tehlikeli option) + raw socket   │
│  • Seccomp stage 3 (event loop başı, event_loop.c:429):│
│    symlink/link/chmod/chown, clone, socket(AF_INET,    │
│    AF_INET6, AF_XDP, AF_ALG, AF_VSOCK, AF_NETLINK)     │
├─────────────────────────────────────────────────────────┤
│ Layer 1: Process İzolasyonu                             │
│  • TSYNC: 32-bit seccomp bypass engeli                  │
│  • NO_NEW_PRIVS: setuid escalation engeli               │
│  • PR_SET_DUMPABLE=0: /proc/PID/mem engeli              │
└─────────────────────────────────────────────────────────┘
```

### 10.2 Seccomp Aşamaları

Seccomp-bpf additive'tir: stage 1 kuralları kalıcıdır, her stage yalnızca yeni kural ekler. `seccomp_policy_load(stage)` (seccomp.c:176) — `SCMP_ACT_KILL` (SIGSYS).

```
Stage 1 (constructor, main.c:121 — main'den önce):
  process_vm_readv, process_vm_writev          ← process memory okuma engeli
  ptrace (yalnızca NDEBUG)                     ← attach engeli
  io_uring_setup, io_uring_enter, io_uring_register
  userfaultfd, perf_event_open                 ← kernel CVE / timing yüzeyi
  bpf, kexec_file_load, finit_module           ← kernel injection
  personality                                  ← ABI bypass engeli

Stage 2 (Tor spawn sonrası, main.c:1272 — fork/execve artık gerekmez):
  execve, execveat, fork, vfork                ← process manipulation
  pidfd_open, process_madvise, kcmp
  mount, umount2, fsopen, fsconfig, fsmount, fspick,
  move_mount, open_tree, umount, pivot_root,
  open_by_handle_at, openat2                   ← filesystem API
  reboot, sethostname, setdomainname, kexec_load
  init_module, delete_module
  unshare, setns                               ← namespace
  swapon, swapoff
  request_key, add_key, keyctl
  nfsservctl, quotactl
  + özel kurallar:
    clone: CLONE_THREAD biti set değilse KILL (pthread_create izinli,
           fork/vfork yolu kapatılır — H-2 fix)
    clone3: tamamen KILL
    prctl: 8 tehlikeli option KILL (PR_SET_DUMPABLE, PR_SET_PTRACER,
           PR_SET_TIMING, PR_SET_MM, PR_SET_TSC, PR_SET_SECUREBITS,
           PR_SET_SYSCALL_USER_DISPATCH, PR_SET_MDWE)
    socket(AF_PACKET), socket(AF_INET, SOCK_RAW),
    socket(AF_INET6, SOCK_RAW)                 ← raw paket engeli

Stage 3 (event loop başı, event_loop.c:429):
  symlink, symlinkat, link, linkat             ← fs manipulation
  chmod, fchmod, fchmodat, chown, fchown, fchownat
  + özel kurallar:
    clone: tamamen KILL (event loop tek thread)
    socket(AF_INET), socket(AF_INET6)          ← TCP/UDP tamamen yasak
    socket(AF_XDP), socket(AF_ALG), socket(AF_VSOCK)  ← H-6 fix:
       alternatif sızıntı yolları (raw paket / kernel crypto / VM)
    socket(AF_NETLINK)                         ← kernel network config

İzinli kalanlar: AF_UNIX socket (Tor control/SOCKS/peer bağlantısı),
getaddrinfo yalnızca stage 3 öncesi (bootstrap sırasında).
```

### 10.3 Arena Bellek Topolojisi

```
┌──────────────────────────────────┐
│ Lower Guard Page (PROT_NONE)     │ ← SIGSEGV (underflow)
├──────────────────────────────────┤
│ Usable Area (RW, bump allocator) │
│  key1          32 byte           │ ← gerçek key
│  [0-3 honeypot] 32 byte/adet     │ ← scatter_honeypots() ile rastgele
│  key2          32 byte           │    yerleştirilmiş sahte key'ler
│  ... (key'ler + handshake/       │
│       session structs)           │
├──────────────────────────────────┤
│ Canary Zone (16 byte)            │ ← arena bütünlük (NOX_CANARY_LEN)
├──────────────────────────────────┤
│ Upper Guard Page (PROT_NONE)     │ ← SIGSEGV (overflow)
└──────────────────────────────────┘
```

Gerçek yerleşim (main.c:887-940): her gerçek key alloc'undan ÖNCE
`scatter_honeypots(&state.arena, 0, 3)` çağrılır — 0-3 arası rastgele
adette sahte key (`arena_alloc_canary`, arena.c:408) yerleştirilir.
Böylece key'lerin arena içindeki konumu her çalıştırmada farklıdır ve
saldırgan hangi 32-byte bloğun gerçek key olduğunu tahmin edemez.

Canary kontrolü: `arena_check_canary()` her allocation öncesi çalışır;
`arena_restore()` canary ihlalini tespit eder (P4). Bellek: mmap +
MAP_LOCKED (fallback: mlock), MADV_DONTFORK + MADV_DONTDUMP,
destroy'da sodium_memzero ile temizleme.

---

## 11. Test Kapsamı

### 11.1 Unit Testler (80/80 — `make test`)

| Test Dosyası | Test Sayısı | Kapsadığı Fonksiyonlar |
|--------------|-------------|------------------------|
| `test_arena.c` | 14 | arena_init, arena_alloc, arena_alloc_canary, arena_destroy, canary check |
| `test_crypto.c` | 10 | Argon2id, subkey derivation, salt, identity roundtrip, Ed25519→Curve25519 |
| `test_database.c` | 5 | DB open/close, contacts, wrong key, queue, history |
| `test_landlock_rights.c` | 12 | Landlock hak maskeleme (birim 12 + entegrasyon) |
| `test_network.c` | 7 | Frame encode/decode, listener create, UTF-8 chunking |
| `test_noise.c` | 9 | Null safety, loopback handshake, transport roundtrip, MAC tamper, spec vectors |
| `test_pin.c` | 12 | PIN validation (min, max, empty, null, control chars, UTF-8, spaces) |
| `test_seccomp_stage3.c` | 11 | AF_INET, AF_INET6, clone, DNS, connect, AF_NETLINK, AF_UNIX, prctl |

Ayrıca: `test_seccomp.c` (make seccomp-test) — tüm seccomp kural dizisinin
canlı testi (LSan kapalı, seccomp ptrace ile uyumsuz olduğundan).

### 11.2 Formal Doğrulama (CBMC + ESBMC + ProVerif)

| Kaynak | CBMC/ESBMC | Durum |
|--------|-----------|-------|
| `arena.c` (cbmc_arena.c) | ✅ | VERIFICATION SUCCESSFUL |
| `crypto.c` (cbmc_crypto.c) | ✅ | VERIFICATION SUCCESSFUL |
| `log.c` (cbmc_log.c) | ✅ | VERIFICATION SUCCESSFUL |
| `noise.c` easy (cbmc_noise_easy.c) | ✅ | VERIFICATION SUCCESSFUL |
| `sanitize_filename.c` (cbmc_sanitize_filename.c) | ✅ | VERIFICATION SUCCESSFUL |
| `state_machine.c` (cbmc_state_machine.c) | ✅ | VERIFICATION SUCCESSFUL |
| `stdin_handler.c` (cbmc_stdin.c) | ✅ | VERIFICATION SUCCESSFUL |
| `validate_onion.c` (cbmc_validate_onion.c) | ✅ | VERIFICATION SUCCESSFUL |
| Noise XX protokolü (tests/proverif/) | ProVerif | XX.noise.active.pv, XX.noise.passive.pv |

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
| `fuzz_noise` | `fuzz/fuzz_noise.c` | Noise transport |
| Differential | `tests/fuzz_noise_differential.c` | Noise-c referans kütüphane ile differential testing |
| Differential (star) | `tests/fuzz_noise_differential_noise_star.c` | noise_star referans implementasyon |

### 11.4 Çalıştırma

```bash
# Unit testler
make test                    # 80/80, ASan+UBSan altında (8 suite)
make seccomp-test            # Seccomp canlı kural testi

# Formal doğrulama
./tests/formal-verify.sh     # Tümü (CBMC + ESBMC)
./tests/formal-verify.sh arena    # Sadece arena
./tests/formal-verify.sh sm       # Sadece state machine

# ProVerif
# tests/proverif/XX.noise.active.pv ve XX.noise.passive.pv

# Fuzz testler
make fuzz                    # Tüm fuzz hedefleri
```

---

## 12. Dosya Haritası

```
noxtor-cli/
├── include/
│   ├── arena.h              # Arena API
│   ├── asm_utils.h          # strub/asembly yardımcıları
│   ├── common.h             # Sabitler, hata kodları
│   ├── crypto.h             # Kripto API
│   ├── database.h           # DB API
│   ├── event_loop.h         # Event loop API
│   ├── file_transfer.h      # Dosya transfer API
│   ├── landlock_sandbox.h   # Landlock API
│   ├── network.h            # Network API + frame sabitleri
│   ├── noise.h              # Noise API
│   ├── seccomp_policy.h     # Seccomp API
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
│   ├── state_machine.c      # 8 states, 17 events, 40 transitions
│   ├── stdin_handler.c      # Command processing
│   ├── tui.c                # termbox2 TUI
│   └── ui.c                 # ANSI terminal UI
├── tests/
│   ├── cbmc_arena.c         # CBMC harness (arena)
│   ├── cbmc_crypto.c        # CBMC harness (crypto)
│   ├── cbmc_log.c           # CBMC harness (log)
│   ├── cbmc_noise_easy.c    # CBMC harness (noise)
│   ├── cbmc_sanitize_filename.c # CBMC harness (sanitize)
│   ├── cbmc_state_machine.c # CBMC harness (state machine)
│   ├── cbmc_stdin.c         # CBMC harness (stdin)
│   ├── cbmc_validate_onion.c # CBMC harness (onion validation)
│   ├── fuzz_noise_differential.c         # Noise-c differential
│   ├── fuzz_noise_differential_noise_star.c # noise_star differential
│   ├── formal-verify.sh     # Dual formal verification script
│   ├── proverif/            # ProVerif modeli (XX.noise.active.pv, ...)
│   ├── test_arena.c         # Arena unit tests (14)
│   ├── test_crypto.c        # Crypto unit tests (10)
│   ├── test_database.c      # Database unit tests (5)
│   ├── test_landlock_rights.c # Landlock rights tests (12)
│   ├── test_network.c       # Network unit tests (7)
│   ├── test_noise.c         # Noise unit tests (9)
│   ├── test_pin.c           # PIN unit tests (12)
│   ├── test_seccomp.c       # Seccomp live tests (make seccomp-test)
│   └── test_seccomp_stage3.c # Seccomp stage-3 tests (11)
├── fuzz/
│   ├── fuzz_arena.c
│   ├── fuzz_ctrl.c
│   ├── fuzz_file_transfer.c
│   ├── fuzz_frame_decode.c
│   ├── fuzz_handshake.c
│   ├── fuzz_noise.c
│   ├── fuzz_sanitize.c
│   ├── fuzz_socks5.c
│   ├── fuzz_stdin.c
│   ├── fuzz_stdin_events.c
│   ├── corpus/
│   └── findings*/
│
├── .github/workflows/      # arch.yml (make) + codeql.yml
├── LICENSE                 # GPL-3.0
├── Makefile
├── README.md
└── noxtor-cli              # Binary
```

---

