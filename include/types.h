/* SPDX-License-Identifier: GPL-3.0-or-later
 * types.h — noxtor-cli temel veri yapıları
 *
 * Tüm struct tanımları burada. Implementasyon detayı yok.
 * Sıralama: önce bağımsız tipler, sonra bağımlı olanlar.
 */

#ifndef PARANOID_TYPES_H
#define PARANOID_TYPES_H

#include "common.h"
#include <sodium.h>
#include <signal.h>

/* ================================================================
 * SECURE ARENA — Güvenli bellek havuzu
 *
 * Key materyali için mmap + MAP_LOCKED tabanlı arena.
 * 64 KB RLIMIT_MEMLOCK sınırına uygun.
 * 16-byte aligned bump allocator (libsodium SIMD uyumu).
 * ================================================================ */
struct secure_arena {
    void    *base;          /* mmap ile ayrılan bölge başlangıcı       */
    size_t   total_size;    /* guard page'ler dahil toplam boyut       */
    size_t   usable_size;   /* kullanılabilir alan (guard page'siz)    */
    size_t   offset;        /* sonraki alloc pozisyonu (bump)          */
    size_t   page_size;     /* sistem sayfa boyutu (cache)             */
    bool     fork_safe;     /* MADV_DONTFORK durumu                    */
    bool     dump_safe;     /* MADV_DONTDUMP durumu                    */
    uint8_t  canary[NOX_CANARY_LEN]; /* taşma tespiti için            */
};

/* ================================================================
 * MESAJ FRAMING
 *
 * Length-prefixed, tip alanı olan basit frame yapısı.
 * Network byte order (big-endian) ile gönderilir.
 * ================================================================ */
enum msg_type {
    NOX_MSG_TEXT  = 1,   /* metin mesajı        */
    NOX_MSG_FILE  = 2,   /* dosya chunk'ı       */
    NOX_MSG_ACK   = 3,   /* alındı onayı        */
    NOX_MSG_CTRL  = 4,   /* kontrol mesajı      */
};

struct __attribute__((packed)) frame_header {
    uint32_t magic;         /* NOX_FRAME_MAGIC = 0xDEADC0DE         */
    uint8_t  type;          /* enum msg_type                        */
    uint32_t seq;           /* sıra numarası                        */
    uint32_t len;           /* payload uzunluğu (şifreli, MAC dahil)*/
};

/* Wire format: 4+1+4+4 = 13 byte — padding yok, nonce Noise CipherState'te */
NOX_STATIC_ASSERT(sizeof(struct frame_header) == 13,
                  "frame_header wire format boyutu 13 byte olmali");

/* ================================================================
 * MESAJ DURUMU — SQLite kuyruk state machine
 * ================================================================ */
enum msg_state {
    NOX_STATE_QUEUED   = 0,  /* kuyruğa eklendi, gönderilmedi       */
    NOX_STATE_SENDING  = 1,  /* gönderiliyor                        */
    NOX_STATE_ACKED    = 2,  /* karşı taraf onayladı                */
    NOX_STATE_FAILED   = 3,  /* gönderim başarısız — retry bekliyor */
};

/* ================================================================
 * KİŞİ REHBERİ — TOFU modeli
 *
 * FKurulumda noise_key kaydedilir.
 * Sonraki bağlantılarda değişmişse MITM uyarısı.
 * ================================================================ */
struct contact {
    char     name[NOX_CONTACT_NAME_LEN];  /* kullanıcı verdiği isim  */
    char     onion[NOX_ONION_LEN];        /* .onion adresi           */
    uint8_t  noise_key[NOX_KEY_LEN];      /* static public key       */
    bool     verified;                     /* fingerprint onaylandı mı*/
};

/* ================================================================
 * NOISE XX — Cipher State (handshake sonrası transport)
 * ================================================================ */
struct noise_cipher_state {
    uint8_t  k[NOX_KEY_LEN];   /* şifreleme anahtarı              */
    uint64_t n;                 /* nonce counter — monoton artan   */
    bool     has_key;           /* key set edilmiş mi               */
};

/* ================================================================
 * NOISE XX — Symmetric State (handshake sırasında)
 * ================================================================ */
struct noise_symmetric_state {
    uint8_t  ck[64];           /* chaining key                    */
    uint8_t  h[64];            /* handshake hash                  */
    struct noise_cipher_state cs;
};

/* ================================================================
 * NOISE XX — Handshake State
 *
 * XX pattern: → e / ← e, ee, se, s, es / → s, se
 * Ephemeral key'ler kullanıldıktan sonra derhal silinir.
 * ================================================================ */
struct noise_handshake {
    struct noise_symmetric_state ss;
    uint8_t  s[NOX_KEY_LEN];       /* local static private key    */
    uint8_t  s_pub[NOX_KEY_LEN];   /* local static public key     */
    uint8_t  e[NOX_KEY_LEN];       /* local ephemeral private key */
    uint8_t  e_pub[NOX_KEY_LEN];   /* local ephemeral public key  */
    uint8_t  rs[NOX_KEY_LEN];      /* remote static public key    */
    uint8_t  re[NOX_KEY_LEN];      /* remote ephemeral public key */
    bool     initiator;
    int      msg_index;             /* 0, 1, 2 — hangi adımdayız  */
};

/* ================================================================
 * NOISE XX — Session (handshake tamamlandıktan sonra)
 * ================================================================ */
struct noise_session {
    struct noise_cipher_state tx;   /* gönderme yönü               */
    struct noise_cipher_state rx;   /* alma yönü                   */
    uint8_t  remote_static[NOX_KEY_LEN]; /* doğrulanmış peer key   */
};

/* ================================================================
 * PLUGGABLE TRANSPORT & ASENKRON DOSYA DURUMLARI (Faz 6.2)
 * ================================================================ */
enum tor_transport_type {
    TRANSPORT_DIRECT = 0,
    TRANSPORT_SNOWFLAKE,
    TRANSPORT_OBFS4
};

/* CRIT-1: tx_buf için güvenli kapasite sabiti */
#define TX_BUF_CAPACITY (FRAME_HEADER_WIRE_SIZE + 4096 + NOX_MAC_LEN)

struct file_rx_state {
    bool     active;
    int      fd;                  /* hedef dosya tanımlayıcısı */
    char     filename[256];       /* dezenfekte edilmiş dosya adı */
    uint64_t expected_size;
    uint64_t received_bytes;
    uint8_t  expected_hash[32];   /* 256-bit BLAKE2b */
    crypto_generichash_state hash_state;

    /* B-1 FIX: unlinkat için gerçek dosya adı */
    char     local_name[300];
};

struct file_tx_state {
    bool     active;
    int      fd;                  /* kaynak dosya tanımlayıcısı */
    char     filename[256];       /* sadece dezenfekte dosya adı */
    uint64_t total_size;
    uint64_t sent_bytes;
    uint8_t  hash[32];            /* önceden hesaplanan BLAKE2b */
    
    /* D-1 FIX: önceden ayrılmış şifresiz tampon (stack yerine heap) */
    uint8_t *plain_buf;

    /* Kısmi yazım için frame tamponu — boyut TX_BUF_CAPACITY ile sabit */
    uint8_t  tx_buf[TX_BUF_CAPACITY];
    size_t   tx_len;              /* mevcut frame'in toplam boyutu */
    size_t   tx_offset;           /* şimdiye dek yazılan byte */
    size_t   current_chunk_size;  /* mevcut şifrelenmemiş dosya boyutu */
};

/* ================================================================
 * UYGULAMA ANA DURUMU — app_state
 *
 * Tek global struct. Tüm modüller buna pointer alır.
 * Key materyali burada değil, secure_arena'da yaşar.
 * ================================================================ */
struct app_state {
    /* Bellek güvenliği */
    struct secure_arena arena;

    /* Kriptografi — pointer'lar arena'ya işaret eder */
    uint8_t *master_key;         /* arena'da, 32 byte                */
    uint8_t *db_key;             /* arena'da, 32 byte                */
    uint8_t *session_key;        /* arena'da, 32 byte                */
    uint8_t *my_static_priv;     /* arena'da, 32 byte (Curve25519)  */
    uint8_t *my_static_pub;      /* arena'da, 32 byte (Curve25519)  */

    /* Noise session (aktif bağlantı varsa) */
    struct noise_session *session; /* arena'da veya NULL              */
    struct noise_handshake *hs;  /* aktif handshake veya NULL         */

    /* Tor */
    int      tor_ctrl_fd;        /* Tor Control Protocol fd          */
    pid_t    tor_pid;            /* Tor process PID                  */
    char     onion_addr[NOX_ONION_LEN + 1]; /* kendi .onion adresimiz */
    char     torrc_path[NOX_PATH_MAX];   /* torrc dosya yolu         */
    char     tor_data_dir[NOX_PATH_MAX]; /* tor veri dizini           */

    /* Network */
    int      epoll_fd;           /* epoll instance                   */
    int      listen_fd;          /* incoming peer listener veya -1   */
    int      peer_fd;            /* aktif peer bağlantısı veya -1    */
    uint16_t listen_port;        /* listener portu (OS atar)         */
    uint16_t socks_port;         /* Tor SOCKS proxy portu (auto)     */
    uint32_t tx_seq;             /* gönderme sıra numarası           */
    uint32_t rx_seq;             /* alma sıra numarası               */
    size_t   session_arena_mark; /* session öncesi arena offset      */

    /* Durum */
    bool     running;            /* false olunca event loop çıkar    */
    bool     first_run;          /* ilk çalıştırma mı                */

    /* Config yolları — NOX_PATH_MAX yeterli, PATH_MAX stack'i taşırır */
    char     config_dir[NOX_PATH_MAX];
    char     identity_path[NOX_PATH_MAX];
    char     contacts_path[NOX_PATH_MAX];

    /* TOFU State */
    bool     tofu_pending;
    int      tofu_peer_fd;
    char     tofu_onion[NOX_ONION_LEN + 1];
    char     tofu_name[NOX_CONTACT_NAME_LEN + 1];
    uint8_t  tofu_new_key[NOX_KEY_LEN];
    size_t   tofu_arena_mark;
    char     active_peer_onion[NOX_ONION_LEN + 1];

    /* Async stdin buffering */
    char    *stdin_buf;
    size_t   stdin_len;
    size_t   stdin_cap;
    bool     input_saved;        /* ui_save/restore iç içe çağrı koruması */

    /* Pluggable Transport (Faz 6.2) */
    enum tor_transport_type transport_type;
    char     obfs4_bridge_line[512];

    /* Asenkron Dosya İşlemleri */
    int      downloads_dir_fd;
    char     downloads_dir[NOX_PATH_MAX];
    struct file_rx_state rx_file;
    struct file_tx_state tx_file;
};

extern volatile sig_atomic_t g_shutdown;

#endif /* PARANOID_TYPES_H */
