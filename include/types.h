/* SPDX-License-Identifier: GPL-3.0-or-later
 * types.h — noxtor-cli temel veri yapıları
 *
 * Tüm struct tanımları burada. Implementasyon detayı yok.
 * Sıralama: önce bağımsız tipler, sonra bağımlı olanlar.
 */

#ifndef PARANOID_TYPES_H
#define PARANOID_TYPES_H

#include "common.h"

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
    uint8_t  nonce[NOX_NONCE_LEN]; /* 24 byte nonce                 */
};

/* Wire format: 4+1+4+4+24 = 37 byte — padding yok */
NOX_STATIC_ASSERT(sizeof(struct frame_header) == 37,
                  "frame_header wire format boyutu 37 byte olmali");

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
 * İlk bağlantıda noise_key kaydedilir.
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
    uint8_t  ck[NOX_KEY_LEN];  /* chaining key                    */
    uint8_t  h[NOX_KEY_LEN];   /* handshake hash (32 byte)        */
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
};

#endif /* PARANOID_TYPES_H */
