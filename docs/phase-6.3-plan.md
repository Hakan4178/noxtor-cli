# Faz 6.3 — Çoklu Oturum, Pairwise Onion ve ncurses TUI Mimari Planı

## Amaç ve Kapsam

Bu faz, Noxtor-CLI'ı tek peer'lı basit bir CLI mesajlaşıcıdan, **çoklu oturum destekleyen, TUI tabanlı bir uygulamaya** dönüştürür. **Tek .onion adresi** ile çoklu bağlantı desteği sağlar. Noise protocol zaten pairwise şifreleme (forward secrecy + key freshness) sunar.

---

## Arka Plan: Tartışılan Kararlar

### 1. Kimlik Doğrulama Katmanları (Mevcut Durum)
Şu an kimlik doğrulama 3 katmanlı çalışıyor:
- **Ağ Katmanı:** `.onion` adresi (Tor Hidden Service özel anahtarına sahip olan kişi)
- **Kriptografik Katman:** Noise XX Handshake ile karşı tarafın Curve25519 statik public key'i
- **Güven Katmanı:** TOFU modeli — ilk bağlantıda kullanıcı onayı, sonraki bağlantılarda key karşılaştırması

### 2. Kalıcı vs Geçici Onion Adresi Sorunu
**Sorun:** Şu an `ADD_ONION NEW:ED25519-V3` kullanılıyor — her uygulama yeniden başlatıldığında **farklı bir .onion adresi** üretiliyor. Bu, rehberdeki kayıtlı adreslerin geçersiz kalmasına neden oluyor.

**Karar:** Tor Control Protocol'ün `ADD_ONION ED25519-V3:<base64_private_key>` özelliğini kullanarak onion özel anahtarını diske şifreli olarak kaydedip, her açılışta aynı adresi yeniden oluşturma.

### 3. ~~Pairwise Identity — Anonimlik Korelasyon Koruması~~ İPTAL

> **İPTAL (2026-06-28):** Pairwise onion modeli iptal edildi.
> Noise protocol zaten her bağlantıyı ayrı şifreler (forward secrecy + key freshness).
> Tek onion modeli yeterli anonimlik sağlıyor.

### 4. Çoklu Oturum Mimarisi
**Karar:** `app_state` içindeki tek `peer_fd` + tek `session` yerine, bir oturum dizisi (`struct peer_session sessions[NOX_MAX_PEERS]`) tutulur. ncurses TUI ile kullanıcı oturumlar arasında geçiş yapar.

### 5. Ghost Mod Davranışı
Ghost modda hiçbir anahtar, rehber veya geçmiş saklanmaz. Her bağlantıda geçici (ephemeral) `.onion` adresi kullanılır — mevcut davranış aynen korunur. Çoklu oturum desteği ghost modda da çalışır ama hiçbir şey diske yazılmaz.

---

## Mimari Genel Bakış

```
┌─────────────────────────────────────────────────────────────┐
│                    ncurses TUI Katmanı                        │
│  ┌──────────┐  ┌──────────────────────────────────────────┐  │
│  │ Sidebar  │  │              Chat Paneli                  │  │
│  │          │  │                                          │  │
│  │ Ali    ● │  │  [14:30] [Ali] merhaba                   │  │
│  │ Veli     │  │  [14:31] [Sen] selam!                    │  │
│  │ + Yeni   │  │                                          │  │
│  │          │  ├──────────────────────────────────────────┤  │
│  │          │  │ > mesaj yaz...                            │  │
│  └──────────┘  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Önerilen Değişiklikler

### Bileşen 1: Veri Yapıları (`types.h`)

#### [MODIFY] [types.h](file:///home/hakan/noxtor-cli/include/types.h)

Yeni sabitler ve struct'lar eklenir:

```c
#define NOX_MAX_PEERS          16U    /* Eş zamanlı maksimum oturum */
#define NOX_ONION_KEY_B64_LEN  88U    /* ED25519-V3 private key base64 */
#define NOX_HISTORY_MAX        256U   /* Bellekte tutulan mesaj sayısı */
```

**Yeni struct — Peer oturumu:**
```c
struct peer_session {
    /* Kimlik */
    char     peer_onion[NOX_ONION_LEN + 1];     /* Karşı tarafın adresi       */
    char     my_onion[NOX_ONION_LEN + 1];       /* BİZİM bu peer'a özel adresimiz */
    char     name[NOX_CONTACT_NAME_LEN + 1];    /* İsim (rehberden)           */

    /* Bağlantı */
    int      fd;                                 /* TCP soket fd veya -1       */
    int      listen_fd;                          /* Bu peer'a özel listener    */
    uint16_t listen_port;                        /* Listener portu             */

    /* Kriptografi */
    struct noise_session *session;               /* Arena'da veya NULL         */
    struct noise_handshake *hs;                  /* Aktif handshake veya NULL  */
    time_t   handshake_start;                    /* Timeout kontrolü           */
    size_t   arena_mark;                         /* Session öncesi arena offset */

    /* Sıra numaraları */
    uint32_t tx_seq;
    uint32_t rx_seq;

    /* Dosya transfer durumu */
    struct file_rx_state rx_file;
    struct file_tx_state tx_file;

    /* TOFU durumu */
    bool     tofu_pending;
    uint8_t  tofu_new_key[NOX_KEY_LEN];

    /* Durum */
    enum {
        PEER_STATE_IDLE = 0,       /* Bağlantı yok                */
        PEER_STATE_CONNECTING,     /* SOCKS5 bağlantısı kuruluyor */
        PEER_STATE_HANDSHAKING,    /* Noise XX handshake devam     */
        PEER_STATE_ACTIVE,         /* Şifreli kanal hazır          */
    } state;

    /* Okunmamış mesaj sayacı (TUI badge) */
    uint32_t unread_count;
};
```

**`app_state` değişiklikleri:**
```c
struct app_state {
    /* ... mevcut arena, crypto, config alanları korunur ... */

    /* ===== YENİ: Çoklu Oturum ===== */
    struct peer_session peers[NOX_MAX_PEERS];
    int      active_peer_idx;     /* Şu an aktif olan oturum indeksi (-1 = yok) */
    int      peer_count;          /* Aktif oturum sayısı                        */

    /* ===== ESKİ TEK PEER ALANLARI KALDIRILIR ===== */
    /* peer_fd, session, hs, handshake_start, tx_seq, rx_seq,
       session_arena_mark, active_peer_onion, tofu_* alanları
       -> peers[] dizisine taşınır */

    /* ===== YENİ: ncurses TUI ===== */
    bool     tui_active;          /* ncurses başlatıldı mı        */
    int      sidebar_scroll;      /* Sidebar kaydırma pozisyonu   */
};
```

---

### Bileşen 2: Veritabanı (`database.c` / `database.h`)

#### [MODIFY] [database.h](file:///home/hakan/noxtor-cli/include/database.h)

Yeni API fonksiyonları:

```c
/* Rehberdeki tüm kişileri listele (şifre çözülmüş olarak) */
typedef void (*db_contact_visitor_fn)(const char *onion, const char *name,
                                      const uint8_t noise_key[NOX_KEY_LEN],
                                      const char *my_onion,
                                      const uint8_t *my_onion_key,
                                      size_t onion_key_len,
                                      void *ctx);
nox_err_t db_list_contacts(db_contact_visitor_fn visitor, void *ctx);

/* Mesaj geçmişi kaydetme ve okuma */
nox_err_t db_save_message(const char *peer_onion, const char *text,
                          bool is_outgoing, time_t timestamp);

typedef void (*db_message_visitor_fn)(const char *text, bool is_outgoing,
                                      time_t timestamp, void *ctx);
nox_err_t db_get_history(const char *peer_onion, int limit,
                         db_message_visitor_fn visitor, void *ctx);
```

#### [MODIFY] [database.c](file:///home/hakan/noxtor-cli/src/database.c)

**`contact_payload` genişletilir:**
```c
struct contact_payload {
    char    onion[NOX_ONION_LEN + 1];              /* Karşı tarafın adresi     */
    char    name[NOX_CONTACT_NAME_LEN + 1];        /* İsim                     */
    uint8_t noise_key[NOX_KEY_LEN];                /* Noise public key         */
    char    my_onion[NOX_ONION_LEN + 1];           /* BİZİM özel adresimiz     */
    uint8_t my_onion_key[NOX_ONION_KEY_B64_LEN];   /* Onion private key (b64)  */
};
```

> [!WARNING]
> `contact_payload` boyutu değiştiğinden, eski veritabanı kayıtları okunamayacaktır. Migration stratejisi:
> - Eski kayıtlar `sizeof(old_payload)` ile decode edilir, yeni alanlar sıfır olarak eklenir.
> - İlk bağlantıda peer'a özel yeni onion otomatik üretilir ve güncellenir.

**Yeni tablo — Mesaj geçmişi:**
```sql
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_hash BLOB NOT NULL,
    nonce BLOB NOT NULL,
    encrypted_payload BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    is_outgoing INTEGER NOT NULL
);
```

**`db_list_contacts` implementasyonu:**
Tüm `contacts` tablosunu tarar, her satırı decrypt eder ve `visitor` callback'ine geçirir. Bu sayede rehber listesi oluşturulabilir.

---

### Bileşen 3: Ağ Katmanı (`network.c` / `network.h`)

#### [MODIFY] [network.h](file:///home/hakan/noxtor-cli/include/network.h)

```c
/* Kalıcı onion — kayıtlı private key ile Hidden Service oluştur */
nox_err_t tor_create_persistent_hs(int ctrl_fd, uint16_t local_port,
                                    const char *onion_key_b64,
                                    char *onion_out, size_t onion_len);

/* Yeni onion üret ve private key'i döndür */
nox_err_t tor_create_new_hs(int ctrl_fd, uint16_t local_port,
                             char *onion_out, size_t onion_len,
                             char *key_out, size_t key_len);
```

#### [MODIFY] [network.c](file:///home/hakan/noxtor-cli/src/network.c)

**`tor_create_persistent_hs`:**
```c
// Komut: ADD_ONION ED25519-V3:<key> Port=9876,127.0.0.1:<port>
// Bu, kaydedilmiş private key ile aynı .onion adresini yeniden oluşturur.
```

**`tor_create_new_hs`:**
```c
// Komut: ADD_ONION NEW:ED25519-V3 Port=9876,127.0.0.1:<port>
// Yanıttaki PrivateKey= satırını parse edip key_out'a kopyalar.
// Yanıttaki ServiceID= satırını parse edip onion_out'a kopyalar.
```

> [!IMPORTANT]
> Tor `ADD_ONION` yanıtında `PrivateKey=ED25519-V3:xxxxx` satırı **yalnızca `NEW:` kullanıldığında** döner. Bu anahtarı yakalamak için `ctrl_read_response` yanıtını ayrıştırmamız gerekir.

---

### Bileşen 4: Olay Döngüsü (`main.c`)

#### [MODIFY] [main.c](file:///home/hakan/noxtor-cli/src/main.c)

Bu en kapsamlı değişikliktir. Mevcut `event_loop` fonksiyonu temelinden yeniden yazılır:

**epoll Değişiklikleri:**
- Tek `peer_fd` yerine `peers[i].fd` dizisi izlenir.
- Her `EPOLLIN` olayında, tetiklenen `fd`'nin hangi peer'a ait olduğu aranır (`fd_to_peer_index` yardımcısı).
- `events[]` dizisi boyutu `4` yerine `4 + NOX_MAX_PEERS * 2` olur (her peer için fd + listen_fd).

**Gelen Bağlantı Dispatching:**
```c
// Eski: if (fd == state->listen_fd) { accept → state->peer_fd }
// Yeni: for each peers[i] → if (fd == peers[i].listen_fd) { accept → peers[i].fd }
```

**Peer Veri Okuma:**
```c
// Eski: if (fd == state->peer_fd) { read frame → process }
// Yeni: int idx = fd_to_peer_index(state, fd);
//       if (idx >= 0) { read frame → process for peers[idx] }
```

**Başlangıç Akışı:**
```
1. Tor spawn + bootstrap (aynı)
2. Rehberdeki her kişi için:
   a. listener_create() → peers[i].listen_port
   b. tor_create_persistent_hs(key) → peers[i].my_onion
   c. epoll_add_fd(peers[i].listen_fd)
3. ncurses TUI başlat
4. Event loop
```

---

### Bileşen 5: Komut İşleyici (`stdin_handler.c`)

#### [MODIFY] [stdin_handler.c](file:///home/hakan/noxtor-cli/src/stdin_handler.c)

**Yeni/Değişen Komutlar:**

| Komut | Davranış |
|-------|----------|
| `/list` | Rehberdeki tüm kişileri listele (isim, adres kısaltma, çevrimiçi durumu) |
| `/connect <isim\|onion>` | İsimle veya onion ile bağlan. İsim rehberde aranır. |
| `/switch <isim\|indeks>` | Aktif sohbeti değiştir (ncurses sidebar'da vurgulama güncellenir) |
| `/history [isim]` | Mesaj geçmişini göster (varsayılan: aktif peer) |
| `/rename <yeni_isim>` | Aktif peer'ın rehber ismini değiştir |
| `/disconnect` | Aktif peer'ın bağlantısını kes (oturumu koru) |
| `/addr` | **Aktif peer'a özel** .onion adresini göster (global değil!) |
| `<metin>` | Aktif peer'a (`active_peer_idx`) mesaj gönder |

**`/connect ali` akışı:**
```
1. db_get_contact("ali") ile rehberden onion + my_onion_key bul
2. Eğer my_onion yoksa: tor_create_new_hs() → yeni onion üret → db_add_contact ile kaydet
3. Eğer my_onion varsa: tor_create_persistent_hs(key) → aynı adresi ayağa kaldır
4. listener_create() → peers[idx].listen_port
5. socks5_connect(ali.onion) → peers[idx].fd
6. Noise XX handshake başlat (onion payload = my_onion)
7. active_peer_idx = idx
8. TUI sidebar güncelle
```

---

### Bileşen 6: ncurses TUI (`tui.c` / `tui.h`)

#### [NEW] [tui.h](file:///home/hakan/noxtor-cli/include/tui.h)
#### [NEW] [tui.c](file:///home/hakan/noxtor-cli/src/tui.c)

**Pencere Yapısı (3 Panel):**

```
┌─────────┬────────────────────────────────────┐
│ SIDEBAR │          CHAT PANEL                │
│ (WINDOW)│          (WINDOW)                  │
│         │                                    │
│ Ali   ● │  [14:30] [Ali] merhaba             │
│ Veli  2 │  [14:31] [Sen] selam!              │
│ ─────── │                                    │
│ + Yeni  │                                    │
│         ├────────────────────────────────────┤
│         │ INPUT PANEL (WINDOW)               │
│         │ > mesaj yaz...                      │
└─────────┴────────────────────────────────────┘
```

| Panel | ncurses Window | İşlev |
|-------|---------------|-------|
| Sidebar | `sidebar_win` | Peer listesi, unread badge, çevrimiçi durum |
| Chat | `chat_win` | Mesaj akışı (scrollback buffer) |
| Input | `input_win` | Kullanıcı girdi alanı |

**Kısayollar:**

| Tuş | İşlev |
|-----|-------|
| `Tab` | Sonraki peer'a geç |
| `Shift+Tab` | Önceki peer'a geç |
| `Ctrl+N` | Yeni bağlantı başlat (`/connect` prompt) |
| `Ctrl+P` | Çıkış (mevcut) |
| `Page Up/Down` | Mesaj geçmişinde kaydır |
| `Enter` | Mesaj gönder |

**TUI → Mevcut UI Geçişi:**
Mevcut `ui.c` fonksiyonları (`ui_print_incoming`, `ui_print_outgoing`, vb.) ncurses modunda `chat_win`'e yazdıracak şekilde refactor edilir. `tui_active` flag'i kontrol eder:
- `tui_active = true` → ncurses penceresine yaz
- `tui_active = false` → mevcut ANSI fprintf davranışı (fallback)

---

### Bileşen 7: Onion Handshake Payload Değişikliği

#### [MODIFY] [main.c](file:///home/hakan/noxtor-cli/src/main.c) — Handshake Payload

Şu an handshake payload'ında **global tek .onion adresi** gönderiliyor:

```c
// ESKİ:
handshake_write(state->hs, (const uint8_t *)state->onion_addr, NOX_ONION_LEN + 1, ...);
```

**YENİ:** Her peer'a kendi özel `.onion` adresimizi göndeririz:

```c
// YENİ:
handshake_write(peers[idx].hs, (const uint8_t *)peers[idx].my_onion, NOX_ONION_LEN + 1, ...);
```

---

### Bileşen 8: Makefile ve Bağımlılıklar

#### [MODIFY] [Makefile](file:///home/hakan/noxtor-cli/Makefile)

- `tui.c` → `tui.o` derleme kuralı ekle
- `-lncursesw` (wide-char desteği ile) bağlama satırına ekle
- ncurses yoksa derlemenin başarısız olması yerine, `HAVE_NCURSES` flag'i ile koşullu derleme yapılabilir (fallback: mevcut ANSI TUI)

---

## Uygulama Sırası (Alt Fazlar)

> [!IMPORTANT]
> Bu büyük bir mimari değişikliktir. Aşamalı olarak uygulanmalıdır. Her alt faz kendi başına derlenebilir ve test edilebilir olmalıdır.

### Alt Faz 6.3.1 — Kalıcı Onion Anahtarı
- `tor_create_new_hs` ve `tor_create_persistent_hs` implementasyonu
- `contact_payload` struct genişletme ve veritabanı migration
- `db_list_contacts` implementasyonu
- Ghost modda mevcut ephemeral davranışın korunması
- **Test:** Uygulama yeniden başlatıldığında aynı `.onion` adresinin geri gelmesi

### Alt Faz 6.3.2 — Pairwise Onion Adresleri
- Her yeni peer için ayrı `ADD_ONION` çağrısı
- `peer_session` struct'ı ve `peers[]` dizisine geçiş
- Rehberden yüklenirken her peer için listener + HS oluşturma
- **Test:** İki farklı peer'a farklı `.onion` adresleri verildiğinin doğrulanması

### Alt Faz 6.3.3 — Çoklu Oturum Event Loop
- `event_loop` refactoring: `fd_to_peer_index` dispatching
- `epoll` genişletme: birden fazla `listen_fd` ve `peer_fd`
- `/connect`, `/switch`, `/disconnect` komutları
- İsimle bağlantı (`/connect ali`)
- Tek seferde birden fazla aktif sohbet
- **Test:** İki peer'la aynı anda bağlantı kurma ve mesajlaşma

### Alt Faz 6.3.4 — Mesaj Geçmişi
- `history` tablosu ve `db_save_message` / `db_get_history`
- Gelen/giden her mesajın veritabanına (şifreli) kaydedilmesi
- `/history` komutu
- **Test:** Uygulama yeniden başlatıldıktan sonra geçmişin okunabilmesi

### Alt Faz 6.3.5 — ncurses TUI
- `tui.c` / `tui.h` — 3 panelli arayüz
- Sidebar: peer listesi + unread badge + çevrimiçi durum
- Chat panel: scrollback buffer + mesaj geçmişi yükleme
- Input panel: readline benzeri girdi
- Tab/Shift+Tab ile oturum geçişi
- `ui.c` refactoring: `tui_active` flag'ine göre çıktı yönlendirme
- **Test:** Görsel doğrulama + resize (SIGWINCH) testi

---

## Kesinleşen Kararlar

### S0: Tek Onion Modeli (2026-06-28 — Güncel)

> **Karar:** Pairwise onion iptal, tek onion modeline geçiş.

**Neden:**
- Pairwise onion pratikte sıkıntılı: herkese ayrı onion vermek, out-of-band paylaşım, DB'de key saklama
- Noise protocol zaten pairwise şifreleme sağlıyor (forward secrecy + key freshness)
- Ghost mod zaten ephemeral key üretiyor
- Tor anonimliği zaten koruyor

**Nasıl çalışır:**
```
1. Uygulama açılır → tek HS üretilir → state->onion_addr dolar (kalıcı)
2. /addr → her zaman state->onion_addr gösterir
3. Yeni peer → /add <onion> <isim> → DB'ye kaydedilir
4. Bağlantı gelir → Noise handshake → karşı taraf onion adresini gönderir
5. DB'de aranır → isim/noise_key peers[idx]'ye yazılır
6. Şifreli kanal hazır
```

**Kaldırılan:**
- `ps->my_onion`, `ps->my_onion_key`, `ps->listen_fd`, `ps->listen_path`
- `peer_init_visitor`, `listener_create_at`
- DB'de `my_onion`/`my_onion_key` alanları

**Korunan (Multi-Peer):**
- `peers[NOX_MAX_PEERS]`, `active_peer_idx`, `peer_count`
- `/list`, `/switch`, `/disconnect`, `/msg <onion> <msj>`
- TUI sidebar, per-peer chat buffer

---

### S1: Mesaj Geçmişi → EVET, Şifreli
Mesaj geçmişi diske kaydedilecek. Mevcut `crypto_secretbox_easy` + `db_key` mekanizmasının aynısı kullanılacak. Her mesaj satırı ayrı nonce + şifreli payload olarak `history` tablosunda saklanır. Ghost modda geçmiş kaydedilmez.

### S2: ncurses → OPSİYONEL (Dual-Mode Mimari)
- **ncurses VARSA (`HAVE_NCURSES`):** Çoklu peer, TUI, sidebar, Tab geçişi — tam deneyim.
- **ncurses YOKSA:** Fallback olarak mevcut tek-peer ANSI modu çalışır. `NOX_MAX_PEERS=1`, `peers[0]` kullanılır, hiçbir şey kırılmaz.

```c
// types.h
#ifdef HAVE_NCURSES
  #define NOX_MAX_PEERS  16U
#else
  #define NOX_MAX_PEERS  1U
#endif
```

```makefile
# Makefile — otomatik ncurses tespiti
NCURSES_LIBS := $(shell pkg-config --libs ncursesw 2>/dev/null)
ifneq ($(NCURSES_LIBS),)
  CFLAGS  += -DHAVE_NCURSES $(shell pkg-config --cflags ncursesw)
  LDFLAGS += $(NCURSES_LIBS)
  SRCS    += src/tui.c
endif
```

### S3: Başlangıçta HS Yükleme → İmplementasyon Sırasında Belirlenecek
Sıralı mı yoksa arka plan mı olacağı, gerçek Tor davranışı test edildiğinde kararlaştırılacak.

### S4: `NOX_MAX_PEERS` → 16 (Sabit)
16 yeterli. İleride gerekirse artırılır.

---

## Doğrulama Planı

### Otomatik Testler
- `test_database`: `db_list_contacts`, `db_save_message`, `db_get_history` testleri
- `test_network`: `tor_create_persistent_hs` ve `tor_create_new_hs` yanıt parse testleri
- `make analyze`: Sıfır uyarı zorunluluğu
- `make fuzz`: Mevcut tüm fuzzer'ların yeni yapıyla uyumlu çalışması

### Manuel Doğrulama
- İki Noxtor-CLI instance'ı arasında pairwise onion ile bağlantı kurma
- Aynı anda 2+ peer ile aktif sohbet (ncurses modda)
- Tab ile oturum geçişi ve unread badge doğrulaması
- ncurses olmadan derleme → tek-peer ANSI modunun sorunsuz çalışması
- Uygulama yeniden başlatıldıktan sonra `.onion` adreslerinin korunması
- Ghost modda hiçbir şeyin diske yazılmaması

---

## EK: Detaylı Uygulama Planı (2026-06-24)

### Teknik Kararlar (Güncel)

| Karar | Seçim |
|---|---|
| TUI Teknolojisi | **termbox2** (mevcut 772 satır korunur, ncurses'e geçiş yok) |
| noise_key lookup | Sonra (ayrı iyileştirme) |
| Ortak fingerprint | Sonra (ayrı tasarım kararı) |
| Key rotation | Sonra (gelecek optimizasyonu) |
| State machine refactoring | Sonra (şu an 7 boş stub var, doldurulacak) |
| Test stratejisi | Manuel test (iki terminal, iki instance) |
| Commit zamanlaması | Manuel, her alt fazdan sonra |

### Veri Modeli

#### Mevcut (database.c — değişiklik gerekmez)

```c
struct contact_payload {
    char     onion[63];
    char     name[65];
    uint8_t  noise_key[32];
    char     my_onion[63];      // ← Pairwise için zaten var
    char     my_onion_key[89];  // ← Kalıcı HS için zaten var
};
```

#### Yeni (types.h)

```c
#define NOX_MAX_PEERS  16U

struct peer_session {
    char     peer_onion[NOX_ONION_LEN + 1];
    char     my_onion[NOX_ONION_LEN + 1];
    uint8_t  my_onion_key[NOX_ONION_KEY_B64_LEN + 1];
    char     name[NOX_CONTACT_NAME_LEN + 1];
    int      fd;
    int      listen_fd;
    char     listen_path[NOX_PATH_MAX];
    struct noise_session *session;
    struct noise_handshake *hs;
    time_t   handshake_start;
    size_t   session_arena_mark;
    uint32_t tx_seq;
    uint32_t rx_seq;
    bool     queue_flushed;
    struct file_rx_state rx_file;
    struct file_tx_state tx_file;
    bool     tofu_pending;
    uint8_t  tofu_new_key[NOX_KEY_LEN];
    char     tofu_onion[NOX_ONION_LEN + 1];
    char     tofu_name[NOX_CONTACT_NAME_LEN + 1];
    struct   timespec tofu_start;
    uint8_t  recv_buf[RECV_BUF_CAPACITY];
    size_t   recv_pos;
    peer_state_t state;
    uint32_t unread_count;
    int      hs_attempt_count;
    time_t   hs_window_start;
};

struct app_state {
    struct noise_identity id;
    struct noise_identity peer_id;
    struct noise_session  session;
    struct noise_handshake *hs;
    time_t handshake_start;
    struct config  cfg;
    struct tor     tor;
    struct pollfd  fds[4];
    struct tor_state tor_st;
    struct tor_state tor_hs;
    struct tor_state tor_ev;
    struct arena   session_arena;
    struct arena   msg_arena;
    size_t session_arena_mark;
    bool   session_arena_active;
    struct file_rx_state rx_file;
    struct file_tx_state tx_file;
    size_t   recv_pos;
    uint8_t  recv_buf[4096];
    uint32_t tx_seq;
    uint32_t rx_seq;
    bool     queue_flushed;
    bool     id_loaded;
    bool     has_identity_key;
    uint8_t  peer_onion_hash[BLAKE2b_HASH_LEN];
    char     peer_onion[NOX_ONION_LEN + 1];
    char     peer_name[NOX_CONTACT_NAME_LEN + 1];
    bool     verified;
    uint8_t  peer_noise_pub[32];
    bool     peer_noise_pub_set;
    char     onion_priv_b64[NOX_ONION_KEY_B64_LEN + 1];
    uint8_t  onion_priv[NOX_ONION_PRIV_LEN];
    bool     onion_generated;
    struct sockaddr_un remote_addr;
    socklen_t remote_addr_len;
    peer_state_t state;
    struct timespec handshake_deadline;
    uint8_t  tofu_new_key[NOX_KEY_LEN];
    char     tofu_onion[NOX_ONION_LEN + 1];
    char     tofu_name[NOX_CONTACT_NAME_LEN + 1];
    struct   timespec tofu_start;
    struct epoll_event events[4];

    /* ===== YENİ: Çoklu peer ===== */
    struct peer_session peers[NOX_MAX_PEERS];
    int      active_peer_idx;
    int      peer_count;

    /* ===== ESKİ: Tek peer alanları (kalır, geriye uyumluluk için) ===== */
    int      peer_fd;
    int      listen_fd;
    char     listen_path[NOX_PATH_MAX];
};
```

---

### Alt Faz 6.3.1 — Kalıcı Onion Anahtarı

**Hedef:** Her restart'ta aynı .onion adresleri geri gelsin.
**Tahmini Satır:** ~200
**Dosyalar:** network.c, network.h, main.c

#### network.c Yeni Fonksiyonlar

```c
nox_err_t tor_create_new_hs(int ctrl_fd, const char *listen_path,
                             char *onion_out, size_t onion_len,
                             char *key_out, size_t key_len);
// ADD_ONION NEW:ED25519-V3 → ServiceID + PrivateKey parse

nox_err_t tor_create_persistent_hs(int ctrl_fd, const char *listen_path,
                                    const char *onion_key_b64,
                                    char *onion_out, size_t onion_len);
// ADD_ONION ED25519-V3:<key> → sadece ServiceID parse
```

#### main.c Startup Flow

```
Mevcut:
  tor_create_hidden_service(ctrl_fd, listen_path, onion_addr, sizeof(onion_addr))

Yeni:
  1. DB'den mevcut onion key'i ara (self-key veya ilk contact'tan)
  2. Key varsa → tor_create_persistent_hs(key)
  3. Key yoksa → tor_create_new_hs() → key'i DB'ye kaydet
  4. onion_addr'i peers[0].my_onion'a yaz
```

#### PrivateKey Parse

Tor control port yanıtından `PrivateKey=` alanını parse:
```
250-ServiceID=abc123.onion\r\n
250-PrivateKey=ED25519-V3:base64key\r\n
250 OK\r\n
```

#### Test
- Uygulama yeniden başlatıldığında aynı .onion adresinin gelmesi

---

### ~~Alt Faz 6.3.2 — Pairwise Onion Adresleri~~ İPTAL

> **İPTAL (2026-06-28):** Pairwise onion modeli pratikte sıkıntılı:
> - Her peer'a ayrı onion vermek gerekiyor (karmaşık)
> - Onion'ları karşıya iletmek gerekiyor (out-of-band)
> - DB'de `my_onion`/`my_onion_key` saklaman gerekiyor
> - Buffer havuzu çok karmaşık
> - Ghost mod zaten ephemeral key üretiyor
> - Noise protocol zaten pairwise şifreleme sağlıyor
>
> **Yerine:** Tek onion modeli (herkese aynı .onion adresi).
> Noise protocol zaten her bağlantıyı ayrı şifreler (forward secrecy + key freshness).
>
> Bu fazdaki per-peer HS kodu (`peer_init_visitor`, `listener_create_at`,
> `ps->my_onion`, `ps->listen_fd`, `ps->listen_path`) kaldırılacaktır.
> Multi-peer desteği (peers[], /list, /switch, /disconnect) aynen korunur.

#### ~~Veri Akışı~~ İPTAL

```
~~Ali (/connect veli) →~~
  ~~1. db_get_contact("veli") → peer_onion, name, my_onion, my_onion_key~~
  ~~2. my_onion_key varsa → tor_create_persistent_hs(my_onion_key) → peers[i].my_onion~~
  ~~3. my_onion_key yoksa → tor_create_new_hs() → key'i DB'ye kaydet~~
  ~~4. SOCKS5 proxy üzerinden veli.onion'a bağlan~~
```

nox_err_t db_list_contacts(sqlite3 *db,
                            struct contact_list **out);
```

#### Test
- İki farklı peer'a farklı .onion adresleri verildiğinin doğrulanması

---

### Alt Faz 6.3.3 — Çoklu Oturum Event Loop

**Hedef:** Birden fazla peer ile aynı anda iletişim.
**Tahmini Satır:** ~350
**Dosyalar:** event_loop.c, state_machine.c, stdin_handler.c

#### event_loop.c Değişiklikleri

| Değişiklik | Açıklama |
|---|---|
| `fd_to_peer_index()` | fd → peers[i] eşleştirmesi |
| `events[]` boyutu | `4` → `4 + NOX_MAX_PEERS * 2` |
| Accept routing | Tek `listen_fd` → `peers[i].listen_fd` döngüsü |
| Data routing | `fd == peer_fd` → `fd_to_peer_index(state, fd)` |
| `process_peer_frames()` | `state->session` → `peers[idx].session` |
| Timeout checks | Tek peer → tüm peer'ları tara |
| recv_buf drain | Tek buffer → `peers[idx].recv_buf` |

#### state_machine.c Değişiklikleri

| Değişiklik | Açıklama |
|---|---|
| `sm_dispatch` imzası | `sm_dispatch(state, ev)` → `sm_dispatch(ps, ev)` |
| `action_cleanup` | `state->peer_fd` → `ps->fd`, `state->session` → `ps->session` |
| `action_tofu_accept` | `state->tofu_*` → `ps->tofu_*` |
| Tüm action fonksiyonları | `app_state*` → `peer_session*` parametresi |

#### stdin_handler.c Değişiklikleri

| Komut | Davranış |
|---|---|
| `/connect <isim\|onion>` | Rehberden bul → `peers[idx]` oluştur → SOCKS5 → handshake |
| `/switch <isim\|indeks>` | `active_peer_idx` güncelle → TUI refresh |
| `/disconnect` | `peers[idx]`'i temizle → state → IDLE |
| `/list` | `db_list_contacts` → sidebar'a yaz |
| `/addr` | `peers[active_peer_idx].my_onion` göster |
| `<metin>` | `peers[active_peer_idx]`'e mesaj gönder |

#### Test
- İki peer'la aynı anda bağlantı kurma ve mesajlaşma

---

### Alt Faz 6.3.4 — Mesaj Geçmişi + Peer Silme

**Hedef:** `/history` komutu + TUI'da geçmiş gösterimi + `/peer_delete` ile rehberden kişi silme.
**Tahmini Satır:** ~100
**Dosyalar:** stdin_handler.c, tui.c, database.c

database.c zaten hazır:
- `db_save_message()` ✅
- `db_get_history()` ✅
- `db_delete_conversation()` ✅

#### 6.3.4.1 — Mesaj Kaydetme (Send/Receive)
- Giden mesaj: `send_segmented_message_to()` sonrası `db_save_message(..., true, ...)`
- Gelen mesaj: `event_loop.c` decrypt sonrası `db_save_message(..., false, ...)`
- Ghost modda kayıt yapılmaz

#### 6.3.4.2 — `/history` Komutu
- `db_get_history(onion, 50, history_visitor_cb, state)` ile son 50 mesajı göster
- Aktif peer yoksa argümanla isim/onion belirtilebilir

#### 6.3.4.3 — `/peer_delete <isim|onion>` Komutu
- Rehberden kişiyi siler: `db_delete_contact(onion)` **(yeni fonksiyon — database.c'ye eklenecek)**
- Bağlıysa önce disconnect: `sm_dispatch(ps, state, EV_PEER_DISCONNECTED)`
- Listener'ı kapatır ve `.sock` dosyasını siler
- TUI sidebar'dan kaldırır
- Uyarı: `"[!] <isim> rehberden silinecek. Emin misiniz? (y/n): "` onay ister
- Ghost modda devre dışı
- DB: `DELETE FROM contacts WHERE peer_hash = ?` (hash_onion ile)

#### 6.3.4.4 — TUI'da Geçmiş Yükleme
- Contact'a geçiş yapıldığında `db_get_history(tc->onion, 200, ...)` ile chat panelini doldur
- `TUI_CHAT_SCROLLBACK` (512) yeterli

---

### Alt Faz 6.3.5 — TUI Multi-peer Genişletme

**Hedef:** Per-peer chat buffer, unread badge, Tab ile geçiş.
**Tahmini Satır:** ~150
**Dosyalar:** tui.c

| Değişiklik | Açıklama |
|---|---|
| Per-peer chat buffer | `chat_lines[]` → `peers[i].chat_lines[]` veya ring buffer |
| Unread badge | Sidebar'da `peers[i].unread_count` göster |
| Tab/BackTab | `active_peer_idx` döngüsel geçiş |
| Chat temizleme | Sidebar'da Enter → sadece o peer'ın chat'ini temizle |

---

### Özet Tablosu

| Alt Faz | Satır | Dosya | Bağımlılık |
|---|---|---|---|
| 6.3.1 Kalıcı Onion | ~200 | network.c, network.h, main.c | — |
| 6.3.2 Pairwise Onion | ~250 | types.h, main.c, event_loop.c | 6.3.1 |
| 6.3.3 Çoklu Oturum | ~350 | event_loop.c, state_machine.c, stdin_handler.c | 6.3.2 |
| 6.3.4 Mesaj Geçmişi + Peer Silme | ~100 | stdin_handler.c, tui.c, database.c | 6.3.3 |
| 6.3.5 TUI Genişletme | ~150 | tui.c | 6.3.3 |
| **Toplam** | **~1000** | **~8 dosya** | — |

### Sıralı Uygulama

```
6.3.1 → 6.3.2 → 6.3.3 → 6.3.4 → 6.3.5
```

Her alt faz bağımsız derlenebilir ve test edilebilir.

### Eksik Konular (Bu Plan'a Dahil Değil)

| Konu | Neden |
|---|---|
| noise_key ile contact lookup | Onion rotation koruması — ayrı bir iyileştirme |
| Ortak fingerprint | Out-of-band doğrulama — ayrı bir tasarım kararı |
| Key rotation | Gelecek optimizasyon — şimdilik gerek yok |

---

## Faz 6.3.3 — Çoklu Oturum Event Loop Detaylı Plan

**Tarih:** 2026-06-28
**Durum:** Planlandı, uygulanacak

### Kesinleşen Kararlar

| Karar | Seçim | Neden |
|-------|-------|-------|
| Per-peer listener | **Her peer ayrı listener (Seçenek B)** | Tam pairwise anonimlik gerekli |
| Legacy alan kaldırma | **Faz 6.4'e ertelendi** | Riskli变更, bağımsız faz olarak yapılacak |
| `peer_count` | **Kullan (bitmask yok)** | Tor varken ince optimizasyon gereksiz |
| SM action stubs | **Boş kalsın** | Mevcut bypass zaten sm_dispatch kullanıyor |
| Commit | **Manuel, her alt fazdan sonra** | GPG imzası için |

### Ertelenen (Faz 6.4)

- `app_state`'ten legacy tek-peer alanlarının kaldırılması (types.h:261-315)
  - `session`, `hs`, `handshake_start`, `tofu_start`
  - `peer_fd`, `tx_seq`, `rx_seq`, `session_arena_mark`
  - `recv_buf`, `recv_pos`, `peer_state`, `connect_target`
  - `queue_flushed`, `tofu_pending`, `tofu_peer_fd`, `tofu_onion`, `tofu_name`, `tofu_new_key`, `tofu_arena_mark`
- `main.c` cleanup'dan eski tek-peer temizliği (satır 525-528: `state->peer_fd`)

### Alt Faz 6.3.3.1 — Per-Peer Listener Wiring

**Hedef:** Her peer'a ayrı listener + Tor HS.
**Tahmini Satır:** ~120
**Dosyalar:** main.c, event_loop.c, types.h

#### Startup Akışı

```
Mevcut (main.c):
  1. Tor spawn + bootstrap
  2. listener_create() → state->listen_fd (tek)
  3. tor_create_persistent_hs(onion.key) → state->onion_addr
  4. epoll_add_fd(state->listen_fd)

Yeni:
  1. Tor spawn + bootstrap
  2. db_list_contacts() ile rehberdeki her kişi için:
     a. peers[i].listen_path = "<config_dir>/listen_<i>.sock"
     b. listener_create(peers[i].listen_path) → peers[i].listen_fd
     c. my_onion_key varsa → tor_create_persistent_hs(key) → peers[i].my_onion
     d. my_onion_key yoksa → tor_create_new_hs() → key'i DB'ye kaydet
     e. epoll_add_fd(peers[i].listen_fd)
     f. peer_count++
  3. Event loop
```

#### event_loop.c Değişiklikleri

**Accept routing (satır 597-671):**
```c
// ESKİ:
if (fd == state->listen_fd) { ... }

// YENİ:
for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
    if (fd == state->peers[i].listen_fd) {
        // accept4 → state->peers[i].fd
        // handshake_init(state->peers[i].hs, false, ...)
        // sm_dispatch(&state->peers[i], state, EV_PEER_ACCEPTED)
        break;
    }
}
```

**epoll_setup (main.c):**
- `state->listen_fd` tek global listener olarak KALIR mı yoksa KALDIRILIR mı?
  - **Karar:** KALDIRILIR. Her peer'ın kendi `listen_fd`'i var.
  - `state->listen_fd = -1` yapılır, `epoll_setup()` sadece stdin ve peers[].listen_fd'leri kaydeder.

**events[] boyutu:**
```c
// Zaten doğru:
struct epoll_event events[1 + 2 * NOX_MAX_PEERS];  // 1 stdin + 2*16
```

#### main.c Cleanup

```c
// Tüm peers[] temizle
for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
    if (state->peers[i].listen_fd >= 0) {
        close(state->peers[i].listen_fd);
        unlink(state->peers[i].listen_path);
    }
}
// state->listen_fd artık kullanılmaz
```

#### Test
- Uygulama başlatıldığında rehberdeki her kişi için ayrı `.sock` dosyası oluşur
- `ls -la <config_dir>/listen_*.sock` → 16'ya kadar dosya
- İki instance arasında bağlantı kurulabilir

---

### Alt Faz 6.3.3.2 — Yeni Komutlar

**Hedef:** `/list`, `/switch`, `/disconnect` komutları.
**Tahmini Satır:** ~80
**Dosyalar:** stdin_handler.c, ui.c

#### Komutlar

| Komut | Davranış |
|-------|----------|
| `/list` | `db_list_contacts` → isim, onion kısaltma, çevrimiçi durum, unread count |
| `/switch <isim\|onion>` | İsimle/onion ile peer bul → `active_peer_idx = i` → TUI refresh |
| `/disconnect` | `sm_dispatch(ps, state, EV_PEER_DISCONNECTED)` → slot temizle |

#### `/list` Implementasyonu

```c
// stdin_handler.c
static void handle_list(struct app_state *state) {
    // Rehberden kişileri listele
    db_list_contacts(list_visitor_cb, state);
    // Çevrimiçi durumunu peers[] ile kontrol et
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        if (state->peers[i].state != ST_IDLE) {
            // Bu peer çevrimiçi
        }
    }
}
```

#### `/switch` Implementasyonu

```c
static void handle_switch(struct app_state *state, const char *arg) {
    // İsimle veya onion ile peer bul
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        if (strcmp(state->peers[i].name, arg) == 0 ||
            strcmp(state->peers[i].peer_onion, arg) == 0) {
            state->active_peer_idx = i;
            strncpy(state->active_peer_onion, state->peers[i].peer_onion, ...);
            ui_print_system(state, "Aktif peer: %s", state->peers[i].name);
            return;
        }
    }
    ui_print_error(state, "Peer bulunamadı: %s", arg);
}
```

#### `/disconnect` Implementasyonu

```c
static void handle_disconnect(struct app_state *state) {
    struct peer_session *ps = ACTIVE_PEER(state);
    if (!ps) {
        ui_print_error(state, "Aktif peer yok");
        return;
    }
    sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
    ui_print_system(state, "Bağlantı kesildi: %s", ps->name);
}
```

#### Test
- `/list` → rehberdeki tüm kişiler listelenir, çevrimiçi olanlar işaretli
- `/switch ali` → aktif peer değişir
- `/disconnect` → peer bağlantısı kesilir, slot temizlenir

---

### Alt Faz 6.3.3.3 — Multi-Peer Mesaj Yönlendirme

**Hedef:** Mesajlar doğru peer'a gitsin, `ACTIVE_PEER` bağımlılığı azalsın.
**Tahmini Satır:** ~60
**Dosyalar:** stdin_handler.c, ui.c

#### Değişiklikler

**`send_segmented_message`:**
```c
// ESKİ:
static void send_segmented_message(struct app_state *state, const char *text) {
    struct peer_session *ps = ACTIVE_PEER(state);
    ...
}

// YENİ:
static void send_segmented_message(struct app_state *state, struct peer_session *ps,
                                   const char *text) {
    // ps parametre olarak alınır
}
```

**`process_line`:**
```c
// ESKİ:
send_segmented_message(state, text);

// YENİ:
struct peer_session *ps = ACTIVE_PEER(state);
if (ps) send_segmented_message(state, ps, text);
```

**`/msg <isim> <text>`:**
```c
// YENİ: İsimle peer bul
struct peer_session *find_peer_by_name(struct app_state *state, const char *name);
// /msg → find_peer_by_name → ps'a gönder
```

**`ui_print_incoming`:**
```c
// ESKİ: sadece mesaj gösterir
// YENİ: hangi peer'dan geldiği belli olsun
// [Ali] merhaba  veya  [Veli] selam
```

#### Test
- İki peer'a bağlıyken `/msg ali merhaba` → Ali'ye gider
- `/msg veli selam` → Veli'ye gider
- Gelen mesajlarda hangi peer'dan geldiği görünür

---

### Alt Faz 6.3.3.4 — Peer Count ve State Tracking

**Hedef:** `peer_count` doğru tutulsun, peer bağlantı/kesinti durumları takip edilsin.
**Tahmini Satır:** ~30
**Dosyalar:** event_loop.c, stdin_handler.c, state_machine.c

#### Değişiklikler

**Accept handler:**
```c
state->peer_count++;
```

**action_cleanup:**
```c
state->peer_count--;
```

**Startup:**
```c
state->peer_count = 0;  // zaten {0} ile sıfırlanıyor
```

#### Test
- İki peer bağlan → `peer_count = 2`
- Birini disconnect et → `peer_count = 1`
- `/list` → doğru peer sayısı gösterilir

---

### Uygulama Sırası

```
6.3.3.1 (per-peer listener) → 6.3.3.4 (peer count) → 6.3.3.2 (yeni komutlar) → 6.3.3.3 (mesaj yönlendirme) → test
```

### Doğrulama

- `make clean && make` → sıfır hata
- `make test` → tüm testler başarılı
- İki terminal'de iki instance → pairwise onion ile bağlantı
- `/list`, `/switch`, `/disconnect` manuel test
- `/msg <isim> <text>` ile hedefli mesaj gönderme
