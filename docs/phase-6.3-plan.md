# Faz 6.3 — Çoklu Oturum, Pairwise Onion ve ncurses TUI Mimari Planı

## Amaç ve Kapsam

Bu faz, Noxtor-CLI'ı tek peer'lı basit bir CLI mesajlaşıcıdan, **Signal benzeri çoklu oturum destekleyen, ncurses tabanlı bir TUI uygulamasına** dönüştürür. Aynı zamanda **her peer için ayrı .onion adresi** (pairwise identity) kullanarak anonimlik korelasyonunu ortadan kaldırır.

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

### 3. Pairwise Identity — Anonimlik Korelasyon Koruması
**Sorun:** Tüm peer'lara aynı `.onion` adresini vermek, iki peer'ın iş birliği yaparak aynı kişiyle konuştuklarını anlamalarına olanak tanır.

**Karar:** Her peer için **ayrı bir `.onion` adresi ve ayrı bir onion özel anahtarı** üretilip saklanır. Ali seni `abc.onion` olarak tanırken, Veli seni `xyz.onion` olarak tanır. İkisi bir araya gelse bile korelasyon kuramazlar.

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
