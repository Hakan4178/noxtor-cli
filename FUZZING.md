# Noxtor-CLI Fuzzing Rehberi ve Yol Haritası

Bu belgede projedeki fuzzer altyapısı, aktif olarak fuzz edilen fonksiyonlar ve gelecekte eklenmesi planlanan hedefler listelenmiştir.

---

## 1. Aktif Fuzz Hedefleri

Şu anda aktif olarak fuzz edilen fonksiyonlar:

*   **`frame_header_decode(const uint8_t *wire, struct frame_header *hdr)`**
    *   **Dosya:** `src/network.c`
    *   **Harness:** `fuzz/fuzz_frame_decode.c`
    *   **Açıklama:** Ağ soketinden gelen ilk 13 byte'lık ham veriyi (magic, type, seq, len) ayrıştırır. Paket sınırlarını ve protokol bütünlüğünü denetler.
    *   **Amaç:** Geçersiz paket boyutları, yanlış magic değerleri veya beklenmedik byte dizilimlerinde ASan/UBSan crash'lerini yakalamak.

*   **`sanitize_filename(char *name, size_t max_len)`**
    *   **Dosya:** `src/file_transfer.c`
    *   **Harness:** `fuzz/fuzz_sanitize.c`
    *   **Açıklama:** Dosya transferi sırasında karşı taraftan gelen dosya adlarını ayrıştırıp temizler.
    *   **Amaç:** Path traversal (örneğin dosya adında `../` geçmesi) ve buffer overflow açıklarını engellemek.

*   **`arena_alloc` / `arena_restore` / `arena_check_canary` (Secure Memory Arena)**
    *   **Dosya:** `src/arena.c`
    *   **Harness:** `fuzz/fuzz_arena.c`
    *   **Açıklama:** Kriptografik anahtarların saklandığı mmap + MAP_LOCKED tabanlı secure bellek yöneticisini test eder.
    *   **Amaç:** Ardışık bellek ayırma, geri yükleme ve canary doğrulaması sırasında oluşabilecek hizalama (alignment) hatalarını, integer overflow veya canary sızma açıklarını tespit etmek.

*   **`process_line(struct app_state *state, const char *line)`**
    *   **Dosya:** `src/stdin_handler.c`
    *   **Harness:** `fuzz/fuzz_stdin.c`
    *   **Açıklama:** Kullanıcının veya otomasyon arayüzünün terminale girdiği komut satırlarını (`/msg`, `/add`, `/connect` vb.) ayrıştırır ve ilgili modüllere yönlendirir.
    *   **Amaç:** Hatalı boşluklar, kontrol karakterleri veya aşırı uzun parametrelerin neden olabileceği parser çökmelerini (crash) tespit etmek.

*   **`file_transfer_handle_rx(struct app_state *state, const uint8_t *payload, uint32_t len)`**
    *   **Dosya:** `src/file_transfer.c`
    *   **Harness:** `fuzz/fuzz_file_transfer.c`
    *   **Açıklama:** Dosya transferi sırasında karşı taraftan gelen dosya paketlerini (Metadata veya veri blokları) alır, şifresini çözer ve diske yazar.
    *   **Amaç:** Dosya metadata ayrıştırma mantığında, hash kontrollerinde veya disk yazma işlemlerinde oluşabilecek olası buffer overflow, integer overflow veya mantıksal hataları yakalamak.

*   **`process_stdin_events(struct app_state *state)`**
    *   **Dosya:** `src/stdin_handler.c`
    *   **Harness:** `fuzz/fuzz_stdin_events.c`
    *   **Açıklama:** Standart girdiden (non-blocking) gelen asenkron veri akışını okur, dinamik olarak büyüyen bir buffer'da tamponlar ve satır satır bölerek `process_line` parser'ına yönlendirir.
    *   **Amaç:** Satır parçalama mantığındaki sınır durumları (`\n`, `\r` konumları), tamponun dinamik büyütülmesi / yeniden konumlandırılması ve kısmi (partial) okuma durumlarında oluşabilecek bellek bozulmalarını veya mantıksal hataları yakalamak.

*   **Tor Control Response Parser (`ctrl_read_line` / `ctrl_read_response`)**
    *   **Dosya:** `src/network.c`
    *   **Harness:** `fuzz/fuzz_ctrl.c`
    *   **Açıklama:** Tor Control Portundan gelen durum ve bootstrap el sıkışma yanıtlarını (`250`, `510` vb.) satır tabanlı okur ve doğrular.
    *   **Amaç:** Tor kontrol soketinden dönebilecek kötü niyetli veya biçimsiz yanıtların arabellek taşması, sonsuz döngü veya mantıksal çökmelere yol açmasını engellemek.

*   **SOCKS5 Response Parser (`socks5_connect` response phase)**
    *   **Dosya:** `src/network.c`
    *   **Harness:** `fuzz/fuzz_socks5.c`
    *   **Açıklama:** SOCKS5 proxy (Tor) el sıkışma yanıtlarını (`VER`, `REP`, `ATYP` ve domain/IP uzunlukları) okur, doğrular ve arta kalan veriyi arabellekten temizler.
    *   **Amaç:** SOCKS5 yanıtlarında gelebilecek hatalı uzunluk bilgileri (domain length) veya tanımsız adres tiplerinin (ATYP) yol açabilecek bellek sınır aşımlarını test etmek.

*   **Noise XX State Machine (`handshake_read`)**
    *   **Dosya:** `src/noise.c`
    *   **Harness:** `fuzz/fuzz_handshake.c`
    *   **Açıklama:** Noise XX el sıkışma mesajlarını (`msg0` / `msg1` / `msg2`) çözen state machine'in parser dayanıklılığını test eder. Girdinin ilk byte'ı kontrol bayrağıdır: initiator/responder, msg_index başlangıcı (0..3; 3 = invalid → STATE error), remote key injection. Production prologue (`"Mustafa Kemal Atatürk"`) kullanılarak code path eşleşmesi sağlanır.
    *   **Amaç:** Truncation, length overflow, malformed token sırası, rastgele remote key, invalid msg_index gibi durumlarda DH hesaplama, MixKey/MixHash, AEAD decrypt ve state machine'in hata yollarının UB / OOB / leak üretmediğini doğrulamak.

---

## 2. Gelecek Yol Haritası (Eklenecek Hedefler)

Gelecekte sisteme entegre edilmesi planlanan fuzz hedefleri listesi:

*   `[ ]` *(şu an boş — tüm aktif hedefler yukarıda)*

---

## 3. Çalıştırma Talimatları

### Ön Hazırlık
AFL++'ın crash'leri gecikmesiz yakalayabilmesi için çekirdek dump mekanizmasını yapılandırın:
```bash
sudo sh -c "echo core > /proc/sys/kernel/core_pattern"
```

### Derleme ve Fuzzing
```bash
make fuzz                    # Tüm fuzzer hedeflerini derler (ASan/UBSan etkin)

make fuzz-run                # frame_header_decode fuzzing'i başlatır
make fuzz-run-sanitize       # sanitize_filename fuzzing'i başlatır
make fuzz-run-arena          # secure_arena fuzzing'i başlatır
make fuzz-run-stdin          # stdin parser fuzzing'i başlatır
make fuzz-run-file_transfer  # file_transfer alıcısı fuzzing'i başlatır
make fuzz-run-stdin_events   # stdin olay akışı ve tamponlama fuzzing'i başlatır
make fuzz-run-ctrl           # Tor kontrol protokolü fuzzer'ını başlatır
make fuzz-run-socks5         # socks5 protokol fuzzer'ını başlatır
make fuzz-run-handshake      # Noise XX state machine (handshake_read) fuzzer'ını başlatır
```
