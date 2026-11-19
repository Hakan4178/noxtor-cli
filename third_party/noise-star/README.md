# Noise\* — XX_25519_ChaChaPoly_BLAKE2b (vendor)

`src/noise.c` için **ikinci oracle**: F\* ile biçimsel doğrulanmış Noise
implementasyonu. Bu dizin yalnızca gereken suite'i içerir; üst akış dosyaları
değiştirilmemiştir (SHA-256'lar aşağıda).

## Kaynak

- Depo: <https://github.com/Inria-Prosecco/noise-star>
- Pin: `ca2a3643821cb1433caf1d104f4020534b0d52c6`
- Yol: `noise-all/api-XX/XX_25519_ChaChaPoly_BLAKE2b/`
- Lisans: Apache-2.0 (`LICENSE.md`) — GPL-3.0-or-later ile uyumlu.

Üst akışta 59 protokol × 8 cipher suite var (onlarca MB). Bize yalnızca
`XX_25519_ChaChaPoly_BLAKE2b` gerekiyor: **8 dosya, 229 KB**.
`libnoiseapi.def` bilinçli olarak alınmadı (Windows DLL dışa aktarım listesi).

## HACL\* sürümü — KRİTİK (ABI)

Bu suite, HACL\*'in `Hacl_Blake2b_32_blake2b_init` fonksiyonunun **5 argümanlı**
olduğu döneme karşı üretilmiştir:

```c
void Hacl_Blake2b_32_blake2b_init(uint64_t *wv, uint64_t *hash,
                                  uint32_t kk, uint8_t *k, uint32_t nn);
```

2021-11'den itibaren HACL bu imzayı 3 argümana indirdi
(`init(hash, kk, nn)` + ayrı `update_key`). Vendored `Hacl.h` ve üretilmiş
`Noise_XX.c` 5 argümanlı çağrı yaptığı için yanlış HACL ile linklemek
**sessizce yanlış handshake hash'i** üretir: msg0 dışındaki tüm mesajlar ve
handshake hash'i farklı çıkar. C'de ayrı derleme birimleri arasında tip
kontrolu olmadığı için link sırasında hiçbir uyarı çıkmaz.

| HACL\* | `blake2b_init` | Sonuç |
|---|---|---|
| `v0.3.0` (2020-10) | 5 argüman | `crypto_random` yok; `kremlin/` başlıkları |
| **`349b052` (2021-09-21)** | **5 argüman** | **DOĞRU PIN — tüm semboller + doğru ABI** |
| `16c4798` (2022-07-31) | 3 argüman | ❌ aynı ABI sorunu |
| `be4a57c` (2022-11-01) | 3 argüman | ❌ ABI uyumsuz: yanlış `h`, msg1/msg2/hash farklı |
| `main` (2025) | 3 argüman | ❌ gerekli sembollerin çoğu kaldırılmış |

Pin: `349b0521d5e326caa7a43df0d2f6fd9b18812daf`

### Doğrulama kanıtı

Aynı statik/ephemeral anahtarlar ve prologue ile Noise\* ve `src/noise.c`
karşılaştırıldığında (`-DNOISE_TEST_DETERMINISTIC`):

```
OK   msg0 (initiator e): 32 bayt birebir
OK   msg1 (responder e,ee,s,es): 96 bayt birebir
OK   msg2 (initiator s,se): 64 bayt birebir
OK   hash initiator: 64 bayt birebir
OK   hash responder: 64 bayt birebir
SONUÇ: tüm karşılaştırmalar eşit
```

`be4a57c` ile aynı test şunu veriyordu: msg0 OK, msg1 ilk fark `[64]`
(ciphertext 32..63 birebir → DH anahtarları doğru, **AD/`h` yanlış**), msg2
ilk fark `[32]`, hash tamamen farklı. Kök neden yukarıdaki ABI değişimi. Ayrıca
`Noise_XX_mix_hash` çıktısı one-shot BLAKE2b ile uyuşuyordu (streaming state
yanlış init edilmiş); `349b052` ile `mix_hash == HASH(pad‖prologue) == star`.

## Opsiyonel spike (zorunlu kapı değil)

`tests/noise_star_handshake_spike.c` (~300 satır), aynı anahtarlar/prologue ile
Noise\* ve `noise.c` handshake mesajlarını + başlangıç/nihai hash'ini bayt bayt
karşılaştırır; üç prologue senaryosu (varsayılan / boş / uzun) kapsar.

```bash
scripts/build-noise-star.sh         # HACL* + suite (HACL_DIR varsayılan /tmp/hacl-349b052)
make noise-star-spike               # HACL_DIR=/other/path geçilebilir
```

Spike **zorunlu kapıya girmez**: `TEST_SRCS` filtresi `noise_star_%.c`'yi
hariç tutar; `make test` ve `differential-gate` bunu derlemez/çalıştırmaz.
noise-c diferansiyel kapısı (1,5M+ iddia) hâlâ tek zorunlu oracle'dır; Noise\*
yalnızca handshake happy-path için bağımsız ikinci görüştür. Hata yolu ve
transport (H2 AD) diferansiyeli noise-c'de kalır.

## Derleme

Tek komut: [`scripts/build-noise-star.sh`](../../scripts/build-noise-star.sh).
Aşağıda elle karşılığı (script bunu otomatize eder):

```bash
HACL=/tmp/hacl-349b052
git init "$HACL" && cd "$HACL"
git remote add origin https://github.com/project-everest/hacl-star.git
git fetch --depth 1 --filter=blob:none origin \
    349b0521d5e326caa7a43df0d2f6fd9b18812daf
git checkout FETCH_HEAD
git sparse-checkout init --cone && git sparse-checkout set dist

# Suite'in ürettiği `krml/` include yolları için alias (eski sürüm `kremlin/` kullanır):
cd dist
mkdir -p karamel/include karamel/krmllib/dist
ln -sfn ../../kremlin/include/kremlin karamel/include/krml
ln -sfn ../../../kremlin/kremlib/dist/minimal karamel/krmllib/dist/minimal

cd gcc-compatible
./configure
make -j"$(nproc)" libevercrypt.a USER_CFLAGS="-Wno-error"
# → libevercrypt.a (~9.8 MB)
```

```bash
K=/tmp/hacl-349b052/dist/kremlin
make -C third_party/noise-star/XX_25519_ChaChaPoly_BLAKE2b \
     HACL_HOME=/tmp/hacl-349b052 \
     USER_CFLAGS="-Wno-error -I$K/include -I$K/kremlib/dist/minimal" \
     -j"$(nproc)"
# → libnoiseapi.a (~174 KB, 70 Noise_XX_* sembolü)
```

Bağlama sırası: `libnoiseapi.a` **sonra** `libevercrypt.a`.

```bash
cc -I third_party/noise-star/XX_25519_ChaChaPoly_BLAKE2b \
   -I /tmp/hacl-349b052/dist/karamel/include \
   -I /tmp/hacl-349b052/dist/karamel/krmllib/dist/minimal \
   -I /tmp/hacl-349b052/dist/kremlin/include \
   -I /tmp/hacl-349b052/dist/kremlin/kremlib/dist/minimal \
   harness.c libnoiseapi.a /tmp/hacl-349b052/dist/gcc-compatible/libevercrypt.a
```

### Temizlik

`make clean`, `HACL_HOME` tanımlı değilse erken durur (upstream
`Makefile.basic`). Doğrusu:

```bash
make clean HACL_HOME=/tmp/hacl-349b052
# veya
rm -f *.o *.d *.d.* libnoiseapi.a libnoiseapi.so
```

Yapıtlar repoya girmez (yerel `.gitignore`).

## Dosyalar

| Dosya | Bayt | SHA-256 |
|---|---|---|
| `Hacl.h` | 2325 | `375838b5e3f3763286487db8766bce9931486cdbf9df8830d4686ea21f19d167` |
| `Noise_XX.h` | 2630 | `e7e9eab2fa27625d5c6993c5edbafcbc09a133c6820d2e6bbe1c81a5f1d8f9ae` |
| `XX.h` | 14627 | `eebf8fa9a94e093e90af48641d021d5182d1feadf6d680c85c03a62dc123d5a8` |
| `Noise_XX.c` | 6780 | `1e8005547e729ab0113ff86d04bdcf9234ac861d66b8b972e3cf4c6602437b3f` |
| `XX.c` | 200136 | `c6e1fdf97905260a1bc217c23e44293ade243f6802f39ec2cdf22346597d6d6c` |
| `Makefile` | 23 | `3ac7fe5b1503052aff03199ac135f3ac814cc1ef273f0ddbe691eb175a9ce68d` |
| `Makefile.basic` | 1356 | `4fe1878863c64dc4616cc126a45fbd3536734b05369215e01ffe4727fc9e9842` |
| `Makefile.include` | 116 | `31e1b668d95c886b7c21ff4814e537b792151b0e2e795ca9bb2a6d0a89466c6f` |
| `LICENSE.md` | 11357 | `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4` |

## API notları (adaptör için)

- `Noise_XX_device_create(prlg_len, prlg, info, sk, spriv)` — prologue cihaz
  başına; statik anahtar burada. `sk` bir serileştirme anahtarıdır (dummy 32
  byte yeterli); statik private `spriv`'den türetilir.
- `Noise_XX_device_add_peer(dvp, pinfo, rs)` — XX responder için initiator'ın
  statik anahtarı **önceden** kaydedilmeli; initiator tarafı da responder'ı
  tanımalı (aksi halde `session_read` `Stuck` döner).
- `Noise_XX__session_create_{initiator,responder}_with_ephemeral(dvp, epriv, epub)`
  — test/bench amaçlı ephemeral enjeksiyonu; bayt-bayt diferansiyelin anahtarı.
- `Noise_XX_pack_message` / `session_write` → ham mesaj (uzunluk öneki yok).
- `Noise_XX_session_get_hash` — handshake hash karşılaştırması için.
- Hata semantiği `Success/Error/Stuck`; noise-c'nin hata kodlarıyla birebir
  eşlenemez → hata yolu diferansiyeli noise-c'de kalmalı.
