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

## HACL\* sürümü — kritik

Bu kod 2022'de üretildi; HACL\* API'si sonrasında üç kez kırıldı. Denenenler:

| HACL\* | Sonuç |
|---|---|
| `v0.3.0` (2020-10) | `Lib_RandomBuffer_System_crypto_random` yok; `kremlin/` başlıkları |
| `main` (2025) | `Hacl_Streaming_Blake2_blocks_state_len`, `Hacl_Blake2b_32_blake2b`, `Hacl_Chacha20Poly1305_32_aead_*` yok; `Lib_Memzero0_memzero` → `...memzero0` |
| **`be4a57c` (2022-11-01)** | **altı sembolün hepsi var; shim gerekmiyor** |

Pin: `be4a57ccaa038d838fd1db6c31d02300f8da711b`

## Derleme (doğrulanmış)

```bash
HACL=/tmp/hacl-2022
git init "$HACL" && cd "$HACL"
git remote add origin https://github.com/project-everest/hacl-star.git
git fetch --depth 1 --filter=blob:none origin \
    be4a57ccaa038d838fd1db6c31d02300f8da711b
git checkout FETCH_HEAD
git sparse-checkout init --cone && git sparse-checkout set dist

cd dist/gcc-compatible
./configure
# Çıplak `make` OCaml binding'lerini de derler ve ctypes-foreign ister;
# statik C kütüphanesi hedefini açıkça verin:
make -j"$(nproc)" libevercrypt.a USER_CFLAGS="-Wno-error"
# → libevercrypt.a (~18 MB)
```

```bash
make -C third_party/noise-star/XX_25519_ChaChaPoly_BLAKE2b \
     HACL_HOME=/tmp/hacl-2022 USER_CFLAGS="-Wno-error" -j"$(nproc)"
# → libnoiseapi.a (~174 KB, 70 Noise_XX_* sembolü)
```

Bağlama sırası: `libnoiseapi.a` **sonra** `libevercrypt.a`.

```bash
cc -I third_party/noise-star/XX_25519_ChaChaPoly_BLAKE2b \
   -I /tmp/hacl-2022/dist/karamel/include \
   -I /tmp/hacl-2022/dist/karamel/krmllib/dist/minimal \
   harness.c libnoiseapi.a /tmp/hacl-2022/dist/gcc-compatible/libevercrypt.a
```

### Temizlik

`make clean` `HACL_HOME` tanımlı değilse erken durur (upstream `Makefile.basic`).
Doğrusu:

```bash
make clean HACL_HOME=/tmp/hacl-2022
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
  başına; statik anahtar burada.
- `Noise_XX_device_add_peer(dvp, pinfo, rs)` — XX responder için initiator'ın
  statik anahtarı **önceden** kaydedilmeli ("bilinmeyen uzak statik kabul
  edilmez").
- `Noise_XX__session_create_{initiator,responder}_with_ephemeral(dvp, epriv, epub)`
  — test/bench amaçlı ephemeral enjeksiyonu; bayt-bayt diferansiyelin anahtarı.
- `Noise_XX_pack_message` / `session_write` → ham mesaj (uzunluk öneki yok).
- `Noise_XX_session_get_hash` — handshake hash karşılaştırması için.
- Hata semantiği `Success/Error/Stuck`; noise-c'nin hata kodlarıyla birebir
  eşlenemez → hata yolu diferansiyeli noise-c'de kalmalı.
