# Build Hedefleri

## Hızlı Referans

| Komut | Ne yapar | Ne zaman kullan |
|-------|----------|-----------------|
| `make` | = `make debug` | Günlük geliştirme |
| `make debug` | ASan + UBSan açık, `-O0`, debug sembolleri | Kod yazarken, bug ararken |
| `make release` | Full hardening, `-O2`, strip | Dağıtım binary'si |
| `make test` | Testleri ASan/UBSan altında çalıştırır | Her commit öncesi |
| `make analyze` | GCC `-fanalyzer` statik analiz | Büyük değişiklik sonrası |
| `make clean` | Tüm .o, binary, test dosyalarını siler | Build sorunlarında |
| `make V=1` | Verbose — GCC komutlarını gösterir | Flag debug için |

## Debug (`make debug`)

```
-O0 -g3 -fsanitize=address,undefined
```

- **Optimizasyon yok** → her satır debugger'da görünür
- **ASan** → heap/stack overflow, use-after-free, double-free yakalar
- **UBSan** → undefined behavior (signed overflow, null deref, vb.)
- `LOG_DEBUG` makroları aktif, dosya:satır bilgisi logda görünür
- Binary büyük ve yavaş — **sadece geliştirme için**

## Release (`make release`)

```
-O2 -fhardened -fcf-protection=full -D_FORTIFY_SOURCE=3
```

- **Full optimization** + tüm hardening flag'leri
- **CET** (Shadow Stack + IBT) aktif
- **RELRO + NOW** → GOT/PLT tamamen read-only
- `strip --strip-debug` → küçük binary
- `LOG_DEBUG` derlenmeden çıkar, `NDEBUG` tanımlı
- **Dağıtım binary'si** — aktivistlere bu verilir

## Test (`make test`)

- Debug flag'leri ile test binary'lerini derler
- Her test dosyası (`tests/test_*.c`) ayrı binary olur
- `src/main.o` hariç tüm modüllere linklenir
- ASan/UBSan aktif → testlerde bile memory bug yakalanır
- Çıktı: `8/8 test başarılı` veya hangi test fail oldu

## Analyze (`make analyze`)

```
-O1 -fanalyzer
```

- GCC'nin dahili statik analiz motoru
- Double-free, null deref, leak, buffer overflow **derleme zamanında** bulur
- Yavaş ama değerli — büyük refactor sonrası çalıştır
- `make analyze 2>&1 | tee analiz.txt` ile kaydet
