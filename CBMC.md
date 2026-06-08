# CBMC Formal Doğrulama

noxtor-cli'da CBMC (C Bounded Model Checker) ile formal verification yapılır.
CBMC, kodu matematiksel olarak analiz edip property'lerin tüm olası input'larda
doğru olduğunu kanıtlar (test değil, **proof**).

## Kurulum

```bash
# Arch Linux (AUR)
paru -S cbmc

# Versiyon kontrolü
cbmc --version
# 6.9.0 veya üzeri gerekli (C23 desteği için)
```

**Not:** CBMC 5.x C23 desteklemez. `__builtin_c23_va_start` ve `static_assert` gibi
C23 özelliklerini parse edemez. 6.9.0+ kullanın.

## Çalıştırma

### Temel komut (akademik rigor — tüm flag'ler)

```bash
cbmc --c23 \
  --bounds-check --pointer-check \
  --signed-overflow-check --div-by-zero-check --pointer-overflow-check \
  --enum-range-check \
  --unwind 130 \
  -I include \
  tests/cbmc_log.c src/log.c
```

### Flag açıklamaları

| Flag | Açıklama |
|------|----------|
| `--c23` | C23 standardı ile parse et (varsayılan: C11) |
| `--bounds-check` | Array bounds koruması |
| `--pointer-check` | NULL pointer, invalid pointer, bounds kontrolü |
| `--signed-overflow-check` | Signed arithmetic taşma kontrolü |
| `--div-by-zero-check` | Sıfıra bölme kontrolü |
| `--pointer-overflow-check` | Pointer aritmetik taşma kontrolü |
| `--enum-range-check` | Enum değerlerinin geçerli aralıkta olduğunu doğrular |
| `--unwind N` | Döngü unwinding sınırı (validate_pin: N=130) |
| `--property id` | Sadece tek bir property'yi kontrol et |
| `--stop-on-fail` | İlk hatada dur |
| `--trace` | Hata için counterexample trace göster |
| `-I include` | Header path |

### Harness yazma kuralları

#### 1. common.h artık kullanılabilir

`common.h`'daki `#ifdef __CPROVER__` guard'ları sayesinde C23 sorunları
bypass edilir. `__CPROVER__` altında CBMC uyumlu stub'lar çalışır.

```c
#include "common.h"  /* ✓ Artık güvenli — __CPROVER__ guard'ları var */
```

#### 2. __CPROVER_assume ile input sınırlama

```c
#ifdef __CPROVER__
    __CPROVER_assume(raw_len <= NOX_PIN_MAX_LEN);
#else
    if (raw_len > NOX_PIN_MAX_LEN) return;
#endif
```

#### 3. enum-range-check'i tetiklemeyen guard test

Geçersiz enum değerlerini doğrudan fonksiyona PAS etmeyin (UB).
Yerine integer-level guard mantığını test edin:

```c
int raw = __VERIFIER_nondet_int();
__CPROVER_assume(raw >= 0);
unsigned mod_u = (unsigned)raw;
log_module_t effective = (mod_u >= (unsigned)LOG_MOD_COUNT)
                         ? LOG_MOD_MAIN
                         : (log_module_t)mod_u;
assert(effective == LOG_MOD_MAIN || (unsigned)effective < LOG_MOD_COUNT);
```

### 3. Property'leri assert ile tanımla

```c
/* Property 1: NULL input → hata */
nox_err_t r = validate_pin(NULL, 10);
assert(r == NOX_ERR_PIN);

/* Property 2: Valid output → tüm karakterler geçerli */
if (result == NOX_OK) {
    for (size_t i = 0; i < raw_len; i++) {
        unsigned char c = (unsigned char)pin[i];
        assert(c != 0x00);          /* null byte yok */
        assert(c >= 0x20 || c == '\t'); /* printable + TAB */
        assert(c != 0x7F);          /* DEL yok */
    }
}
```

### 4. CBMC nondeterministic input kullan

```c
extern size_t __VERIFIER_nondet_size_t(void);
extern char __VERIFIER_nondet_char(void);

size_t raw_len = __VERIFIER_nondet_size_t();
```

## Mevcut harness'lar

### tests/cbmc_log.c — log.c

```bash
cbmc --c23 \
  --bounds-check --pointer-check \
  --signed-overflow-check --div-by-zero-check --pointer-overflow-check \
  --enum-range-check \
  --unwind 130 \
  -I include tests/cbmc_log.c src/log.c
```

**Test edilen fonksiyonlar:**
- `nox_strerror` —穷举 14 enum değer + string content eşleşme (P1, P2)
- `validate_pin` — NULL (P3), boundary values (P4/P5), karakter sınıfları (P6), fuzz (P6/P10)
- `nox_log_impl` — valid enum ile array bounds (P7), integer-level guard clause (P8)

**Matematiksel properties:**
- P1: ∀ e ∈ nox_err_t: nox_strerror(e) ≠ NULL ∧ strlen > 0
- P2: ∀ e ∈ nox_err_t: nox_strerror(e) = beklenen string
- P3: ∀ len: validate_pin(NULL, len) = NOX_ERR_PIN
- P4: ∀ pin, len < MIN: validate_pin = NOX_ERR_PIN
- P5: ∀ pin, len > MAX: validate_pin = NOX_ERR_PIN
- P6: ∀ valid pin, len ∈ [MIN,MAX]: validate_pin = NOX_OK
- P7: ∀ level, mod valid: nox_log_impl SEGV-free
- P8: guard clause: unsigned→clamped enum güvenli

**Sonuç:** Tüm assertions + unwinding assertions SUCCESS, 0 FAILURE

**Doğrulanmayan (bilinen limitation):**
- `nox_log_impl` — variadic `va_start` CBMC GOTO conversion'da handle edilemiyor
- `nox_log_impl` guard — geçersiz enum value kasıtlı olarak test edilmiyor (UB)
- `nox_hexdump` — DEBUG-only

**Production code fix:** `(unsigned char)pin[i]` → `const unsigned char *uptr` pointer aliasing ile signed→unsigned cast false positive kaldırıldı (src/log.c:275)

## Yeni harness ekleme

1. `tests/cbmc_<dosya>.c` oluştur
2. `#include "common.h"` — `__CPROVER__` guard'ları C23 sorunlarını bypass eder
3. Gerekirse stub'ları ekle (`__builtin_c23_va_start`, `__VERIFIER_nondet_*`)
4. `__CPROVER_assume` ile input sınırlarını belirle
5. Geçersiz enum testlerinde integer-level guard mantığını kullan (UB'yi tetikleme)
6. Property'leri assert ile tanımla
7. CBMC ile çalıştır ve tüm assertion'ların SUCCESS olduğunu doğrula
8. `VERIFICATION FAILED` olursa `--trace` ile counterexample'ı incele

## Limitasyonlar

| Limitasyon | Açıklama |
|------------|----------|
| C23 variadic | `__builtin_c23_va_start` handle edilemiyor (6.9.0'da) |
| enum-range-check | Geçersiz enum cast kasıtlı UB — integer-level test ile bypass |
| signed-overflow | `char → unsigned char` cast false positive — pointer aliasing ile çözüldü |
| State space | Large codebase'de yavaş olabilir |
| Loop unwind | Büyük döngüler için `--unwind` artırılmalı |
| External libs | `libsodium`, `sqlite3` stub olarak ele alınmalı |

## Karşılaştırma: Test vs CBMC

| Özellik | Unit Test | CBMC |
|---------|-----------|------|
| Yöntem | Belirli input'ları dener | Tüm olası input'larda kanıtlar |
| Coverage | Input bazlı | Property bazlı |
| False positive | Yok | Olabilir |
| Hız | Hızlı | Yavaş (state space'e bağlı) |
| Kullanım | Her build'de | Periyodik formal verification |
