# paranoidcli — Sertleştirilmiş Makefile
# GCC 14+, C23, Linux x86-64
#
# Kullanım:
#   make              → debug build (ASan + UBSan)
#   make release      → release build (CET, Shadow Stack, -fhardened)
#   make analyze      → -fanalyzer ile statik analiz
#   make test         → testleri ASan/UBSan altında çalıştırır
#   make TUI=1        → ncurses arayüzü (varsayılan: ANSI_ONLY)
#   make clean        → tüm üretilmiş dosyaları siler
#
# Gereksinimler:
#   GCC 14+  (-std=c23, -fhardened, strub desteği için)
#   binutils 2.39+ (-Wl,-z,shstk için)

# ================================================================
# COMPILER — GCC 14 zorunlu
# ================================================================
CC      := gcc
STD     := -std=c23
TARGET  := noxtor-cli

# Sessiz derleme — make V=1 ile verbose
V ?= 0
ifeq ($(V),0)
  Q := @
  MSG = @printf '  %-8s %s\n'
else
  Q :=
  MSG = @\#
endif

# GCC versiyon kontrolü — 14'ten düşükse uyar
GCC_VERSION := $(shell $(CC) -dumpversion | cut -d. -f1)
GCC_OK      := $(shell [ $(GCC_VERSION) -ge 14 ] && echo yes || echo no)
ifeq ($(GCC_OK),no)
    $(warning UYARI: GCC $(GCC_VERSION) tespit edildi. GCC 14+ gerekli.)
    $(warning -fhardened, strub ve -std=c23 GCC 14 olmadan çalışmaz.)
endif

# ================================================================
# DIZIN YAPISI
# ================================================================
SRC_DIR  := src
INC_DIR  := include
TEST_DIR := tests

# ================================================================
# KAYNAK VE NESNE DOSYALARI
# ================================================================
SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(SRCS:%.c=%.o)
DEPS     := $(OBJS:%.o=%.d)

# Test binary'leri
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_BINS := $(TEST_SRCS:%.c=%)
TEST_DEPS := $(TEST_SRCS:%.c=%.d)

# Bağımlılık dosyalarını dahil et (varsa)
-include $(DEPS)
-include $(TEST_DEPS)

# ================================================================
# KÜTÜPHANELERd
# ================================================================
LIBS_BASE := -lsodium -lsqlite3 -lseccomp

# ncurses — make TUI=1 ile etkinleşir
TUI ?= 0
ifeq ($(TUI),1)
    LIBS_TUI := -lncursesw
    TUI_DEF  := -DENABLE_TUI
else
    LIBS_TUI :=
    TUI_DEF  := -DANSI_ONLY
endif

LIBS := $(LIBS_BASE) $(LIBS_TUI)

# ================================================================
# UYARI DUVARI
# ================================================================

# Her build'de ortak uyarılar
WARN_BASE := \
    -Wall \
    -Wextra \
    -Wpedantic \
    -Wshadow \
    -Wformat=2 \
    -Wmissing-prototypes \
    -Wnull-dereference \
    -Wdouble-promotion \
    -Wimplicit-fallthrough \
    -Walloca \
    -Wconversion \
    -Wcast-align \
    -Wcast-qual \
    -Wwrite-strings \
    -Wduplicated-branches \
    -Wduplicated-cond \
    -Wlogical-op \
    -Wjump-misses-init \
    -Wstack-usage=16384 \
    -Wvla \
    -Wformat-overflow=2 \
    -Wstrict-overflow=5 \
    -Wundef \
    -Wredundant-decls

# Yalnızca release'de anlamlı — -O0'da gürültü üretir
WARN_RELEASE := \
    -Winline \
    -Wdisabled-optimization

# ================================================================
# ORTAK SERTLEŞTİRME (tüm build'lerde)
# ================================================================
HARDEN_COMMON := \
    -fstack-protector-strong \
    -fstack-clash-protection \
    -fPIE \
    -pipe \
    $(TUI_DEF)

LINK_COMMON := \
    -pie \
    -Wl,-z,relro \
    -Wl,-z,now \
    -Wl,-z,noexecstack

# ================================================================
# DEBUG BUILD (varsayılan: make)
# ASan + UBSan tam açık, hiçbir hata atlanmaz
# ================================================================
DEBUG_FLAGS := \
    -O0 \
    -g3 \
    -fno-omit-frame-pointer \
    -fno-inline \
    -fno-common \
    -DDEBUG \
    -fsanitize=address,undefined \
    -fsanitize-address-use-after-scope \
    -fsanitize=float-divide-by-zero \
    -fsanitize=signed-integer-overflow \
    -fno-sanitize-recover=all

# ================================================================
# RELEASE BUILD (make release)
# GCC 14 gerektiren flaglar burada — versiyon kontrolü yapılır
# ================================================================
RELEASE_FLAGS := \
    -O2 \
    -g \
    -fno-omit-frame-pointer \
    -fcf-protection=full \
    -fhardened \
    -DNDEBUG

RELEASE_LINK := \
    -Wl,-z,shstk

# ================================================================
# ANALYZE BUILD (make analyze)
# Binary üretir + -fanalyzer çıktısı stderr'e gider
# 2>&1 | tee ile dosyaya yönlendir
# ================================================================
ANALYZE_FLAGS := \
    -O1 \
    -g \
    -D_FORTIFY_SOURCE=3 \
    -fanalyzer \
    -DANALYZE

# ================================================================
# BAĞIMLILIK TAKİBİ
# Her .o kuralında -MMD -MP eklenerek .d dosyaları üretilir
# Sonraki derlemelerde header değişiklikleri otomatik izlenir
# ================================================================
DEPFLAGS := -MMD -MP

# ================================================================
# ASan / UBSan RUNTIME SEÇENEKLERİ
# Yalnızca test hedefinde kullanılır, global export yapılmaz
# ================================================================
ASAN_OPTS  := strict_string_checks=1:\
detect_stack_use_after_return=1:\
check_initialization_order=1:\
strict_init_order=1:\
halt_on_error=1
UBSAN_OPTS := print_stacktrace=1:halt_on_error=1

# ================================================================
# HEDEFLER
# ================================================================
.PHONY: all debug release _release_build analyze test clean

# Varsayılan hedef
all: debug

# ----------------------------------------------------------------
# DEBUG — ASan + UBSan
# ----------------------------------------------------------------
debug: CFLAGS  = $(STD) $(WARN_BASE) $(HARDEN_COMMON) $(DEBUG_FLAGS)
debug: LDFLAGS = $(LINK_COMMON)
debug: $(TARGET)

# ----------------------------------------------------------------
# RELEASE — recursive make ile temiz flag garantisi
# ----------------------------------------------------------------
release:
	@echo "[*] Release build başlıyor (clean + yeniden derleme)..."
	$(MAKE) clean
	$(MAKE) _release_build
	strip --strip-debug $(TARGET)
	@echo "[*] Binary: $(TARGET)"
	@echo "[*] Boyut: $$(du -sh $(TARGET) | cut -f1)"

# İç hedef — doğrudan çağrılmaz
_release_build: CFLAGS  = $(STD) $(WARN_BASE) $(WARN_RELEASE) \
                           $(HARDEN_COMMON) $(RELEASE_FLAGS)
_release_build: LDFLAGS = $(RELEASE_LINK)
_release_build: $(TARGET)

# ----------------------------------------------------------------
# ANALYZE — -fanalyzer raporu + çalışan binary
# Not: çıktıyı kaydetmek için: make analyze 2>&1 | tee analiz.txt
# ----------------------------------------------------------------
analyze: CFLAGS  = $(STD) $(WARN_BASE) $(HARDEN_COMMON) $(ANALYZE_FLAGS)
analyze: LDFLAGS = $(LINK_COMMON)
analyze:
	@echo "[*] -fanalyzer statik analiz başlıyor..."
	$(MAKE) clean
	$(MAKE) $(TARGET) \
	    CFLAGS="$(STD) $(WARN_BASE) $(HARDEN_COMMON) $(ANALYZE_FLAGS)" \
	    LDFLAGS="$(LINK_COMMON)"
	@echo "[*] Analiz tamamlandı. Rapor yukarıdaki derleme çıktısındadır."
	@echo "[*] Kaydetmek için: make analyze 2>&1 | tee analiz.txt"

# ----------------------------------------------------------------
# ANA BINARY DERLEME KURALI
# ----------------------------------------------------------------
$(TARGET): $(OBJS)
	$(MSG) 'LD' '$@'
	$(Q)$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Nesne dosyası kuralı — bağımlılık takibi dahil
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(MSG) 'CC' '$<'
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -I$(INC_DIR) -c $< -o $@

# ----------------------------------------------------------------
# TESTLER — ASan + UBSan, src objelere link eder
# ----------------------------------------------------------------
test: CFLAGS  = $(STD) $(WARN_BASE) $(HARDEN_COMMON) $(DEBUG_FLAGS)
test: LDFLAGS = $(LINK_COMMON)
test: $(TEST_BINS)
	@echo "=== Testler ASan/UBSan altında çalıştırılıyor ==="
	@failed=0; \
	for t in $(TEST_BINS); do \
	    echo ">> $$t"; \
	    ASAN_OPTIONS="$(ASAN_OPTS)" \
	    UBSAN_OPTIONS="$(UBSAN_OPTS)" \
	    ./$$t; \
	    if [ $$? -ne 0 ]; then \
	        echo "HATA: $$t başarısız"; \
	        failed=1; \
	    fi; \
	done; \
	[ $$failed -eq 0 ] && echo "=== Tüm testler başarılı ===" || exit 1

# Test binary kuralı — src objelerine link eder (main.o hariç)
# Testlerin kendi main() fonksiyonu var, src/main.o çakışır
TEST_OBJS = $(filter-out $(SRC_DIR)/main.o, $(OBJS))
$(TEST_DIR)/%: $(TEST_DIR)/%.c $(TEST_OBJS)
	$(MSG) 'TEST' '$@'
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -I$(INC_DIR) $< $(TEST_OBJS) \
	    -o $@ $(LDFLAGS) $(LIBS)

# ----------------------------------------------------------------
# TEMİZLİK
# ----------------------------------------------------------------
clean:
	rm -f $(TARGET)
	rm -f $(OBJS) $(DEPS)
	rm -f $(TEST_BINS) $(TEST_DEPS)
	@echo "[*] Temizlendi."