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
SRCS_ALL := $(wildcard $(SRC_DIR)/*.c)
# NO_SECCOMP=1 ise seccomp.c'yi hariç tut
ifeq ($(NO_SECCOMP),1)
    SRCS := $(filter-out $(SRC_DIR)/seccomp.c, $(SRCS_ALL))
else
    SRCS := $(SRCS_ALL)
endif
OBJS     := $(SRCS:%.c=%.o)
DEPS     := $(OBJS:%.o=%.d)

# Test binary'leri — cbmc_ ve fuzz_noise_differential hariç
TEST_SRCS := $(filter-out $(TEST_DIR)/cbmc_%.c $(TEST_DIR)/fuzz_%.c $(TEST_DIR)/test_seccomp.c, $(wildcard $(TEST_DIR)/*.c))
TEST_BINS := $(TEST_SRCS:%.c=%)
TEST_DEPS := $(TEST_SRCS:%.c=%.d)

# Bağımlılık dosyalarını dahil et (varsa)
-include $(DEPS)
-include $(TEST_DEPS)

# ================================================================
# KÜTÜPHANELERd
# ================================================================
# Seccomp — make NO_SECCOMP=1 ile devre dışı bırakılabilir
NO_SECCOMP ?= 0
ifeq ($(NO_SECCOMP),1)
    LIBS_BASE := -lsodium -lsqlite3
    SECCOMP_DEF := -DNO_SECCOMP
else
    LIBS_BASE := -lsodium -lsqlite3 -lseccomp
    SECCOMP_DEF :=
endif

# termbox2 — make TUI=1 ile etkinleşir (header-only, bağımlılık yok)
TUI ?= 0
ifeq ($(TUI),1)
    TUI_DEF := -DHAVE_TERMBOX -DTB_OPT_ATTR_W=32
else
    TUI_DEF := -DANSI_ONLY
endif

LIBS := $(LIBS_BASE)

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
    -Wcast-align \
    -Wcast-qual \
    -Wwrite-strings \
    -Wduplicated-branches \
    -Wduplicated-cond \
    -Wlogical-op \
    -Wjump-misses-init \
    -Wstack-usage=20480 \
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
    $(TUI_DEF) \
    $(SECCOMP_DEF)

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
    -flto=auto \
    -fno-omit-frame-pointer \
    -fcf-protection=full \
    -fhardened \
    -DNDEBUG

RELEASE_LINK := \
    -flto=auto \
    $(LINK_COMMON) \
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
.PHONY: all debug release _release_build analyze test fuzz fuzz-run clean

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
	$(MAKE) _release_build TUI=$(TUI)
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
	$(Q)$(CC) $(filter-out -fhardened,$(CFLAGS)) $^ -o $@ $(LDFLAGS) $(LIBS)

# Nesne dosyası kuralı — bağımlılık takibi dahil
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(MSG) 'CC' '$<'
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -I$(INC_DIR) -c $< -o $@

# ----------------------------------------------------------------
# TESTLER — ASan + UBSan, ayrı .test.o ile NOISE_TEST_DETERMINISTIC
# ----------------------------------------------------------------
TEST_CFLAGS  = $(STD) $(WARN_BASE) $(HARDEN_COMMON) $(DEBUG_FLAGS) \
               -DNOISE_TEST_DETERMINISTIC
TEST_LDFLAGS = $(LINK_COMMON)

# Test-specific src objeler — NOISE_TEST_DETERMINISTIC ile derlenir
TEST_SRC_OBJS = $(filter-out $(SRC_DIR)/main.test.o, $(SRCS:%.c=%.test.o))

$(SRC_DIR)/%.test.o: $(SRC_DIR)/%.c
	$(MSG) 'CC' '$< (test)'
	$(Q)$(CC) $(TEST_CFLAGS) $(DEPFLAGS) -I$(INC_DIR) -c $< -o $@

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

# Test binary kuralı — .test.o objelerine link eder (main.test.o hariç)
# Testlerin kendi main() fonksiyonu var, src/main.test.o çakışır
$(TEST_DIR)/%: $(TEST_DIR)/%.c $(TEST_SRC_OBJS)
	$(MSG) 'TEST' '$@'
	$(Q)$(CC) $(TEST_CFLAGS) $(DEPFLAGS) -I$(INC_DIR) $< $(TEST_SRC_OBJS) \
	    -o $@ $(TEST_LDFLAGS) $(LIBS)

# ----------------------------------------------------------------
# AFL++ FUZZER — make fuzz / make fuzz-run
# afl-gcc-fast ile instrumentasyon, ASan + UBSan
# ----------------------------------------------------------------
FUZZ_DIR     := fuzz
FUZZ_CC      := /tmp/aflpp-build/afl-gcc-fast
FUZZ_CFLAGS  = $(STD) -O2 -g -I$(INC_DIR) \
               -fsanitize=address,undefined \
               -fno-sanitize-recover=all \
               -fno-omit-frame-pointer \
               -DNOISE_TEST_DETERMINISTIC
FUZZ_LDFLAGS = -fsanitize=address,undefined $(LIBS)
FUZZ_SRCS    = $(filter-out $(SRC_DIR)/main.c, $(SRCS))
FUZZ_OBJS    = $(FUZZ_SRCS:$(SRC_DIR)/%.c=$(FUZZ_DIR)/%.fuzz.o)

# Fuzzer kaynak objeleri — afl-gcc-fast ile derlenir
$(FUZZ_DIR)/%.fuzz.o: $(SRC_DIR)/%.c
	$(MSG) 'AFL' '$<'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) -c $< -o $@

# frame_header_decode fuzzer hedefi
$(FUZZ_DIR)/fuzz_frame_decode: $(FUZZ_DIR)/fuzz_frame_decode.c $(FUZZ_OBJS)
	$(MSG) 'FUZZ' '$@'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)
	@echo "[*] Fuzzer binary hazır: $@"

# sanitize_filename fuzzer hedefi
$(FUZZ_DIR)/fuzz_sanitize: $(FUZZ_DIR)/fuzz_sanitize.c $(FUZZ_OBJS)
	$(MSG) 'FUZZ' '$@'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)
	@echo "[*] Fuzzer binary hazır: $@"

# secure_arena fuzzer hedefi
$(FUZZ_DIR)/fuzz_arena: $(FUZZ_DIR)/fuzz_arena.c $(FUZZ_OBJS)
	$(MSG) 'FUZZ' '$@'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)
	@echo "[*] Fuzzer binary hazır: $@"

# stdin fuzzer hedefi
$(FUZZ_DIR)/fuzz_stdin: $(FUZZ_DIR)/fuzz_stdin.c $(FUZZ_OBJS)
	$(MSG) 'FUZZ' '$@'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)
	@echo "[*] Fuzzer binary hazır: $@"

# file_transfer fuzzer hedefi
$(FUZZ_DIR)/fuzz_file_transfer: $(FUZZ_DIR)/fuzz_file_transfer.c $(FUZZ_OBJS)
	$(MSG) 'FUZZ' '$@'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)
	@echo "[*] Fuzzer binary hazır: $@"

# stdin_events fuzzer hedefi
$(FUZZ_DIR)/fuzz_stdin_events: $(FUZZ_DIR)/fuzz_stdin_events.c $(FUZZ_OBJS)
	$(MSG) 'FUZZ' '$@'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)
	@echo "[*] Fuzzer binary hazır: $@"

# ctrl fuzzer hedefi
$(FUZZ_DIR)/fuzz_ctrl: $(FUZZ_DIR)/fuzz_ctrl.c $(FUZZ_OBJS)
	$(MSG) 'FUZZ' '$@'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)
	@echo "[*] Fuzzer binary hazır: $@"

# socks5 fuzzer hedefi
$(FUZZ_DIR)/fuzz_socks5: $(FUZZ_DIR)/fuzz_socks5.c $(FUZZ_OBJS)
	$(MSG) 'FUZZ' '$@'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)
	@echo "[*] Fuzzer binary hazır: $@"

# handshake_read (Noise XX state machine) fuzzer hedefi
$(FUZZ_DIR)/fuzz_handshake: $(FUZZ_DIR)/fuzz_handshake.c $(FUZZ_OBJS)
	$(MSG) 'FUZZ' '$@'
	$(Q)AFL_PATH=/tmp/aflpp-build $(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDFLAGS)
	@echo "[*] Fuzzer binary hazır: $@"

fuzz: $(FUZZ_DIR)/fuzz_frame_decode $(FUZZ_DIR)/fuzz_sanitize $(FUZZ_DIR)/fuzz_arena $(FUZZ_DIR)/fuzz_stdin $(FUZZ_DIR)/fuzz_file_transfer $(FUZZ_DIR)/fuzz_stdin_events $(FUZZ_DIR)/fuzz_ctrl $(FUZZ_DIR)/fuzz_socks5 $(FUZZ_DIR)/fuzz_handshake
	@echo "[*] Fuzzerlar derlendi. Çalıştırmak için: make fuzz-run, make fuzz-run-sanitize, make fuzz-run-arena, make fuzz-run-stdin, make fuzz-run-file_transfer, make fuzz-run-stdin_events, make fuzz-run-ctrl, make fuzz-run-socks5 veya make fuzz-run-handshake"

fuzz-run: fuzz
	@echo "[*] AFL++ başlatılıyor (frame_decode)... Durdurmak için Ctrl+C"
	AFL_SKIP_CPUFREQ=1 \
	AFL_PATH=/tmp/aflpp-build \
	/tmp/aflpp-build/afl-fuzz -i $(FUZZ_DIR)/corpus/frame_decode \
	         -o $(FUZZ_DIR)/findings \
	         -- ./$(FUZZ_DIR)/fuzz_frame_decode

fuzz-run-sanitize: fuzz
	@echo "[*] AFL++ başlatılıyor (sanitize_filename)... Durdurmak için Ctrl+C"
	AFL_SKIP_CPUFREQ=1 \
	AFL_PATH=/tmp/aflpp-build \
	/tmp/aflpp-build/afl-fuzz -i $(FUZZ_DIR)/corpus/sanitize \
	         -o $(FUZZ_DIR)/findings_sanitize \
	         -- ./$(FUZZ_DIR)/fuzz_sanitize

fuzz-run-arena: fuzz
	@echo "[*] AFL++ başlatılıyor (secure_arena)... Durdurmak için Ctrl+C"
	AFL_SKIP_CPUFREQ=1 \
	AFL_PATH=/tmp/aflpp-build \
	/tmp/aflpp-build/afl-fuzz -i $(FUZZ_DIR)/corpus/arena \
	         -o $(FUZZ_DIR)/findings_arena \
	         -- ./$(FUZZ_DIR)/fuzz_arena

fuzz-run-stdin: fuzz
	@echo "[*] AFL++ başlatılıyor (stdin)... Durdurmak için Ctrl+C"
	AFL_SKIP_CPUFREQ=1 \
	AFL_PATH=/tmp/aflpp-build \
	/tmp/aflpp-build/afl-fuzz -i $(FUZZ_DIR)/corpus/stdin \
	         -o $(FUZZ_DIR)/findings_stdin \
	         -- ./$(FUZZ_DIR)/fuzz_stdin

fuzz-run-file_transfer: fuzz
	@echo "[*] AFL++ başlatılıyor (file_transfer)... Durdurmak için Ctrl+C"
	AFL_SKIP_CPUFREQ=1 \
	AFL_PATH=/tmp/aflpp-build \
	/tmp/aflpp-build/afl-fuzz -i $(FUZZ_DIR)/corpus/file_transfer \
	         -o $(FUZZ_DIR)/findings_file_transfer \
	         -- ./$(FUZZ_DIR)/fuzz_file_transfer

fuzz-run-stdin_events: fuzz
	@echo "[*] AFL++ başlatılıyor (stdin_events)... Durdurmak için Ctrl+C"
	AFL_SKIP_CPUFREQ=1 \
	AFL_PATH=/tmp/aflpp-build \
	/tmp/aflpp-build/afl-fuzz -i $(FUZZ_DIR)/corpus/stdin_events \
	         -o $(FUZZ_DIR)/findings_stdin_events \
	         -- ./$(FUZZ_DIR)/fuzz_stdin_events

fuzz-run-ctrl: fuzz
	@echo "[*] AFL++ başlatılıyor (ctrl)... Durdurmak için Ctrl+C"
	AFL_SKIP_CPUFREQ=1 \
	AFL_PATH=/tmp/aflpp-build \
	/tmp/aflpp-build/afl-fuzz -i $(FUZZ_DIR)/corpus/ctrl \
	         -o $(FUZZ_DIR)/findings_ctrl \
	         -- ./$(FUZZ_DIR)/fuzz_ctrl

fuzz-run-socks5: fuzz
	@echo "[*] AFL++ başlatılıyor (socks5)... Durdurmak için Ctrl+C"
	AFL_SKIP_CPUFREQ=1 \
	AFL_PATH=/tmp/aflpp-build \
	/tmp/aflpp-build/afl-fuzz -i $(FUZZ_DIR)/corpus/socks5 \
	         -o $(FUZZ_DIR)/findings_socks5 \
	         -- ./$(FUZZ_DIR)/fuzz_socks5

fuzz-run-handshake: fuzz
	@echo "[*] AFL++ başlatılıyor (handshake_read state machine)... Durdurmak için Ctrl+C"
	AFL_SKIP_CPUFREQ=1 \
	AFL_PATH=/tmp/aflpp-build \
	/tmp/aflpp-build/afl-fuzz -i $(FUZZ_DIR)/corpus/handshake \
	         -o $(FUZZ_DIR)/findings_handshake \
	         -- ./$(FUZZ_DIR)/fuzz_handshake

# ----------------------------------------------------------------
# DIFFERENTIAL FUZZING — noise-c referans ile karşılaştırma (hedefli + kapsamlı)
# ----------------------------------------------------------------
$(TEST_DIR)/fuzz_noise_differential: $(TEST_DIR)/fuzz_noise_differential.c src/noise.c
	$(MSG) 'DIFF' '$<'
	$(Q)$(CC) $(STD) $(HARDEN_COMMON) -fsanitize=address,undefined -DNOISE_TEST_DETERMINISTIC -I$(INC_DIR) \
		$^ -L/usr/local/lib -lnoiseprotocol -lsodium -o $@

differential: $(TEST_DIR)/fuzz_noise_differential
	$(Q)$(TEST_DIR)/fuzz_noise_differential



# ----------------------------------------------------------------
# SECCOMP DENEME
# ----------------------------------------------------------------
$(TEST_DIR)/test_seccomp: $(TEST_DIR)/test_seccomp.c
	$(MSG) 'SECCOMP' '$<'
	$(Q)$(CC) $(STD) $(HARDEN_COMMON) -fsanitize=address,undefined $< -lseccomp -o $@

seccomp-test: $(TEST_DIR)/test_seccomp
	$(Q)LSAN_OPTIONS=detect_leaks=0 ASAN_OPTIONS=detect_leaks=0 $(TEST_DIR)/test_seccomp

# ----------------------------------------------------------------
# TEMİZLİK
# ----------------------------------------------------------------
clean:
	rm -f $(TARGET)
	rm -f $(OBJS) $(DEPS)
	rm -f $(SRC_DIR)/*.test.o $(SRC_DIR)/*.test.d
	rm -f $(TEST_BINS) $(TEST_DEPS)
	rm -f $(FUZZ_DIR)/*.fuzz.o $(FUZZ_DIR)/fuzz_frame_decode $(FUZZ_DIR)/fuzz_sanitize $(FUZZ_DIR)/fuzz_arena $(FUZZ_DIR)/fuzz_stdin $(FUZZ_DIR)/fuzz_file_transfer $(FUZZ_DIR)/fuzz_stdin_events $(FUZZ_DIR)/fuzz_ctrl $(FUZZ_DIR)/fuzz_socks5 $(FUZZ_DIR)/fuzz_handshake
	rm -f $(TEST_DIR)/fuzz_noise_differential

	rm -f $(TEST_DIR)/test_seccomp
	rm -rf $(FUZZ_DIR)/tmp_downloads
	@echo "[*] Temizlendi."
