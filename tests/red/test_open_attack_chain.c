/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_open_attack_chain.c — K-26 + T-15 saldırgan zinciri (KASITLI KIRMIZI).
 *
 * Saldırgan modeli: TOFU ile onaylanmış kötü niyetli peer. Zincir:
 *   1) kullanıcı --ghost modunda; peer yine de downloads/ altına yazıyor,
 *   2) gelen dosya kullanıcı onayı olmadan otomatik kabul ediliyor,
 *   3) chunk timeout'u aşılmışken gelen 1 bayt transferi diriltiyor.
 * Üçü de açık bulgu (K-26/S2-FT-1 + T-15). Düzeltilene kadar bu binary
 * exit 1 verir; `make test` kapsamına BİLEREK alınmadı.
 */

#include "common.h"
#include "types.h"
#include "file_transfer.h"
#include "state_machine.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>

#define DL_DIR "tests/.tmp_dl_open_chain"

static struct app_state st;
static int g_red;

/* Kırmızı sayacı — ilk hatada durma, zincirin tamamını raporla. */
#define RED_CHECK(cond, msg) do {                                      \
    if (!(cond)) {                                                     \
        g_red++;                                                       \
        fprintf(stderr, "    KIRMIZI: %s\n", (msg));                    \
    }                                                                  \
} while (0)

/* 305B v1 METADATA: "METADATA\0" + ad(256) + boyut(8 BE) + hash(32). */
static void build_metadata(uint8_t meta[305], const char *name,
                           uint64_t size)
{
    memset(meta, 0, 305);
    memcpy(meta, "METADATA", 9);
    snprintf((char *)meta + 9, 256, "%s", name);
    for (int i = 0; i < 8; i++)
        meta[265 + i] = (uint8_t)(size >> (56 - 8 * i));
    memset(meta + 273, 0xA5, 32); /* sıfır olmayan hash */
}

static int setup_fixture(bool ghost)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx  = -1;
    st.epoll_fd         = -1;
    st.downloads_dir_fd = -1;
    st.ghost_mode       = ghost;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        st.peers[i].fd = -1;
        st.peers[i].rx_file.fd = -1;
        st.peers[i].tx_file.fd = -1;
    }

    if (mkdir(DL_DIR, 0700) != 0) {
        fprintf(stderr, "    fixture: mkdir %s başarısız\n", DL_DIR);
        return 1;
    }
    if (chmod(DL_DIR, 0700) != 0)
        return 1;
    st.downloads_dir_fd = open(DL_DIR,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (st.downloads_dir_fd < 0)
        return 1;

    st.peers[0].state = ST_ACTIVE;
    return 0;
}

static void stage_cleanup(void)
{
    struct peer_session *ps = &st.peers[0];

    if (ps->rx_file.fd >= 0)
        close(ps->rx_file.fd);

    if (st.downloads_dir_fd >= 0) {
        if (ps->rx_file.local_name[0] != '\0')
            unlinkat(st.downloads_dir_fd, ps->rx_file.local_name, 0);
        /* Adlandırma deterministik; fixture kalıntısını da temizle. */
        unlinkat(st.downloads_dir_fd, "received_ghost_probe.bin", 0);
        unlinkat(st.downloads_dir_fd, "received_consent_probe.bin", 0);
        close(st.downloads_dir_fd);
    }
    rmdir(DL_DIR);

    sodium_memzero(&st, sizeof(st));
    ps->rx_file.fd = -1;
}

/* 1) T-15: ghost mod "iz bırakma" sözü verir; RX yolu bunu yok sayıyor. */
static void stage_ghost_rx(void)
{
    fprintf(stderr, "\n[1/3] T-15 — ghost modda uzaktan dosya yazımı\n");
    if (setup_fixture(true) != 0) {
        g_red++;
        return;
    }
    struct peer_session *ps = &st.peers[0];

    uint8_t meta[305];
    build_metadata(meta, "ghost_probe.bin", 1024);
    (void)file_transfer_handle_rx(&st, ps, meta, sizeof(meta));

    RED_CHECK(!ps->rx_file.active,
              "ghost modda RX başlamamalı (aktif transfer iz bırakır)");
    RED_CHECK(faccessat(st.downloads_dir_fd, "received_ghost_probe.bin",
                        F_OK, 0) == -1,
              "ghost modda downloads/ altında dosya oluşmamalı");

    if (ps->rx_file.active)
        fprintf(stderr, "    kanıt: rx_file.active=true, local_name=%s\n",
                ps->rx_file.local_name[0] ? ps->rx_file.local_name : "(yok)");

    stage_cleanup();
}

/* 2) K-26/S2-FT-1: METADATA kullanıcı onayı olmadan diske yazıyor. */
static void stage_no_consent(void)
{
    fprintf(stderr, "\n[2/3] K-26 — onaysız gelen dosya kabulü\n");
    if (setup_fixture(false) != 0) {
        g_red++;
        return;
    }
    struct peer_session *ps = &st.peers[0];

    uint8_t meta[305];
    build_metadata(meta, "consent_probe.bin", 1024);
    (void)file_transfer_handle_rx(&st, ps, meta, sizeof(meta));

    RED_CHECK(!ps->rx_file.active,
              "kullanıcı onayı yokken RX başlamamalı");
    RED_CHECK(faccessat(st.downloads_dir_fd, "received_consent_probe.bin",
                        F_OK, 0) == -1,
              "onay yokken dosya oluşturulmamalı");

    if (ps->rx_file.active)
        fprintf(stderr, "    kanıt: METADATA sonrası dosya açıldı, "
                        "kullanıcıya sorulmadı\n");

    stage_cleanup();
}

/* 3) K-26/A: timeout aşılmışken gelen chunk ölü transferi diriltiyor.
 *    Event loop süpürmeden önce gelen geç chunk, last_chunk_ts'i tazeler;
 *    handler girişte yaş kontrolü yapmıyor. */
static void stage_stale_chunk_revive(void)
{
    fprintf(stderr, "\n[3/3] K-26 — timeout sonrası geç chunk ile diriltme\n");
    if (setup_fixture(false) != 0) {
        g_red++;
        return;
    }
    struct peer_session *ps = &st.peers[0];

    ps->state = ST_FILE_RX;
    ps->rx_file.active = true;
    ps->rx_file.expected_size = 64;
    ps->rx_file.received_bytes = 0;
    snprintf(ps->rx_file.filename, sizeof(ps->rx_file.filename),
             "stale_probe.bin");
    snprintf(ps->rx_file.local_name, sizeof(ps->rx_file.local_name),
             "stale_probe.bin");
    ps->rx_file.fd = openat(st.downloads_dir_fd, "stale_probe.bin",
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (ps->rx_file.fd < 0) {
        g_red++;
        fprintf(stderr, "    fixture: stale dosya açılamadı\n");
        stage_cleanup();
        return;
    }
    clock_gettime(CLOCK_MONOTONIC, &ps->rx_file.last_chunk_ts);
    ps->rx_file.last_chunk_ts.tv_sec -= (NOX_FILE_CHUNK_TIMEOUT_SEC + 5);

    uint8_t byte = 'X';
    (void)file_transfer_handle_rx(&st, ps, &byte, 1);

    RED_CHECK(!ps->rx_file.active,
              "timeout aşılmışsa geç chunk transferi diriltmemeli");
    RED_CHECK(ps->state == ST_ACTIVE,
              "timeout sonrası peer ST_ACTIVE'e dönmeli");
    RED_CHECK(faccessat(st.downloads_dir_fd, "stale_probe.bin",
                        F_OK, 0) == -1,
              "timeout sonrası yarım dosya silinmeli");

    if (ps->rx_file.active)
        fprintf(stderr, "    kanıt: 70s sessizlikten sonra 1 bayt kabul "
                        "edildi (received=%llu)\n",
                (unsigned long long)ps->rx_file.received_bytes);

    stage_cleanup();
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }

    fprintf(stderr, "=== AÇIK SALDIRGAN ZİNCİRİ (K-26 + T-15) ===\n");
    fprintf(stderr, "    TOFU-onaylı peer → ghost ihlali → onaysız kabul "
                    "→ timeout diriltme\n");

    stage_ghost_rx();
    stage_no_consent();
    stage_stale_chunk_revive();

    if (g_red == 0) {
        fprintf(stderr, "\n=== YEŞİL: açıklar kapanmış görünüyor — "
                        "testi make test'e taşıyın ===\n");
        return 0;
    }
    fprintf(stderr, "\n=== KIRMIZI: %d invariant ihlali — K-26/T-15 hâlâ "
                    "açık ===\n", g_red);
    return 1;
}
