/* ================================================================
 * Seccomp Deneme — ptrace engelleme
 *
 * Bağımsız test: libseccomp ile ptrace'i engelle,
 * sonra deneyip çalışıp çalışmadığını gör.
 *
 * Compile:
 *   cc -o tests/test_seccomp tests/test_seccomp.c -lseccomp
 *
 * Run:
 *   ./tests/test_seccomp
 *   strace ./tests/test_seccomp   ← ptrace hata vermeli
 * ================================================================ */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <seccomp.h>

int main(void) {
    printf("=== Seccomp Deneme: ptrace_engelleme ===\n\n");

    /* 1. Seccomp filter oluştur */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);  /* default: her şeye izin */
    if (!ctx) {
        perror("seccomp_init");
        return 1;
    }

    /* 2. ptrace'i engelle */
    int     rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
                              SCMP_SYS(ptrace), 0);
    if (rc < 0) {
        fprintf(stderr, "seccomp_rule_add(ptrace): error %d\n", rc);
        seccomp_release(ctx);
        return 1;
    }
    printf("[+] ptrace engellendi (SCMP_ACT_ERRNO(EPERM))\n");

    /* 3. load — filter'ı aktif et */
    rc = seccomp_load(ctx);
    if (rc < 0) {
        fprintf(stderr, "seccomp_load: error %d\n", rc);
        seccomp_release(ctx);
        return 1;
    }
    printf("[+] Seccomp filter yüklendi\n");

    /* 4. Filter'ı serbest bırak (artık kernel'de) */
    seccomp_release(ctx);

    /* 5. Normal çalışmayı dene */
    printf("\n--- Normal test ---\n");
    printf("[+] getpid() = %d (çalışmalı)\n", getpid());
    printf("[+] write() = çalışmalı\n");
    write(STDOUT_FILENO, "[+] write test OK\n", 18);

    /* 6. ptrace denemesi — bu artık başarısız olmalı */
    printf("\n--- ptrace test ---\n");
    printf("[!] ptrace denemesi yapılıyor...\n");
    rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (rc == 0) {
        printf("[✗] ptrace BAŞARILI OLDU — seccomp çalışmıyor!\n");
        return 1;
    } else {
        printf("[✓] ptrace ENGELLENDI (errno=%d: %s)\n", errno, strerror(errno));
    }

    /* 7. Diğer tehlikeli syscall'ları da deneyelim */
    printf("\n--- Diğer engellenen syscall'lar ---\n");

    /* mount */
    rc = mount("none", "/tmp", "tmpfs", 0, NULL);
    if (rc < 0) {
        printf("[✓] mount engellendi (errno=%d: %s)\n", errno, strerror(errno));
    } else {
        printf("[✗] mount BAŞARILI OLDU!\n");
    }

    /* reboot */
    rc = reboot(RB_POWER_OFF);
    if (rc < 0) {
        printf("[✓] reboot engellendi (errno=%d: %s)\n", errno, strerror(errno));
    } else {
        printf("[✗] reboot BAŞARILI OLDU!\n");
    }

    printf("\n=== Tamamlandı ===\n");
    return 0;
}
