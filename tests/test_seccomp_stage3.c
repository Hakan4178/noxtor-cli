/* ================================================================
 * test_seccomp_stage3.c — Stage 3 sıfır-ağ-sızıntısı testi
 *
 * src/seccomp.c'deki seccomp_policy_load(3) yüklenir; politika kopyası
 * DEĞİL. (Ders: kopya politika testi, kaynaktaki regresyonu gizler.)
 *
 * Her test ayrı child process'te çalışır:
 *   1. socket(AF_INET/AF_INET6) tüm tipler (K-03: +BT/SMC/RDS/QIPCRTR)
 *                                          → SIGSYS beklenir
 *   2. S-1 allowlist: AF_UNIX dışı HER domain (AF_PPPOX, AF_TIPC, AF_IB,
 *      AF_MCTP, AF_RXRPC, AF_LLC, AF_IRDA, AF_ISDN, AF_SNA, AF_PHONET,
 *      AF_X25, AF_DECnet, AF_BRIDGE, AF_ASH dahil) → SIGSYS
 *   3. clone() → SIGSYS; clone3 → ENOSYS (fallback yaşar)
 *   4. getaddrinfo/connect                → SIGSYS beklenir
 *   5. symlink/link/chmod/chown/shmat (SHM_EXEC dahil) → SIGSYS
 *      sendto → serbest (glibc send uyumu; TODO(IPC-SENDTO))
 *   6. AF_UNIX/socketpair/mmap RW serbest → yaşaması beklenir
 *      (AF_UNIX'un SOCK_STREAM/DGRAM/SEQPACKET tüm tipleri serbest)
 *
 * NOT: Seccomp filtresi syscall'den önce çalıştığı için kernel'in aile
 * desteği (EAFNOSUPPORT vb.) sonucu DEĞİŞTİRMEZ — aile desteklenmese
 * bile SIGSYS beklenir. "Atla" yolu yoktur: filtreye ulaşmak = regresyon.
 *
 * Build:
 *   make test                    (src .test.o'ları ile link edilir)
 *
 * Run:
 *   ./tests/test_seccomp_stage3
 * ================================================================ */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <seccomp.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <linux/prctl.h>
#include <linux/netlink.h>

#include "common.h"
#include "seccomp_policy.h"

/* Stage 3 filtresini child process'e uygula — GERÇEK politika
 * (src/seccomp.c → seccomp_policy_load). Kopya filtre yerine kaynağın
 * kendisi yüklenir; kaynak↔test sapması artık gizlenemez. */
static int apply_stage3(void) {
  if (seccomp_policy_load(3) != NOX_OK) return -1;
  return 0;
}

/* Test sonuçları */
struct test_case {
  const char *name;
  const char *desc;
  void (*fn)(void);  /* bu fonksiyon asla dönüş yapmaz — SIGSYS ile öldürülür */
  int should_die;    /* 1 = SIGSYS beklenir, 0 = yaşamalı */
};

/* ── Test fonksiyonları ── */

static void test_tcp_v4(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Bu çağrı SIGSYS ile öldürmeli */
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  /* Buraya ulaşırsak test başarısız */
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_tcp_v6(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_udp_v4(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_clone(void) {
  if (apply_stage3() < 0) _exit(2);
  /* glibc clone() wrapper'ı NULL fn ile EINVAL dönür — syscall'a ulaşmaz.
   * Doğrudan syscall() ile deniyoruz. */
  syscall(SYS_clone, 0, NULL, NULL, NULL, 0);
  /* Buraya ulaşırsak seccomp çalışmadı */
  _exit(1);
}

static void test_getaddrinfo(void) {
  if (apply_stage3() < 0) _exit(2);
  /* "8.8.8.8" IP literal — DNS çözümlemez.
   * "google.com" gerçek DNS çözümlemesi gerektirir.
   * glibc nsswitch.files → /etc/hosts'tan çözülebilir,
   * ama AF_NETLINK/AF_INET socket açmaya çalışır. */
  struct addrinfo hints = {0}, *result = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;
  getaddrinfo("google.com", "80", &hints, &result);
  if (result) freeaddrinfo(result);
  _exit(1);
}

/* AF_NETLINK doğrudan test */
static void test_netlink(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_connect_tcp_direct(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Doğrudan connect() denemesi — socket oluşturulamaz */
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd >= 0) {
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(80),
    };
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
  }
  _exit(1);
}

static void test_af_unix_should_work(void) {
  if (apply_stage3() < 0) _exit(2);
  /* AF_UNIX serbest — bu yaşamalı */
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd >= 0) {
    close(fd);
    _exit(0);  /* BAŞARILI: AF_UNIX serbest */
  }
  _exit(1);
}

/* ── S-1: socket() allowlist — AF_UNIX dışı her domain kapalı ──────
 * Aile listesi (deny-list) kapatmadığı, ağ taşıyabilen aileler:
 * AF_PPPOX (PPPoX — 13 Kasım 2026 turunda bu kernelde ETKİN olduğu
 * ölçüldü), AF_TIPC, AF_IB (RDMA), AF_MCTP, AF_RXRPC, AF_LLC, AF_IRDA,
 * AF_ISDN, AF_SNA, AF_PHONET, AF_X25, AF_DECnet, AF_BRIDGE, AF_ASH.
 *
 * Allowlist kuralı: socket(domain != AF_UNIX) → KILL_PROCESS.
 * Seccomp filtresi syscall'den ÖNCE çalışır → aile kernel'de desteklenmese
 * bile SIGSYS beklenir. Bu yüzden kernel hatasına (EAFNOSUPPORT vb.)
 * "atla" yolu YOKTUR: filtreye ulaşmak = regresyon = FAIL. */

/* Test edilecek domain — child fork sonrası bu değeri miras alır */
static int g_af_domain;

static void test_af_family_blocked(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Hangi tip denense filtre aynı anda tetiklenir; kernel ailesi
   * desteklemese bile SIGSYS beklenir. */
  int fd = socket(g_af_domain, SOCK_STREAM, 0);
  if (fd >= 0) close(fd);
  /* Buraya ulaşmak = allowlist kuralı çalışmadı → FAIL */
  _exit(1);
}

/* ── AF_UNIX'un tüm tipleri serbest (allowlist type kısıtı yok) ── */

static void test_af_unix_dgram(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (fd >= 0) { close(fd); _exit(0); }
  _exit(1);
}

static void test_af_unix_seqpacket(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd >= 0) { close(fd); _exit(0); }
  _exit(1);
}

/* ── W^X: executable bellek yaratma engelleme testleri ── */

static void test_mprotect_exec(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Önce RW mapping al (serbest), sonra RX'e çevir → SIGSYS beklenir */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  mprotect(p, 4096, PROT_READ | PROT_EXEC);
  munmap(p, 4096);
  _exit(1);  /* buraya ulaşılırsa filtre çalışmadı */
}

static void test_mmap_exec(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Doğrudan executable mmap → SIGSYS beklenir */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  munmap(p, 4096);
  _exit(1);  /* buraya ulaşılırsa filtre çalışmadı */
}

static void test_mmap_rw_allow(void) {
  if (apply_stage3() < 0) _exit(2);
  /* RW mapping serbest olmalı — normal bellek kullanımı bozulmamalı */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  munmap(p, 4096);
  _exit(0);  /* BAŞARILI: RW mmap serbest */
}

/* ── prctl option filtreleme testleri ── */

static void test_prctl_dumpable_kill(void) {
  if (apply_stage3() < 0) _exit(2);
  /* prctl(PR_SET_DUMPABLE, 1) → KILL (core dump engeli kaldırılamaz) */
  prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
  _exit(1);
}

static void test_prctl_ptracer_kill(void) {
  if (apply_stage3() < 0) _exit(2);
  /* prctl(PR_SET_PTRACER, ANY) → KILL (ptrace attach) */
  prctl(PR_SET_PTRACER, (unsigned long)-1, 0, 0, 0);
  _exit(1);
}

static void test_prctl_nonewprivs_allow(void) {
  if (apply_stage3() < 0) _exit(2);
  /* prctl(PR_SET_NO_NEW_PRIVS, 1) → ALLOW (güvenlik özelliği) */
  int rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  /* prctl başarılı olmalı (rc=0) */
  if (rc == 0)
    _exit(0);  /* BAŞARILI: PR_SET_NO_NEW_PRIVS serbest */
  _exit(1);
}

/* ── fs/kanal ek testleri ── */

static void test_symlink(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Hedef yok — politika bozuksa ENOENT döner, yan etki bırakmaz */
  symlink("/nonexistent-target", "/nonexistent-link");
  _exit(1);  /* buraya ulaşılırsa filtre çalışmadı */
}

static void test_link(void) {
  if (apply_stage3() < 0) _exit(2);
  link("/nonexistent-a", "/nonexistent-b");
  _exit(1);
}

static void test_chmod(void) {
  if (apply_stage3() < 0) _exit(2);
  chmod("/nonexistent", 0600);
  _exit(1);
}

static void test_chown(void) {
  if (apply_stage3() < 0) _exit(2);
  chown("/nonexistent", 0, 0);
  _exit(1);
}

static void test_sendto(void) {
  if (apply_stage3() < 0) _exit(2);
  /* sendto stage 3'te serbest: glibc send() sendto(NULL) kullanır.
   * TODO(IPC-SENDTO): IPC gelince politika tekrar değerlendirilecek. */
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) _exit(2);
  sendto(sv[0], "x", 1, 0, NULL, 0);
  _exit(0);
}

static void test_socketpair_allow(void) {
  if (apply_stage3() < 0) _exit(2);
  /* IPC aynı process içinde — serbest kalmalı */
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) _exit(1);
  close(sv[0]);
  close(sv[1]);
  _exit(0);
}

static void test_mprotect_rw_allow(void) {
  if (apply_stage3() < 0) _exit(2);
  /* PROT_EXEC içermeyen mprotect serbest (normal bellek yönetimi) */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  mprotect(p, 4096, PROT_READ | PROT_WRITE);
  munmap(p, 4096);
  _exit(0);
}

/* ── shmat: W^X ailesinin kalbi (denetim: "stage 3'te yasaklanmıyor") ──
 * shmat tümüyle yasak (blacklist .stage=2 → load(3)'e dahil; W^X ailesi
 * stage-2'den aktarıldı). SHM_EXEC (Linux ≥2.6.9) segmenti YÜRÜTÜLEBİLİR
 * eşler (man7 shmop(2): "Allow the contents ... to be executed") — W^X
 * iddiası bu kural olmadan eksik kalırdı. Bu testler regresyonu yakalar. */
#ifndef SHM_EXEC
#define SHM_EXEC 0100000  /* linux/shm.h — glibc'te her sürümde yok */
#endif

static void test_shmat_shm_exec(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Geçersiz shmid fark etmez — seccomp syscall girişinde KILL eder */
  void *p = shmat(0, NULL, SHM_EXEC);
  if (p != (void *)-1) (void)shmdt(p);
  _exit(1);
}

static void test_shmat_plain(void) {
  if (apply_stage3() < 0) _exit(2);
  /* SHM_EXEC'siz shmat da yasak (kullanım yok — grep doğrulaması) */
  void *p = shmat(0, NULL, 0);
  if (p != (void *)-1) (void)shmdt(p);
  _exit(1);
}

static void test_clone3_enosys(void) {
  if (apply_stage3() < 0) _exit(2);
  /* clone3 → ERRNO(ENOSYS): glibc pthread fallback'i sağlansın */
  struct {
    unsigned long long flags, pidfd, child_tid, parent_tid, exit_signal;
    unsigned long long stack, stack_size, tls, set_tid, set_tid_size, cgroup;
  } args;
  memset(&args, 0, sizeof(args));
  args.flags = CLONE_THREAD;
  errno = 0;
  long r = syscall(SYS_clone3, &args, sizeof(args));
  if (r == -1 && errno == ENOSYS) _exit(0);  /* beklenen */
  _exit(1);
}

#ifdef AF_ALG
static void test_af_alg(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

#ifdef AF_VSOCK
static void test_af_vsock(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

#ifdef AF_XDP
static void test_af_xdp(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_XDP, SOCK_RAW, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

/* ── K-03: eksik AF aileleri (probe8/9) — SIGSYS beklenir ──
 * glibc sabitleri taşımayabilir; kernel uapi değerleriyle tamamla.
 * Politika domain-genelinde kapattığı için tip kombinasyonları da ölür. */
#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#ifndef AF_RDS
#define AF_RDS 21
#endif
#ifndef AF_QIPCRTR
#define AF_QIPCRTR 42
#endif
#ifndef AF_SMC
#define AF_SMC 43
#endif

/* ── S-1 allowlist testi: daha önce aile listesinde OLMAYAN, ağ
 * taşıyabilen aileler. glibc sabitleri taşımayabilir; kernel uapi
 * değerleriyle tamamla (asm-generic/socket.h). */
#ifndef AF_PPPOX
#define NOX_AF_PPPOX 24
#else
#define NOX_AF_PPPOX AF_PPPOX
#endif
#ifndef AF_TIPC
#define NOX_AF_TIPC 30
#else
#define NOX_AF_TIPC AF_TIPC
#endif
#ifndef AF_IB
#define NOX_AF_IB 27
#else
#define NOX_AF_IB AF_IB
#endif
#ifndef AF_MCTP
#define NOX_AF_MCTP 45
#else
#define NOX_AF_MCTP AF_MCTP
#endif
#ifndef AF_RXRPC
#define NOX_AF_RXRPC 33
#else
#define NOX_AF_RXRPC AF_RXRPC
#endif
#ifndef AF_LLC
#define NOX_AF_LLC 26
#else
#define NOX_AF_LLC AF_LLC
#endif
#ifndef AF_IRDA
#define NOX_AF_IRDA 23
#else
#define NOX_AF_IRDA AF_IRDA
#endif
#ifndef AF_ISDN
#define NOX_AF_ISDN 34
#else
#define NOX_AF_ISDN AF_ISDN
#endif
#ifndef AF_SNA
#define NOX_AF_SNA 22
#else
#define NOX_AF_SNA AF_SNA
#endif
#ifndef AF_PHONET
#define NOX_AF_PHONET 35
#else
#define NOX_AF_PHONET AF_PHONET
#endif
#ifndef AF_X25
#define NOX_AF_X25 9
#else
#define NOX_AF_X25 AF_X25
#endif
#ifndef AF_DECnet
#define NOX_AF_DECNET 12
#else
#define NOX_AF_DECNET AF_DECnet
#endif
/* AF_BRIDGE(7) ve AF_ASH(18) glibc'de yok */
#define NOX_AF_BRIDGE 7
#define NOX_AF_ASH 18

static void test_af_bluetooth(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_BLUETOOTH, SOCK_STREAM, 0);  /* probe8: STREAM açıktı */
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_af_smc(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_SMC, SOCK_STREAM, 0);  /* probe8: STREAM açıktı */
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_af_rds(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_RDS, SOCK_SEQPACKET, 0);  /* probe9 */
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_af_qipcrtr(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_QIPCRTR, SOCK_DGRAM, 0);  /* probe9 */
  if (fd >= 0) close(fd);
  _exit(1);
}

/* ── Stage 3 — gerçek event-loop syscall'ları (yaşaması beklenir) ──
 * NoxTor'un stage 3'te fiilen kullandığı syscall'lar:
 *   epoll_create1  → network.c:1810 (event loop kurulumu)
 *   epoll_ctl      → stdin_handler.c:566, event_loop.c (fd kaydı)
 *   epoll_wait     → event_loop.c (ana döngü)
 *   poll           → network.c read_full/write_full/ctrl_read_line
 *   fcntl(F_GETFL) → set_nonblocking deseni
 *   accept4        → event_loop.c:863 (AF_UNIX bağlantı kabulü)
 *   read/write     → network.c read_full/write_full
 *   clock_gettime  → zaman aşımı/aktivite takibi (CLOCK_MONOTONIC)
 *   nanosleep      → network.c safe_nanosleep (backoff)
 * Hiçbiri filtrede değil; stage 3'te event loop'u bloklamamalı. */

static void test_epoll_create1(void) {
  if (apply_stage3() < 0) _exit(2);
  int efd = epoll_create1(EPOLL_CLOEXEC);
  if (efd < 0) _exit(1);
  close(efd);
  _exit(0);
}

static void test_epoll_ctl(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  int efd = epoll_create1(EPOLL_CLOEXEC);
  if (efd < 0) _exit(1);
  struct epoll_event ev = { .events = EPOLLIN, .data.fd = fds[0] };
  int rc = epoll_ctl(efd, EPOLL_CTL_ADD, fds[0], &ev);
  close(fds[0]);
  close(fds[1]);
  close(efd);
  _exit(rc == 0 ? 0 : 1);
}

static void test_epoll_wait(void) {
  if (apply_stage3() < 0) _exit(2);
  int efd = epoll_create1(EPOLL_CLOEXEC);
  if (efd < 0) _exit(1);
  struct epoll_event evs[1];
  /* Kayıtlı fd yok, timeout=0 → olaysız döner */
  int n = epoll_wait(efd, evs, 1, 0);
  close(efd);
  _exit(n == 0 ? 0 : 1);
}

static void test_poll_timeout(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
  /* Veri yok, timeout=0 → 0 döner (read_full/write_full deseni) */
  int r = poll(&pfd, 1, 0);
  close(fds[0]);
  close(fds[1]);
  _exit(r == 0 ? 0 : 1);
}

static void test_fcntl_getfl(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  int fl = fcntl(fds[0], F_GETFL, 0);
  close(fds[0]);
  close(fds[1]);
  _exit(fl >= 0 ? 0 : 1);
}

static void test_accept4(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Abstract AF_UNIX — dosya sistemine dokunmaz (event_loop.c deseni).
   * SOCK_NONBLOCK accept4'ün kendisini bloklamaz → önce client bağlanır,
   * sonra kabul edilir (event_loop.c:863 ile aynı desen). */
  int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sfd < 0) _exit(1);
  struct sockaddr_un sa;
  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  snprintf(sa.sun_path + 1, sizeof(sa.sun_path) - 1, "nox_s3_accept4_%d", (int)getpid());
  if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) _exit(2);
  if (listen(sfd, 1) != 0) _exit(2);
  int cli = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (cli < 0) _exit(2);
  if (connect(cli, (struct sockaddr *)&sa, sizeof(sa)) != 0) _exit(2);
  int cfd = accept4(sfd, NULL, NULL, SOCK_NONBLOCK);
  int ok = (cfd >= 0);
  if (cfd >= 0) close(cfd);
  close(cli);
  close(sfd);
  _exit(ok ? 0 : 1);
}

static void test_read_pipe(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  ssize_t w = write(fds[1], "x", 1);
  char c = 0;
  ssize_t n = (w == 1) ? read(fds[0], &c, 1) : -1;
  close(fds[0]);
  close(fds[1]);
  _exit(n == 1 && c == 'x' ? 0 : 1);
}

static void test_write_pipe(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  ssize_t w = write(fds[1], "x", 1);
  close(fds[0]);
  close(fds[1]);
  _exit(w == 1 ? 0 : 1);
}

static void test_clock_gettime(void) {
  if (apply_stage3() < 0) _exit(2);
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) _exit(1);
  _exit(0);
}

static void test_nanosleep_zero(void) {
  if (apply_stage3() < 0) _exit(2);
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 0 };
  if (nanosleep(&ts, NULL) != 0) _exit(1);
  _exit(0);
}

/* ── Ana test çalıştırıcı ── */

/* run_test dönüş kodu: 1 = PASS, 0 = FAIL */
static int run_test(const char *name __attribute__((unused)), const char *desc, void (*fn)(void), int should_die) {
  printf("  %-38s ", desc);

  pid_t child = fork();
  if (child < 0) {
    printf("[SKIP] fork başarısız\n");
    return 0;
  }

  if (child == 0) {
    fn();  /* asla dönmez — SIGSYS veya _exit */
    _exit(0);
  }

  int status;
  waitpid(child, &status, 0);

  if (should_die) {
    /* SIGSYS ile ölüm bekleniyor */
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
      printf("[PASS] SIGSYS ✓\n");
      return 1;
    } else if (WIFEXITED(status)) {
      printf("[FAIL] exit=%d (SIGSYS bekleniyordu)\n", WEXITSTATUS(status));
      return 0;
    } else {
      printf("[FAIL] signal=%d (SIGSYS bekleniyordu)\n", WTERMSIG(status));
      return 0;
    }
  } else {
    /* Yaşaması bekleniyor */
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      printf("[PASS] yaşadı ✓\n");
      return 1;
    } else if (WIFSIGNALED(status)) {
      printf("[FAIL] signal=%d (yaşaması bekleniyordu)\n", WTERMSIG(status));
      return 0;
    } else {
      printf("[FAIL] exit=%d (yaşaması bekleniyordu)\n", WEXITSTATUS(status));
      return 0;
    }
  }
}

/* Sayaç yönetimi */
static int g_passed = 0;
static int g_total = 0;

static void run(const char *desc, void (*fn)(void), int should_die) {
  int r = run_test(NULL, desc, fn, should_die);
  g_total++;
  g_passed += r;
}

/* AF ailesi testi — domaini fork öncesi ata */
static void run_af_family(const char *desc, int domain) {
  g_af_domain = domain;
  run(desc, test_af_family_blocked, 1);
}

int main(void) {
  printf("=== Seccomp Stage 3 Testi (gerçek politika) ===\n");
  printf("TCP/UDP/clone/DNS/fs/W^X + socket() allowlist doğrulaması\n");
  printf("Her test ayrı child process'te çalışır\n\n");

  /* Engellenmesi gerekenler (SIGSYS beklenir) */
  run("socket(AF_INET, SOCK_STREAM)  ", test_tcp_v4,  1);
  run("socket(AF_INET6, SOCK_STREAM) ", test_tcp_v6,  1);
  run("socket(AF_INET, SOCK_DGRAM)   ", test_udp_v4,  1);
  run("clone()                        ", test_clone,   1);
  run("getaddrinfo(google.com)         ", test_getaddrinfo, 1);
  run("connect(AF_INET, 8.8.8.8:80)  ", test_connect_tcp_direct, 1);
  run("socket(AF_NETLINK, ROUTE)     ", test_netlink, 1);

  /* Serbest olması gerekenler */
  run("socket(AF_UNIX, SOCK_STREAM)   ", test_af_unix_should_work, 0);
  run("socket(AF_UNIX, SOCK_DGRAM)    ", test_af_unix_dgram, 0);
  run("socket(AF_UNIX, SOCK_SEQPACKET)", test_af_unix_seqpacket, 0);

  /* prctl option filtreleme */
  run("prctl(PR_SET_DUMPABLE)         ", test_prctl_dumpable_kill, 1);
  run("prctl(PR_SET_PTRACER)          ", test_prctl_ptracer_kill, 1);
  run("prctl(PR_SET_NO_NEW_PRIVS)     ", test_prctl_nonewprivs_allow, 0);

  /* W^X: executable bellek yaratma */
  run("mprotect(PROT_READ|PROT_EXEC)   ", test_mprotect_exec, 1);
  run("mmap(PROT_READ|WRITE|EXEC)      ", test_mmap_exec, 1);
  run("mmap(PROT_READ|WRITE) serbest   ", test_mmap_rw_allow, 0);
  run("shmat(SHM_EXEC)                 ", test_shmat_shm_exec, 1);
  run("shmat(plain, yasak)             ", test_shmat_plain, 1);

  /* fs/kanal ek testleri */
  run("symlink()                      ", test_symlink, 1);
  run("link()                         ", test_link, 1);
  run("chmod()                        ", test_chmod, 1);
  run("chown()                        ", test_chown, 1);
  run("sendto(AF_UNIX) serbest        ", test_sendto, 0);
  run("socketpair(AF_UNIX) serbest    ", test_socketpair_allow, 0);
  run("mprotect(READ|WRITE) serbest   ", test_mprotect_rw_allow, 0);
  run("clone3 → ENOSYS (fallback)     ", test_clone3_enosys, 0);
#ifdef AF_ALG
  run("socket(AF_ALG)                 ", test_af_alg, 1);
#endif
#ifdef AF_VSOCK
  run("socket(AF_VSOCK)               ", test_af_vsock, 1);
#endif
#ifdef AF_XDP
  run("socket(AF_XDP)                 ", test_af_xdp, 1);
#endif

  /* K-03: eksik AF aileleri (denetim probe8/9 — kapatıldı) */
  run("socket(AF_BLUETOOTH, STREAM)   ", test_af_bluetooth, 1);
  run("socket(AF_SMC, STREAM)         ", test_af_smc, 1);
  run("socket(AF_RDS, SEQPACKET)      ", test_af_rds, 1);
  run("socket(AF_QIPCRTR, DGRAM)      ", test_af_qipcrtr, 1);

  /* ── S-1: allowlist — daha önce engellenmeyen ağ taşıyabilen aileler ── */
  run_af_family("socket(AF_PPPOX)                ", NOX_AF_PPPOX);
  run_af_family("socket(AF_TIPC)                ", NOX_AF_TIPC);
  run_af_family("socket(AF_IB)                  ", NOX_AF_IB);
  run_af_family("socket(AF_MCTP)                ", NOX_AF_MCTP);
  run_af_family("socket(AF_RXRPC)               ", NOX_AF_RXRPC);
  run_af_family("socket(AF_LLC)                 ", NOX_AF_LLC);
  run_af_family("socket(AF_IRDA)                ", NOX_AF_IRDA);
  run_af_family("socket(AF_ISDN)                ", NOX_AF_ISDN);
  run_af_family("socket(AF_SNA)                 ", NOX_AF_SNA);
  run_af_family("socket(AF_PHONET)              ", NOX_AF_PHONET);
  run_af_family("socket(AF_X25)                 ", NOX_AF_X25);
  run_af_family("socket(AF_DECnet)              ", NOX_AF_DECNET);
  run_af_family("socket(AF_BRIDGE)              ", NOX_AF_BRIDGE);
  run_af_family("socket(AF_ASH)                 ", NOX_AF_ASH);

  /* Stage 3 — gerçek event-loop syscall'ları (yaşaması beklenir) */
  run("epoll_create1() serbest        ", test_epoll_create1, 0);
  run("epoll_ctl(ADD) serbest         ", test_epoll_ctl, 0);
  run("epoll_wait(timeout=0) serbest  ", test_epoll_wait, 0);
  run("poll(timeout=0) serbest        ", test_poll_timeout, 0);
  run("fcntl(F_GETFL) serbest         ", test_fcntl_getfl, 0);
  run("accept4(AF_UNIX, nonblock)     ", test_accept4, 0);
  run("read(pipe) serbest             ", test_read_pipe, 0);
  run("write(pipe) serbest            ", test_write_pipe, 0);
  run("clock_gettime(MONOTONIC)       ", test_clock_gettime, 0);
  run("nanosleep(0) serbest           ", test_nanosleep_zero, 0);

  printf("\nSonuç: %d/%d test başarılı\n", g_passed, g_total);
  return (g_passed == g_total) ? 0 : 1;
}
