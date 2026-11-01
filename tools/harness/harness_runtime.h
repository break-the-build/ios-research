/*
 * harness_runtime.h — process-level runtime for the standalone driver.
 *
 * 1. Guard Malloc self-arming (HARNESS_GMALLOC builds). Apple's frameworks are
 *    precompiled, so compiler sanitizers in this harness never check their
 *    memory accesses: a heap overflow or use-after-free INSIDE ImageIO went
 *    unseen (measured: returned normally under ASan). libgmalloc puts every
 *    allocation against a guard page and unmaps freed memory, so those bugs
 *    fault at the bad access with no instrumentation of the framework. The
 *    driver re-executes itself once with DYLD_INSERT_LIBRARIES set, so every
 *    launcher (Python target, campaign runner, a shell) gets the oracle.
 *    Set IOSR_GMALLOC_REEXEC=0 when an external tool (e.g. a binary-
 *    instrumentation fuzzer) launches the harness and manages the environment.
 *
 * 2. Crash reporter (non-ASan builds). Under Guard Malloc a detection is a
 *    fatal signal, not a sanitizer report, so on SIGSEGV/SIGBUS/... print a
 *    parseable report to stderr and re-raise:
 *      IOSR-CRASH signal=SIGSEGV addr=0x... pc=0x... access=read|write|exec|unknown
 *      IOSR-FRAME <n> 0x<pc> <module>+0x<offset> <symbol>
 *    ios_research.targets.sigcrash turns it into Diagnostics.
 *
 * 3./4. Liveness: exit when the launcher dies, and an optional per-input
 *    deadline (see "liveness" below).
 *
 * Authorized / own-machine research only (SECURITY.md).
 */
#ifndef IOSR_HARNESS_RUNTIME_H
#define IOSR_HARNESS_RUNTIME_H

#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ucontext.h>
#include <unistd.h>

#define IOSR_GMALLOC_PATH "/usr/lib/libgmalloc.dylib"
#define IOSR_GMALLOC_ACTIVE_ENV "IOSR_GMALLOC_ACTIVE"
#define IOSR_GMALLOC_REEXEC_ENV "IOSR_GMALLOC_REEXEC"
#define IOSR_MAX_FRAMES 32
#define IOSR_ALTSTACK_BYTES (64 * 1024)

#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#define IOSR_HAVE_ASAN 1
#else
#define IOSR_HAVE_ASAN 0
#endif

/* ---- Guard Malloc ------------------------------------------------------- */

static int iosr_guard_malloc_loaded(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "libgmalloc")) return 1;
    }
    return 0;
}

static void iosr_arm_guard_malloc(char **argv) {
#ifdef HARNESS_GMALLOC
    if (iosr_guard_malloc_loaded()) return;
    const char *reexec = getenv(IOSR_GMALLOC_REEXEC_ENV);
    if (reexec && *reexec == '0') return;   /* caller owns the environment (e.g. Jackalope) */
    const char *active = getenv(IOSR_GMALLOC_ACTIVE_ENV);
    if (active && *active == '1') {          /* we re-exec'd, yet it did not load */
        fprintf(stderr, "harness: WARNING Guard Malloc is NOT loaded; heap bugs inside "
                        "frameworks will go undetected\n");
        return;
    }
    if (access(IOSR_GMALLOC_PATH, R_OK) != 0) {
        fprintf(stderr, "harness: WARNING %s missing; running without Guard Malloc\n",
                IOSR_GMALLOC_PATH);
        return;
    }
    char libs[4096];
    const char *existing = getenv("DYLD_INSERT_LIBRARIES");
    if (existing && *existing)
        snprintf(libs, sizeof(libs), "%s:%s", IOSR_GMALLOC_PATH, existing);
    else
        snprintf(libs, sizeof(libs), "%s", IOSR_GMALLOC_PATH);
    setenv("DYLD_INSERT_LIBRARIES", libs, 1);
    setenv(IOSR_GMALLOC_ACTIVE_ENV, "1", 1);
    char self[4096];
    uint32_t len = sizeof(self);
    if (_NSGetExecutablePath(self, &len) == 0) execv(self, argv);
    fprintf(stderr, "harness: WARNING re-exec under Guard Malloc failed; continuing without it\n");
#else
    (void)argv;
#endif
}

/* ---- crash reporter ------------------------------------------------------ */

static const char *iosr_signame(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGBUS: return "SIGBUS";
        case SIGILL: return "SIGILL";
        case SIGTRAP: return "SIGTRAP";
        case SIGABRT: return "SIGABRT";
        case SIGFPE: return "SIGFPE";
        default: return "SIG?";
    }
}

static void iosr_emit(const char *s) {
    size_t n = strlen(s);
    while (n) {
        ssize_t w = write(STDERR_FILENO, s, n);
        if (w <= 0) return;
        s += w;
        n -= (size_t)w;
    }
}

static uintptr_t iosr_strip_pac(uintptr_t p) {
#if defined(__arm64__)
    return p & 0x00007fffffffffffULL;   /* user VA is 47 bits; upper bits may carry a PAC */
#else
    return p;
#endif
}

static void iosr_emit_frame(int i, uintptr_t pc) {
    char line[512];
    Dl_info info;
    if (dladdr((const void *)pc, &info) && info.dli_fname) {
        const char *mod = strrchr(info.dli_fname, '/');
        mod = mod ? mod + 1 : info.dli_fname;
        snprintf(line, sizeof(line), "IOSR-FRAME %d 0x%016lx %s+0x%lx %s\n", i,
                 (unsigned long)pc, mod, (unsigned long)(pc - (uintptr_t)info.dli_fbase),
                 info.dli_sname ? info.dli_sname : "?");
    } else {
        snprintf(line, sizeof(line), "IOSR-FRAME %d 0x%016lx ?+0x0 ?\n", i, (unsigned long)pc);
    }
    iosr_emit(line);
}

static void iosr_crash_handler(int sig, siginfo_t *si, void *ctx) {
    ucontext_t *uc = (ucontext_t *)ctx;
    uintptr_t pc = 0, fp = 0;
    const char *access_kind = "unknown";
#if defined(__arm64__)
    pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    fp = (uintptr_t)__darwin_arm_thread_state64_get_fp(uc->uc_mcontext->__ss);
    uint32_t esr = uc->uc_mcontext->__es.__esr;
    uint32_t ec = esr >> 26;                 /* exception class */
    if (ec == 0x24 || ec == 0x25)            /* data abort: WnR (bit 6) = write */
        access_kind = (esr & (1u << 6)) ? "write" : "read";
    else if (ec == 0x20 || ec == 0x21)       /* instruction abort */
        access_kind = "exec";
#elif defined(__x86_64__)
    pc = (uintptr_t)uc->uc_mcontext->__ss.__rip;
    fp = (uintptr_t)uc->uc_mcontext->__ss.__rbp;
    access_kind = (uc->uc_mcontext->__es.__err & 2) ? "write" : "read";
#endif
    pc = iosr_strip_pac(pc);
    char line[256];
    snprintf(line, sizeof(line), "IOSR-CRASH signal=%s addr=0x%016lx pc=0x%016lx access=%s\n",
             iosr_signame(sig), (unsigned long)(uintptr_t)si->si_addr, (unsigned long)pc,
             access_kind);
    iosr_emit(line);
    iosr_emit_frame(0, pc);
    /* Frame-pointer walk, bounded by this thread's stack. */
    uintptr_t hi = (uintptr_t)pthread_get_stackaddr_np(pthread_self());
    uintptr_t lo = hi - pthread_get_stacksize_np(pthread_self());
    for (int i = 1; i < IOSR_MAX_FRAMES; i++) {
        if (fp < lo || fp + 2 * sizeof(uintptr_t) > hi || (fp & 7) != 0) break;
        uintptr_t next = ((uintptr_t *)fp)[0];
        uintptr_t lr = iosr_strip_pac(((uintptr_t *)fp)[1]);
        if (!lr) break;
        iosr_emit_frame(i, lr);
        if (next <= fp) break;
        fp = next;
    }
    /* SA_RESETHAND restored the default action: re-raise so the process
     * still dies by this signal (the Python target keys on that). */
    raise(sig);
}

static void iosr_install_crash_reporter(void) {
#if !IOSR_HAVE_ASAN               /* ASan builds keep ASan's own reports */
    static char altstack[IOSR_ALTSTACK_BYTES];
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    sigaltstack(&ss, NULL);       /* survive stack-overflow crashes */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = iosr_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGABRT, SIGFPE };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) sigaction(sigs[i], &sa, NULL);
#endif
}

/* ---- liveness ------------------------------------------------------------ */

/* 3. Orphan exit. A harness whose launcher dies (a killed campaign, a closed
 *    shell) is re-parented to launchd and keeps running; stuck on a hanging
 *    input, it and the framework XPC services serving it stay at 100% CPU
 *    (measured: for days, unnoticed). A watcher thread exits the harness when
 *    its parent exits. IOSR_ORPHAN_EXIT=0 turns it off.
 *
 * 4. Per-input deadline. With IOSR_INPUT_TIMEOUT=<seconds>, an input that runs
 *    longer ends the process with "IOSR-HANG input=<i> seconds=<n>" on stderr
 *    and exit status 124, so a batch runner can mark that one input a timeout
 *    and resume after it instead of waiting out the whole batch's budget. */
#define IOSR_EXIT_HANG 124
#define IOSR_EXIT_ORPHANED 125
#define IOSR_ORPHAN_EXIT_ENV "IOSR_ORPHAN_EXIT"
#define IOSR_INPUT_TIMEOUT_ENV "IOSR_INPUT_TIMEOUT"

static void *iosr_parent_watch(void *arg) {
    pid_t parent = (pid_t)(intptr_t)arg;
    int kq = kqueue();
    if (kq >= 0) {
        struct kevent change, event;
        EV_SET(&change, (uintptr_t)parent, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);
        int n = kevent(kq, &change, 1, &event, 1, NULL);
        /* NOTE_EXIT fired, or the parent was already gone (ESRCH). */
        if (n > 0 && (!(event.flags & EV_ERROR) || event.data == ESRCH))
            _exit(IOSR_EXIT_ORPHANED);
        close(kq);
    }
    while (getppid() == parent) sleep(1);    /* kqueue refused: poll instead */
    _exit(IOSR_EXIT_ORPHANED);
    return NULL;
}

static void iosr_watch_parent(void) {
    const char *v = getenv(IOSR_ORPHAN_EXIT_ENV);
    if (v && *v == '0') return;
    pid_t parent = getppid();
    if (parent <= 1) return;                 /* started by launchd: nothing to watch */
    pthread_t t;
    if (pthread_create(&t, NULL, iosr_parent_watch, (void *)(intptr_t)parent) == 0)
        pthread_detach(t);
}

static volatile sig_atomic_t g_iosr_input_index = -1;
static unsigned g_iosr_input_timeout = 0;

static void iosr_hang_handler(int sig) {
    (void)sig;
    char line[96];
    snprintf(line, sizeof(line), "IOSR-HANG input=%d seconds=%u\n",
             (int)g_iosr_input_index, g_iosr_input_timeout);
    iosr_emit(line);
    _exit(IOSR_EXIT_HANG);
}

static void iosr_install_input_deadline(void) {
    const char *v = getenv(IOSR_INPUT_TIMEOUT_ENV);
    long secs = v ? strtol(v, NULL, 10) : 0;
    if (secs <= 0) return;
    g_iosr_input_timeout = (unsigned)secs;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = iosr_hang_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);
}

static void iosr_input_begin(int index) {
    g_iosr_input_index = index;
    if (g_iosr_input_timeout) alarm(g_iosr_input_timeout);
}

static void iosr_input_end(void) {
    if (g_iosr_input_timeout) alarm(0);
}

#endif /* IOSR_HARNESS_RUNTIME_H */
