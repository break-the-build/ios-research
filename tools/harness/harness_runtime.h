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
 * Authorized / own-machine research only (SECURITY.md).
 */
#ifndef IOSR_HARNESS_RUNTIME_H
#define IOSR_HARNESS_RUNTIME_H

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#endif /* IOSR_HARNESS_RUNTIME_H */
