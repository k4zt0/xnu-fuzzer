/*
 * executor.c — materialize and issue a program's calls in an isolated child.
 *
 * Each program runs in a fresh fork so userspace faults, port-space damage and
 * fd churn stay contained. A per-call wall-clock budget catches hangs. Kernel
 * panics are NOT observable here (they take the whole machine down); the crash
 * monitor + reboot-persistence layer reconstructs the culprit from disk.
 */
#include "executor.h"
#include "desc.h"
#include "arch.h"
#include "iokit_target.h"
#include "log.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>

/* Communicated from child to parent via exit status:
 *   exit(0)             -> clean
 *   exit(64 + signo)    -> child caught a fatal signal (userspace fault)
 *   killed by signal    -> WIFSIGNALED -> uncaught (e.g. our SIGKILL/timeout)
 * calls_run is not round-tripped in the fast path (kept 0). */
#define XF_CHILDSIG_BASE 64

/* Per-call interruption budget: a single blocking syscall/trap is cut off
 * after this long (via SIGALRM/EINTR) so the whole program keeps making
 * progress instead of the exec eating the full parent timeout. */
#define XF_PER_CALL_US 20000   /* 20 ms */

static void child_arm_call(void) {
    struct itimerval it = { {0,0}, {0, XF_PER_CALL_US} };
    setitimer(ITIMER_REAL, &it, NULL);
}
static void child_disarm_call(void) {
    struct itimerval it = { {0,0}, {0,0} };
    setitimer(ITIMER_REAL, &it, NULL);
}

/* Recovery point: a fatal signal during a call longjmps back so the child
 * skips only the faulting call and continues the sequence — this keeps
 * multi-call programs deep and the child alive (arg faults are benign, not
 * kernel bugs). SIGALRM is left to return normally so a blocking call is
 * merely interrupted (EINTR). */
static sigjmp_buf     s_child_jb;
static volatile sig_atomic_t s_child_faults = 0;
static volatile sig_atomic_t s_in_call = 0;

static void child_sig(int signo) {
    if (signo == SIGALRM) return;          /* interrupt blocking call        */
    if (s_in_call) {
        s_child_faults++;
        siglongjmp(s_child_jb, signo);     /* skip this call, resume loop    */
    }
    _exit(255);                            /* fault outside a call: rare bail */
}

static void child_install_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = child_sig;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   /* NO SA_RESTART: blocking calls return EINTR         */
    int sigs[] = { SIGALRM, SIGSEGV, SIGBUS, SIGSYS, SIGILL, SIGTRAP,
                   SIGFPE, SIGABRT };
    for (size_t i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++)
        sigaction(sigs[i], &sa, NULL);
}

/* ----- child side -------------------------------------------------------- */

/* Resolve a resource slot to its concrete value produced earlier this run. */
static uint64_t resolve_res(const xf_prog *p, uint64_t slot) {
    if (slot >= p->nres) return (uint64_t)-1;
    return p->res_vals[slot];
}

/* Turn a concrete arg into a raw register value, materializing buffers into
 * the child's address space. */
static uint64_t materialize(const xf_prog *p, const xf_call *c,
                            uint32_t ai) {
    const xf_arg *arg = &c->args[ai];
    const xf_arg_desc *ad = c->desc ? &c->desc->args[ai] : NULL;

    switch (arg->type) {
    case XF_ARG_RESOURCE:
        return resolve_res(p, arg->val);
    case XF_ARG_LEN: {
        /* Half the time use the true referenced length, half the fuzzed value
         * (to probe length/overflow mismatches). */
        if (ad && ad->len_ref < c->nargs && (arg->val & 1)) {
            return c->args[ad->len_ref].blob_len;
        }
        return arg->val;
    }
    case XF_ARG_PTR:
    case XF_ARG_BUFFER:
    case XF_ARG_STRING:
        if (arg->blob) return (uint64_t)(uintptr_t)arg->blob;
        /* NULL / tiny buffers: sometimes pass a bare NULL to hit null checks */
        return 0;
    default:
        return arg->val;
    }
}

/* Issue one IOKit external method against a discovered Apple-driver target. */
static void run_iokit_call(const xf_call *c, io_connect_t *conn_cache) {
    const xf_call_desc *d = c->desc;
    if (!d || d->iokit_target < 0 ||
        (uint32_t)d->iokit_target >= g_iokit_ntargets) return;

    xf_iokit_target *tg = &g_iokit_targets[d->iokit_target];
    io_connect_t conn = conn_cache[d->iokit_target];
    if (conn == IO_OBJECT_NULL) {
        io_service_t svc = IOServiceGetMatchingService(
            kIOMainPortDefault, IORegistryEntryIDMatching(tg->entry_id));
        if (svc == IO_OBJECT_NULL) return;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(),
                                         tg->open_type, &conn);
        IOObjectRelease(svc);
        if (kr != KERN_SUCCESS || conn == IO_OBJECT_NULL) return;
        conn_cache[d->iokit_target] = conn;
    }

    uint32_t selector = (uint32_t)(c->args[XF_IOK_ARG_SELECTOR].val %
                                   (tg->max_selector ? tg->max_selector : 1));

    const xf_arg *scal = &c->args[XF_IOK_ARG_SCALARS];
    const xf_arg *sin  = &c->args[XF_IOK_ARG_STRUCT_IN];
    uint32_t out_size  = (uint32_t)(c->args[XF_IOK_ARG_STRUCT_OUT].val % 4097);

    uint64_t input[16] = {0};
    uint32_t inputCnt = 0;
    if (scal->blob && scal->blob_len) {
        inputCnt = scal->blob_len / 8;
        if (inputCnt > 16) inputCnt = 16;
        memcpy(input, scal->blob, inputCnt * 8);
    }

    uint64_t output[64];
    uint32_t outputCnt = 64;

    static uint8_t outbuf[4096];
    size_t outStructCnt = out_size;

    IOConnectCallMethod(conn, selector,
                        input, inputCnt,
                        sin->blob, sin->blob_len,
                        output, &outputCnt,
                        outbuf, &outStructCnt);
    /* Return value ignored: any kIOReturn is a valid fuzz outcome; a bug
     * manifests as a panic (out-of-band) or a hang (timeout). */
}

/* Seal the child off from the manager's inherited descriptors. A fuzzed
 * fd-taking syscall (fchflags, ftruncate, close, dup2, ...) must never reach
 * the manager's log/corpus/state file descriptors — otherwise the fuzzer
 * corrupts its own outputs. Redirect stdio to /dev/null and close everything
 * else; mach ports (IOKit) are unaffected. */
static void child_seal_fds(void) {
    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); }
    int maxfd = getdtablesize();
    if (maxfd > 8192) maxfd = 8192;
    for (int fd = 3; fd < maxfd; fd++) close(fd);
    /* Contain relative-path file creation (fuzzed open(O_CREAT), mkdir, ...)
     * inside a throwaway sandbox so it never litters the project/corpus. */
    if (g_cfg.sandbox_dir) { if (chdir(g_cfg.sandbox_dir) != 0) { /* ignore */ } }
}

/* Execute the whole program in the current (child) process. */
static void child_run(const xf_prog *pc) {
    child_seal_fds();
    /* Ignore job-control stop signals so a fuzzed tty op or self-signal can't
     * park the child in the stopped state. SIGSTOP itself is uncatchable —
     * kill-family and ptrace syscalls are gated as DANGEROUS instead. */
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    child_install_handlers();
    /* Local mutable copy of the resource pool. */
    xf_prog p = *pc;   /* shallow: blobs shared, we only write res_vals */
    for (uint32_t i = 0; i < p.nres; i++) p.res_vals[i] = (uint64_t)-1;

    io_connect_t conn_cache[XF_IOKIT_MAX_TARGETS];
    memset(conn_cache, 0, sizeof(conn_cache));

    for (uint32_t i = 0; i < p.ncalls; i++) {
        const xf_call *c = &p.calls[i];
        const xf_call_desc *d = c->desc;
        if (!d) continue;
        if (d->flags & XF_C_DANGEROUS) continue;  /* never self-destruct    */

        /* Recovery point: a fatal signal inside the call below returns here
         * with a non-zero value, skipping only that call. */
        if (sigsetjmp(s_child_jb, 1) != 0) {
            child_disarm_call();
            s_in_call = 0;
            continue;
        }

        if (d->surface == XF_SURFACE_IOKIT) {
            s_in_call = 1; child_arm_call();
            run_iokit_call(c, conn_cache);
            child_disarm_call(); s_in_call = 0;
            continue;
        }

        uint64_t a[8] = {0};
        uint32_t n = c->nargs < 8 ? c->nargs : 8;
        for (uint32_t k = 0; k < n; k++) a[k] = materialize(&p, c, k);

        int64_t ret;
        s_in_call = 1; child_arm_call();
        if (d->surface == XF_SURFACE_MACH)
            ret = xf_mach_trap(d->number, a);
        else
            ret = xf_bsd_syscall(d->number, a);
        child_disarm_call(); s_in_call = 0;

        /* Capture produced resources (fd / port) for later calls. */
        if (c->res_slot >= 0 && (uint32_t)c->res_slot < p.nres) {
            if (ret >= 0) p.res_vals[c->res_slot] = (uint64_t)ret;
        }
    }
    /* Exit code carries the number of calls that faulted (capped), 0 = clean.
     * Faults are benign userspace telemetry, not kernel bugs. */
    int faults = (int)s_child_faults;
    _exit(faults > 250 ? 250 : faults);
}

/* ----- parent side ------------------------------------------------------- */

void xf_executor_init(void) {
    /* Reap nothing here; parent handles waitpid per exec. Ignore SIGPIPE so a
     * closed pipe never takes down the manager. */
    signal(SIGPIPE, SIG_IGN);
}

void xf_execute(const xf_prog *p, int timeout_ms, xf_exec_result *out) {
    memset(out, 0, sizeof(*out));
    uint64_t t0 = xf_now_ms();

    if (g_cfg.dry_run) {
        /* Validate materialization without touching the kernel. */
        out->status = XF_EXEC_OK;
        out->elapsed_ms = xf_now_ms() - t0;
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        out->status = XF_EXEC_ERROR;
        return;
    }
    if (pid > 0) {
        /* Parent side of the setpgid race: ensure the child's group id equals
         * its pid before we might need kill(-pid). Harmless if the child won
         * the race and already did it. */
        setpgid(pid, pid);
    }
    if (pid == 0) {
        /* Child: default-handle fatal signals so the parent sees WIFSIGNALED.
         * Detach from the controlling terminal's process group so a stray
         * signal to the group can't hit the manager. */
        setpgid(0, 0);
        /* No process-wide alarm(): per-call setitimer (SIGALRM) handles
         * blocking calls; the parent's wall-clock kill is the hang backstop. */
        child_run(p);
        _exit(0);   /* not reached */
    }

    /* Parent: bounded wait. WUNTRACED so a fuzzed self-SIGSTOP (which would
     * otherwise leave the child parked in 'T' and invisible to a plain
     * waitpid) is detected and killed at once instead of leaking. */
    int status = 0;
    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if (w == pid) {
            if (WIFSTOPPED(status)) {
                /* Child stopped itself — nuke its whole group and reap. */
                kill(-pid, SIGKILL);
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                out->status = XF_EXEC_TIMEOUT;   /* treat stop as an anomaly  */
                out->elapsed_ms = xf_now_ms() - t0;
                return;
            }
            break;
        }
        if (w < 0) {
            if (errno == EINTR) continue;
            out->status = XF_EXEC_ERROR;
            return;
        }
        uint64_t now = xf_now_ms();
        if ((int)(now - t0) >= timeout_ms) {
            kill(-pid, SIGKILL);   /* kill the child's process group          */
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            out->status = XF_EXEC_TIMEOUT;
            out->elapsed_ms = now - t0;
            return;
        }
        usleep(200);
    }

    out->elapsed_ms = xf_now_ms() - t0;
    if (WIFSIGNALED(status)) {
        /* Uncaught signal — normally only our own SIGKILL races here. */
        out->status = XF_EXEC_CRASH;
        out->signo  = WTERMSIG(status);
    } else if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 255) {
            /* Fatal signal outside a recoverable call (rare). */
            out->status = XF_EXEC_CHILDSIG;
            out->signo  = 0;
        } else {
            /* code == number of calls that faulted (benign). */
            out->status = XF_EXEC_OK;
            out->child_faults = (uint32_t)code;
        }
    } else {
        out->status = XF_EXEC_OK;
    }
}
