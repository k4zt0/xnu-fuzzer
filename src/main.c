/*
 * main.c — the fuzzer manager / scheduling loop.
 *
 * Generates and mutates programs, runs them through the isolated executor,
 * keeps a corpus guided by the crash/hang oracle + novelty heuristic, and
 * survives kernel panics via the reboot-persistence layer.
 */
#include "xfuzz.h"
#include "rng.h"
#include "log.h"
#include "desc.h"
#include "generator.h"
#include "mutator.h"
#include "corpus.h"
#include "executor.h"
#include "coverage.h"
#include "crash.h"
#include "persist.h"
#include "repro.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <getopt.h>

xf_config_t g_cfg;

static volatile sig_atomic_t s_stop = 0;
static void on_sigint(int s) { (void)s; s_stop = 1; }

/* ----- stats ------------------------------------------------------------- */
typedef struct {
    uint64_t execs, crashes, timeouts, panics, corpus_adds, childsigs;
    uint64_t start_ms;
} xf_stats;

static void print_stats(const xf_stats *st, const xf_corpus *c) {
    uint64_t dt = xf_now_ms() - st->start_ms;
    double eps = dt ? (double)st->execs * 1000.0 / (double)dt : 0.0;
    XF_INFO("stats: execs=%llu (%.0f/s) corpus=%u faults=%llu hangs=%llu "
            "crashes=%llu PANICS=%llu",
            (unsigned long long)st->execs, eps, c->count,
            (unsigned long long)st->childsigs, (unsigned long long)st->timeouts,
            (unsigned long long)st->crashes, (unsigned long long)st->panics);
}

/* ----- defaults & CLI ---------------------------------------------------- */
static void set_defaults(void) {
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.workdir    = "./run";
    g_cfg.seed       = 0x1234;
    g_cfg.procs      = 1;
    g_cfg.timeout_ms = XF_DEFAULT_TIMEOUT_MS;
    g_cfg.enable_bsd = true;
    g_cfg.enable_mach= true;
    g_cfg.enable_iokit = true;
    g_cfg.safe_mode  = true;    /* conservative by default                  */
    g_cfg.dry_run    = false;
    g_cfg.max_execs  = 0;
    g_cfg.verbose    = false;
}

static void usage(const char *p) {
    fprintf(stderr,
      "xfuzz " XFUZZ_VERSION " — XNU kernel fuzzer (arm64)\n"
      "usage: %s [options]\n"
      "  --workdir DIR      root for corpus/crashes/state (default .)\n"
      "  --seed N           master PRNG seed\n"
      "  --procs N          parallel executor workers (default 1)\n"
      "  --timeout MS       per-program timeout (default %d)\n"
      "  --surfaces LIST    comma list of bsd,mach,iokit (default all)\n"
      "  --cov BACKEND      blind|kdebug (default blind)\n"
      "  --unsafe           allow DANGEROUS calls (still never reboot/exec)\n"
      "  --dry-run          build+mutate+serialize only, never touch kernel\n"
      "  --max-execs N      stop after N executions\n"
      "  --verbose          debug logging\n"
      "  -h, --help\n",
      p, XF_DEFAULT_TIMEOUT_MS);
}

static void parse_surfaces(const char *list) {
    g_cfg.enable_bsd = g_cfg.enable_mach = g_cfg.enable_iokit = false;
    char buf[128]; snprintf(buf, sizeof(buf), "%s", list);
    for (char *t = strtok(buf, ","); t; t = strtok(NULL, ",")) {
        if (!strcmp(t, "bsd"))   g_cfg.enable_bsd = true;
        else if (!strcmp(t, "mach"))  g_cfg.enable_mach = true;
        else if (!strcmp(t, "iokit")) g_cfg.enable_iokit = true;
    }
}

/* ----- one worker's fuzzing loop ----------------------------------------- */
static xf_cov_backend s_cov = XF_COV_BLIND;
static char           s_faults[1024];        /* dir for deduped fault samples */
static uint32_t       s_fault_samples = 0;
static uint32_t       s_hang_samples  = 0;

static void worker_loop(uint64_t seed, int worker_id) {
    xf_rng_t rng; xf_rng_seed(&rng, seed);

    /* Each worker owns a private corpus subdir to avoid filename clobbering
     * between workers, but also seeds from any top-level .prog files. */
    char wcorpus[1100];
    snprintf(wcorpus, sizeof(wcorpus), "%s/w%d", g_cfg.corpus_dir, worker_id);
    mkdir(wcorpus, 0755);

    xf_corpus corpus; xf_corpus_init(&corpus);
    xf_corpus_load(&corpus, g_cfg.corpus_dir);   /* shared seeds              */
    xf_corpus_load(&corpus, wcorpus);            /* own persisted corpus      */

    xf_stats st; memset(&st, 0, sizeof(st));
    st.start_ms = xf_now_ms();
    uint64_t counter = xf_persist_load_counter();

    XF_INFO("worker %d: entering fuzz loop (seed=0x%llx, corpus=%u)",
            worker_id, (unsigned long long)seed, corpus.count);

    xf_prog p;
    while (!s_stop) {
        /* Choose: mutate a corpus member or generate fresh. */
        const xf_prog *base = NULL;
        if (corpus.count && !xf_rng_oneof(&rng, 3))
            base = xf_corpus_pick(&corpus, &rng);
        if (base) {
            xf_prog_copy(&p, base);
            xf_mutate(&p, &rng);
            if (corpus.count > 1 && xf_rng_oneof(&rng, 4))
                xf_splice(&p, xf_corpus_pick(&corpus, &rng), &rng);
        } else {
            xf_generate(&p, &rng, 12);   /* bounded length keeps exec fast   */
        }

        xf_persist_mark_pending(&p, counter);

        xf_cov_start();
        xf_exec_result res;
        xf_execute(&p, g_cfg.timeout_ms, &res);
        uint64_t cov = xf_cov_stop();
        (void)cov;

        st.execs++; counter++;

        /* Novelty is computed once (marks the signature seen). It gates both
         * corpus retention and the deduplicated on-disk sampling below. */
        uint64_t sig = xf_prog_signature(&p, res.status, res.signo);
        bool novel = !xf_novelty_seen(sig);
        bool interesting = novel;

        switch (res.status) {
        case XF_EXEC_OK:
        case XF_EXEC_CHILDSIG:
            /* Userspace faults from bad args — NOT kernel bugs. The child
             * skipped the faulting calls and ran to completion. Keep a small
             * deduplicated sample for research; never flood. */
            st.childsigs += res.child_faults + (res.status == XF_EXEC_CHILDSIG);
            if ((res.child_faults || res.status == XF_EXEC_CHILDSIG) &&
                novel && s_fault_samples < 400) {
                char tag[80];
                snprintf(tag, sizeof(tag), "fault-n%u-w%d-%llu",
                         res.child_faults, worker_id, (unsigned long long)st.execs);
                xf_corpus_write_one(&p, s_faults, tag);
                s_fault_samples++;
            }
            break;
        case XF_EXEC_TIMEOUT:
            /* Possible kernel hang/deadlock (benign blocking is cut at 40ms
             * per call, so a full-program timeout is more meaningful). */
            st.timeouts++;
            interesting = true;
            if (novel && s_hang_samples < 400) {
                char tag[80];
                snprintf(tag, sizeof(tag), "hang-w%d-%llu", worker_id,
                         (unsigned long long)st.execs);
                xf_corpus_write_one(&p, g_cfg.crash_dir, tag);
                s_hang_samples++;
                XF_WARN("worker %d: possible hang after %ums (saved %s)",
                        worker_id, (unsigned)res.elapsed_ms, tag);
            }
            break;
        case XF_EXEC_CRASH:
            /* Uncaught signal — rare; worth capturing. */
            st.crashes++;
            interesting = true;
            {
                char tag[80];
                snprintf(tag, sizeof(tag), "crash-uncaught-sig%d-w%d-%llu",
                         res.signo, worker_id, (unsigned long long)st.execs);
                xf_corpus_write_one(&p, g_cfg.crash_dir, tag);
                XF_WARN("worker %d: UNCAUGHT signal %d (saved %s)",
                        worker_id, res.signo, tag);
            }
            break;
        default:
            break;
        }

        if (interesting && corpus.count < 2048) {
            xf_corpus_add(&corpus, &p);
            st.corpus_adds++;
        }
        xf_prog_free(&p);

        /* Periodic housekeeping. */
        if ((st.execs & 0x3FF) == 0) {   /* every 1024 execs */
            char summary[256];
            if (xf_crash_check(summary, sizeof(summary))) {
                st.panics++;
                XF_ERR("worker %d: %s", worker_id, summary);
            }
            xf_persist_store_counter(counter);
            print_stats(&st, &corpus);
        }
        if ((st.execs % 20000) == 0) xf_corpus_save(&corpus, wcorpus);

        if (g_cfg.max_execs && st.execs >= (uint64_t)g_cfg.max_execs) break;
    }

    xf_corpus_save(&corpus, wcorpus);
    xf_persist_store_counter(counter);
    print_stats(&st, &corpus);
    xf_corpus_free(&corpus);
    XF_INFO("worker %d: exiting after %llu execs", worker_id,
            (unsigned long long)st.execs);
}

/* ----- self-test: serialization round-trip is the backbone of corpus,
 * repro, and panic attribution — if it silently breaks, everything downstream
 * does too. Validate it over many generated programs. ---------------------- */
static int self_test(void) {
    xf_rng_t rng; xf_rng_seed(&rng, 0xA5A5A5A5);
    int fail = 0;
    static char a[1 << 20], b[1 << 20];
    for (int i = 0; i < 5000; i++) {
        xf_prog p; xf_generate(&p, &rng, 16);
        xf_prog_serialize(&p, a, sizeof(a));
        xf_prog q;
        if (!xf_prog_deserialize(&q, a)) { XF_ERR("selftest: parse failed @%d", i); fail++; xf_prog_free(&p); continue; }
        xf_prog_serialize(&q, b, sizeof(b));
        if (strcmp(a, b) != 0) {
            XF_ERR("selftest: round-trip mismatch @%d (ncalls %u vs %u)",
                   i, p.ncalls, q.ncalls);
            fail++;
        }
        /* signature must be stable across a copy */
        xf_prog c; xf_prog_copy(&c, &p);
        if (xf_prog_signature(&p, 0, 0) != xf_prog_signature(&c, 0, 0)) {
            XF_ERR("selftest: signature unstable @%d", i); fail++;
        }
        xf_prog_free(&p); xf_prog_free(&q); xf_prog_free(&c);
    }
    if (fail == 0) XF_INFO("selftest: PASS (5000 programs round-tripped)");
    else           XF_ERR("selftest: FAIL (%d errors)", fail);
    return fail ? 1 : 0;
}

/* ----- setup ------------------------------------------------------------- */
static char s_corpus[1024], s_crash[1024], s_state[1024], s_log[1024];
static char s_sandbox[1024];

static void setup_dirs(void) {
    mkdir(g_cfg.workdir, 0755);
    snprintf(s_corpus, sizeof(s_corpus), "%s/corpus", g_cfg.workdir);
    snprintf(s_crash,  sizeof(s_crash),  "%s/crashes", g_cfg.workdir);
    snprintf(s_state,  sizeof(s_state),  "%s/state", g_cfg.workdir);
    snprintf(s_log,    sizeof(s_log),    "%s/xfuzz.log", g_cfg.workdir);
    snprintf(s_faults, sizeof(s_faults), "%s/faults", g_cfg.workdir);
    snprintf(s_sandbox, sizeof(s_sandbox), "%s/sandbox", g_cfg.workdir);
    mkdir(s_corpus, 0755); mkdir(s_crash, 0755); mkdir(s_state, 0755);
    mkdir(s_faults, 0755); mkdir(s_sandbox, 0700);
    g_cfg.corpus_dir  = s_corpus;
    g_cfg.crash_dir   = s_crash;
    g_cfg.state_dir   = s_state;
    g_cfg.sandbox_dir = s_sandbox;
}

int main(int argc, char **argv) {
    set_defaults();
    const char *cov_name = "blind";
    const char *repro_path = NULL;
    const char *minimize_path = NULL;
    int repro_iters = 10;

    static struct option opts[] = {
        {"workdir",  required_argument, 0, 'w'},
        {"seed",     required_argument, 0, 's'},
        {"procs",    required_argument, 0, 'p'},
        {"timeout",  required_argument, 0, 't'},
        {"surfaces", required_argument, 0, 'S'},
        {"cov",      required_argument, 0, 'c'},
        {"unsafe",   no_argument,       0, 'u'},
        {"dry-run",  no_argument,       0, 'd'},
        {"max-execs",required_argument, 0, 'm'},
        {"repro",    required_argument, 0, 'R'},
        {"minimize", required_argument, 0, 'M'},
        {"iters",    required_argument, 0, 'I'},
        {"selftest", no_argument,       0, 'T'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int do_selftest = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, "w:s:p:t:S:c:udm:R:M:I:Tvh", opts, NULL)) != -1) {
        switch (ch) {
        case 'w': g_cfg.workdir = optarg; break;
        case 's': g_cfg.seed = strtoull(optarg, NULL, 0); break;
        case 'p': g_cfg.procs = atoi(optarg); break;
        case 't': g_cfg.timeout_ms = atoi(optarg); break;
        case 'S': parse_surfaces(optarg); break;
        case 'c': cov_name = optarg; break;
        case 'u': g_cfg.safe_mode = false; break;
        case 'd': g_cfg.dry_run = true; break;
        case 'm': g_cfg.max_execs = atol(optarg); break;
        case 'R': repro_path = optarg; break;
        case 'M': minimize_path = optarg; break;
        case 'I': repro_iters = atoi(optarg); break;
        case 'T': do_selftest = 1; break;
        case 'v': g_cfg.verbose = true; break;
        case 'h': default: usage(argv[0]); return ch == 'h' ? 0 : 1;
        }
    }

    setup_dirs();
    xf_log_init(s_log, g_cfg.verbose ? XF_LOG_DEBUG : XF_LOG_INFO);
    XF_INFO("xfuzz " XFUZZ_VERSION " starting: workdir=%s seed=0x%llx procs=%d "
            "safe=%d dry=%d surfaces=[%s%s%s]",
            g_cfg.workdir, (unsigned long long)g_cfg.seed, g_cfg.procs,
            g_cfg.safe_mode, g_cfg.dry_run,
            g_cfg.enable_bsd ? "bsd " : "", g_cfg.enable_mach ? "mach " : "",
            g_cfg.enable_iokit ? "iokit" : "");

    xf_desc_init(!g_cfg.dry_run && g_cfg.enable_iokit && !do_selftest);

    if (do_selftest) { int rc = self_test(); xf_log_flush(); return rc; }

    xf_executor_init();
    s_cov = xf_cov_init(!strcmp(cov_name, "kdebug") ? XF_COV_KDEBUG : XF_COV_BLIND);
    (void)s_cov;
    xf_persist_init();
    xf_crash_init();

    if (xf_persist_post_reboot_check())
        XF_ERR("recovered from a prior kernel panic — reproducer saved");

    /* One-shot replay / minimize modes. */
    if (repro_path)    { int rc = xf_repro_run(repro_path, repro_iters); xf_log_flush(); return rc; }
    if (minimize_path) { int rc = xf_minimize(minimize_path);            xf_log_flush(); return rc; }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    if (g_cfg.procs <= 1) {
        worker_loop(g_cfg.seed, 0);
    } else {
        /* Fork independent workers; each has its own RNG stream and shares the
         * on-disk corpus/crash dirs. A worker killed by jetsam/OOM is respawned
         * so the campaign keeps running indefinitely. */
        int nprocs = g_cfg.procs;
        pid_t *pids = calloc(nprocs, sizeof(pid_t));
        #define SPAWN_WORKER(slot) do {                                        \
            pid_t _p = fork();                                                 \
            if (_p == 0) {                                                     \
                worker_loop(g_cfg.seed + 0x9E3779B97F4A7C15ULL *               \
                            (uint64_t)((slot) + 1) + (uint64_t)restarts, slot);\
                _exit(0);                                                      \
            }                                                                  \
            pids[slot] = _p;                                                   \
        } while (0)
        uint64_t restarts = 0;
        for (int i = 0; i < nprocs; i++) SPAWN_WORKER(i);

        while (!s_stop) {
            int status;
            pid_t w = wait(&status);
            if (w < 0) { if (errno == EINTR) continue; break; }
            if (s_stop) break;
            int slot = -1;
            for (int i = 0; i < nprocs; i++) if (pids[i] == w) slot = i;
            if (slot < 0) continue;
            restarts++;
            XF_WARN("worker %d (pid %d) died — respawning (restart #%llu)",
                    slot, w, (unsigned long long)restarts);
            SPAWN_WORKER(slot);
        }

        /* Shutting down: ask workers to stop, then reap. */
        for (int i = 0; i < nprocs; i++) if (pids[i] > 0) kill(pids[i], SIGTERM);
        for (int i = 0; i < nprocs; i++) if (pids[i] > 0) waitpid(pids[i], NULL, 0);
        free(pids);
    }

    xf_log_flush();
    return 0;
}
