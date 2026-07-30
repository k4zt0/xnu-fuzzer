/*
 * xfuzz.h — XNU Fuzzer common definitions.
 *
 * A coverage-guided (pluggable), generational syscall/Mach/IOKit fuzzer for
 * XNU on Apple Silicon, in the spirit of syzkaller / AFL / NTFUZZ but native
 * to macOS and structured around XNU's actual attack surfaces.
 */
#ifndef XFUZZ_H
#define XFUZZ_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#define XFUZZ_VERSION "0.1.0"

/* ----- Tunables ---------------------------------------------------------- */
#define XF_MAX_CALLS        64      /* max calls in a single program        */
#define XF_MAX_ARGS         8       /* max arguments per call               */
#define XF_MAX_RESOURCES    256     /* live resource slots per program      */
#define XF_BUF_POOL         (1u<<20)/* per-executor scratch buffer (1 MiB)  */
#define XF_DEFAULT_TIMEOUT_MS 2000  /* per-program wall clock budget        */

/* ----- Fuzzing surfaces -------------------------------------------------- */
typedef enum {
    XF_SURFACE_BSD    = 0,  /* BSD/unix syscalls via syscall()              */
    XF_SURFACE_MACH   = 1,  /* Mach traps                                    */
    XF_SURFACE_IOKIT  = 2,  /* IOConnectCallMethod external methods          */
    XF_SURFACE_COUNT
} xf_surface_t;

/* ----- Global runtime configuration -------------------------------------- */
typedef struct {
    const char *workdir;        /* root for corpus/crashes/state            */
    const char *corpus_dir;
    const char *crash_dir;
    const char *state_dir;

    uint64_t    seed;           /* master PRNG seed                          */
    int         procs;          /* parallel executor procs                  */
    int         timeout_ms;     /* per-program timeout                       */

    bool        enable_bsd;
    bool        enable_mach;
    bool        enable_iokit;

    /* Safety governor: when true, calls flagged XF_C_DANGEROUS are skipped
     * (reboot/shutdown/filesystem-destroying syscalls). Live kernel fuzzing
     * still panics — this only removes self-inflicted userspace footguns. */
    bool        safe_mode;

    /* Dry run: generate + serialize + mutate programs but never actually
     * issue the syscalls. Used to validate the engine without touching the
     * kernel. */
    bool        dry_run;

    long        max_execs;      /* stop after N executions (0 = unlimited)  */
    bool        verbose;
} xf_config_t;

extern xf_config_t g_cfg;

/* ----- Utility ----------------------------------------------------------- */
#define XF_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define XF_MIN(a,b) ((a) < (b) ? (a) : (b))
#define XF_MAX(a,b) ((a) > (b) ? (a) : (b))

/* Monotonic milliseconds since some fixed point. */
uint64_t xf_now_ms(void);

#endif /* XFUZZ_H */
