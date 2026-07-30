/* executor.h — run a program against the kernel in an isolated child. */
#ifndef XF_EXECUTOR_H
#define XF_EXECUTOR_H

#include "prog.h"

typedef enum {
    XF_EXEC_OK = 0,      /* child ran all calls and exited cleanly           */
    XF_EXEC_CHILDSIG,    /* child took a (caught) fatal signal — userspace   */
                         /* fault from bad args; benign telemetry, not a     */
                         /* kernel bug. signo carries the signal.            */
    XF_EXEC_CRASH,       /* child killed by an UNcaught signal (rare)        */
    XF_EXEC_TIMEOUT,     /* child exceeded the wall-clock budget (hang)      */
    XF_EXEC_ERROR,       /* fork/setup failure                               */
} xf_exec_status;

typedef struct {
    xf_exec_status status;
    int            signo;        /* signal that killed the child, if any     */
    uint32_t       calls_run;    /* calls the child reported issuing         */
    uint32_t       child_faults; /* # calls that faulted (benign, skipped)   */
    uint64_t       elapsed_ms;
} xf_exec_result;

/* Execute p in a forked, time-boxed child. Never issues XF_C_DANGEROUS calls.
 * A kernel panic during execution reboots the host — that is detected out of
 * band by the crash monitor, not here. */
void xf_execute(const xf_prog *p, int timeout_ms, xf_exec_result *out);

/* One-time executor setup (installs the child-side signal reporting). */
void xf_executor_init(void);

#endif /* XF_EXECUTOR_H */
