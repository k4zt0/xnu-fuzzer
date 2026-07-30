/*
 * coverage.h — pluggable coverage backend.
 *
 * Stock SIP-enabled XNU exposes no KCOV/edge coverage, so the default backend
 * is BLIND (crash/hang oracle only). A KDEBUG backend (root-gated, coarse) can
 * be plugged in to derive a weak per-execution signal from kernel trace
 * events. The interface is deliberately KCOV-shaped so a real edge-coverage
 * source (custom kernel / SIP-off) drops in without touching the engine.
 */
#ifndef XF_COVERAGE_H
#define XF_COVERAGE_H

#include "xfuzz.h"

typedef enum {
    XF_COV_BLIND  = 0,   /* no signal                                        */
    XF_COV_KDEBUG = 1,   /* kdebug trace-count signal (root, coarse)         */
} xf_cov_backend;

/* Initialize the coverage backend. Returns the backend actually active
 * (falls back to BLIND if the requested one is unavailable). */
xf_cov_backend xf_cov_init(xf_cov_backend want);

/* Bracket one execution. start() resets the per-exec signal; stop() returns
 * a signal hash summarizing what the kernel did (0 under BLIND). */
void     xf_cov_start(void);
uint64_t xf_cov_stop(void);

const char *xf_cov_name(xf_cov_backend b);

#endif /* XF_COVERAGE_H */
