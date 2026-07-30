/* repro.h — replay and minimize saved programs. */
#ifndef XF_REPRO_H
#define XF_REPRO_H

/* Replay a saved .prog `iters` times against the kernel, printing the outcome
 * distribution. Returns 0 on success. */
int xf_repro_run(const char *path, int iters);

/* Delta-debug a hanging program down to a minimal reproducer, writing
 * <path>.min. Panics can't be minimized on a single live machine (each trial
 * reboots), so this targets hangs/anomalies. Returns 0 on success. */
int xf_minimize(const char *path);

#endif /* XF_REPRO_H */
