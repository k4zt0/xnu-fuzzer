/* crash.h — out-of-band kernel panic detection & attribution. */
#ifndef XF_CRASH_H
#define XF_CRASH_H

#include "xfuzz.h"

/* Snapshot the current panic-report state as a baseline. Call at startup. */
void xf_crash_init(void);

/* Scan for a NEW kernel panic since the last baseline. If found, copies the
 * panic report into the crash dir, advances the baseline, and returns true.
 * `panic_summary` (if non-NULL) receives a short one-line description. */
bool xf_crash_check(char *panic_summary, size_t cap);

/* Read the last panic string held in NVRAM (pre-reboot), if any. Returns
 * bytes written, 0 if none. */
size_t xf_crash_nvram_panic(char *buf, size_t cap);

#endif /* XF_CRASH_H */
