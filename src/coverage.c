/*
 * coverage.c — coverage backends.
 *
 * BLIND: no-op. The only feedback is the crash/hang oracle + the novelty
 *        heuristic in corpus.c.
 * KDEBUG: best-effort coarse signal via the KERN_KDEBUG sysctl MIB. Requires
 *        root and yields event counts (not edges); used only as a tie-break.
 *        If setup fails (unprivileged / disabled) it transparently degrades to
 *        BLIND.
 */
#include "coverage.h"
#include "log.h"

#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

/* kdebug control constants/struct are behind __APPLE_API_PRIVATE in the SDK;
 * define the minimal subset we need locally so the build never depends on
 * private headers. Values are stable in XNU's bsd/sys/kdebug.h. */
#ifndef KERN_KDEBUG
#define KERN_KDEBUG   68
#endif
#define XF_KDGETBUF   4
typedef struct {
    int   nkdbufs;
    int   nkdthreads;
    int   nolog;
    unsigned int flags;
    int   bufid;
} xf_kbufinfo;

static xf_cov_backend s_backend = XF_COV_BLIND;

const char *xf_cov_name(xf_cov_backend b) {
    switch (b) {
        case XF_COV_KDEBUG: return "kdebug";
        default:            return "blind";
    }
}

/* --- kdebug backend ------------------------------------------------------ */
/* KERN_KDEBUG control via sysctl(CTL_KERN, KERN_KDEBUG, ...). */
static bool kdebug_available(void) {
    if (geteuid() != 0) return false;   /* needs root */
    int mib[3] = { CTL_KERN, KERN_KDEBUG, XF_KDGETBUF };
    xf_kbufinfo info;
    size_t len = sizeof(info);
    if (sysctl(mib, 3, &info, &len, NULL, 0) != 0) return false;
    return true;
}

static uint64_t kdebug_event_count(void) {
    int mib[3] = { CTL_KERN, KERN_KDEBUG, XF_KDGETBUF };
    xf_kbufinfo info;
    size_t len = sizeof(info);
    if (sysctl(mib, 3, &info, &len, NULL, 0) != 0) return 0;
    return (uint64_t)info.nkdbufs;
}

xf_cov_backend xf_cov_init(xf_cov_backend want) {
    if (want == XF_COV_KDEBUG && kdebug_available()) {
        s_backend = XF_COV_KDEBUG;
    } else {
        if (want == XF_COV_KDEBUG)
            XF_WARN("coverage: kdebug unavailable (need root); using blind");
        s_backend = XF_COV_BLIND;
    }
    XF_INFO("coverage backend: %s", xf_cov_name(s_backend));
    return s_backend;
}

static uint64_t s_start_count = 0;

void xf_cov_start(void) {
    if (s_backend == XF_COV_KDEBUG) s_start_count = kdebug_event_count();
}

uint64_t xf_cov_stop(void) {
    if (s_backend == XF_COV_KDEBUG) {
        uint64_t now = kdebug_event_count();
        return now - s_start_count;
    }
    return 0;
}
