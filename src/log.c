#include "log.h"
#include "xfuzz.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <mach/mach_time.h>

static FILE          *s_logf    = NULL;
static xf_loglevel_t  s_level   = XF_LOG_INFO;

static const char *level_tag(xf_loglevel_t l) {
    switch (l) {
        case XF_LOG_ERROR: return "ERR";
        case XF_LOG_WARN:  return "WRN";
        case XF_LOG_INFO:  return "INF";
        case XF_LOG_DEBUG: return "DBG";
        default:           return "???";
    }
}

void xf_log_init(const char *logfile, xf_loglevel_t level) {
    s_level = level;
    if (logfile) {
        s_logf = fopen(logfile, "a");
        if (!s_logf) {
            fprintf(stderr, "[xfuzz] cannot open log file %s\n", logfile);
        }
    }
}

void xf_log(xf_loglevel_t level, const char *fmt, ...) {
    if (level > s_level) return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    char ts[32];
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03d",
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));

    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Terminal (stderr) always gets it; ERR/WARN are highlighted. */
    fprintf(stderr, "[%s %s] %s\n", ts, level_tag(level), msg);
    if (s_logf) {
        fprintf(s_logf, "[%s %s] %s\n", ts, level_tag(level), msg);
        /* Flush aggressively — a kernel panic can kill us at any moment and
         * we want the last lines on disk for post-mortem triage. */
        fflush(s_logf);
    }
}

void xf_log_flush(void) {
    fflush(stderr);
    if (s_logf) fflush(s_logf);
}

/* ----- time util (declared in xfuzz.h) ----------------------------------- */
uint64_t xf_now_ms(void) {
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) mach_timebase_info(&tb);
    uint64_t t = mach_absolute_time();
    /* nanoseconds = t * numer / denom  ->  ms */
    return (t * tb.numer / tb.denom) / 1000000ULL;
}
