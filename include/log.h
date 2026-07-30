/* log.h — leveled logging + crash-safe append logging. */
#ifndef XF_LOG_H
#define XF_LOG_H

#include <stdarg.h>

typedef enum {
    XF_LOG_ERROR = 0,
    XF_LOG_WARN  = 1,
    XF_LOG_INFO  = 2,
    XF_LOG_DEBUG = 3,
} xf_loglevel_t;

void xf_log_init(const char *logfile, xf_loglevel_t level);
void xf_log(xf_loglevel_t level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void xf_log_flush(void);

#define XF_ERR(...)  xf_log(XF_LOG_ERROR, __VA_ARGS__)
#define XF_WARN(...) xf_log(XF_LOG_WARN,  __VA_ARGS__)
#define XF_INFO(...) xf_log(XF_LOG_INFO,  __VA_ARGS__)
#define XF_DBG(...)  xf_log(XF_LOG_DEBUG, __VA_ARGS__)

#endif /* XF_LOG_H */
