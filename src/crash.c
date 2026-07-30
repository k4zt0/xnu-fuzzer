/*
 * crash.c — kernel panic oracle.
 *
 * A kernel panic reboots the machine, so this layer works across reboots:
 *   - baseline: newest Kernel-*.ips timestamp seen so far (persisted).
 *   - check:    any newer Kernel-*.ips (or fresh NVRAM panic string) means the
 *               last executed input took the kernel down.
 * DiagnosticReports is root-readable only; when run unprivileged we fall back
 * to `nvram` (readable) and `log show`.
 */
#include "crash.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

static const char *k_report_dirs[] = {
    "/Library/Logs/DiagnosticReports",
    "/Library/Logs/DiagnosticReports/Retired",
};

static time_t s_baseline_mtime = 0;

/* Newest mtime among Kernel-*.ips / *.panic across the report dirs. */
static time_t newest_panic(char *newest_name, size_t cap) {
    time_t newest = 0;
    for (size_t di = 0; di < XF_ARRAY_LEN(k_report_dirs); di++) {
        DIR *d = opendir(k_report_dirs[di]);
        if (!d) continue;
        struct dirent *de;
        while ((de = readdir(d))) {
            const char *nm = de->d_name;
            size_t len = strlen(nm);
            bool is_kernel = strncmp(nm, "Kernel-", 7) == 0;
            bool is_panic  = len > 6 && strcmp(nm + len - 6, ".panic") == 0;
            if (!is_kernel && !is_panic) continue;
            char path[1200];
            snprintf(path, sizeof(path), "%s/%s", k_report_dirs[di], nm);
            struct stat st;
            if (stat(path, &st) == 0 && st.st_mtime > newest) {
                newest = st.st_mtime;
                if (newest_name) snprintf(newest_name, cap, "%s", path);
            }
        }
        closedir(d);
    }
    return newest;
}

void xf_crash_init(void) {
    s_baseline_mtime = newest_panic(NULL, 0);
    XF_INFO("crash: panic baseline mtime = %ld", (long)s_baseline_mtime);
}

size_t xf_crash_nvram_panic(char *buf, size_t cap) {
    /* `nvram` is world-readable; the panic string lives under a few keys
     * depending on release. */
    static const char *keys[] = { "panicinfo", "aapl,panic-info", "aople-panic-info" };
    for (size_t i = 0; i < XF_ARRAY_LEN(keys); i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "/usr/sbin/nvram %s 2>/dev/null", keys[i]);
        FILE *pf = popen(cmd, "r");
        if (!pf) continue;
        size_t n = fread(buf, 1, cap - 1, pf);
        pclose(pf);
        if (n > (strlen(keys[i]) + 2)) { buf[n] = '\0'; return n; }
    }
    if (cap) buf[0] = '\0';
    return 0;
}

bool xf_crash_check(char *panic_summary, size_t cap) {
    char name[1200] = {0};
    time_t newest = newest_panic(name, sizeof(name));
    if (newest > s_baseline_mtime && name[0]) {
        s_baseline_mtime = newest;
        /* Copy the panic report into the crash dir for triage. */
        char dst[1300];
        snprintf(dst, sizeof(dst), "%s/panic-%ld.ips", g_cfg.crash_dir, (long)newest);
        char cmd[2700];
        snprintf(cmd, sizeof(cmd), "cp '%s' '%s' 2>/dev/null", name, dst);
        int rc = system(cmd);
        (void)rc;
        if (panic_summary) snprintf(panic_summary, cap, "kernel panic report: %s", name);
        XF_ERR("*** KERNEL PANIC detected: %s (copied to %s) ***", name, dst);
        return true;
    }
    /* Fallback: a fresh NVRAM panic string we haven't recorded. */
    char nv[4096];
    if (xf_crash_nvram_panic(nv, sizeof(nv))) {
        if (panic_summary) snprintf(panic_summary, cap, "nvram panic: %.120s", nv);
        return true;
    }
    return false;
}
