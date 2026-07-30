#include "repro.h"
#include "prog.h"
#include "executor.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool load_prog(const char *path, xf_prog *p) {
    FILE *f = fopen(path, "r");
    if (!f) { XF_ERR("repro: cannot open %s", path); return false; }
    static char buf[1 << 20];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    if (!xf_prog_deserialize(p, buf)) {
        XF_ERR("repro: cannot parse %s", path);
        return false;
    }
    return true;
}

static const char *status_name(xf_exec_status s) {
    switch (s) {
        case XF_EXEC_OK:       return "ok";
        case XF_EXEC_CHILDSIG: return "childsig";
        case XF_EXEC_CRASH:    return "crash";
        case XF_EXEC_TIMEOUT:  return "hang/timeout";
        default:               return "error";
    }
}

int xf_repro_run(const char *path, int iters) {
    xf_prog p;
    if (!load_prog(path, &p)) return 1;

    static char buf[1 << 20];
    xf_prog_serialize(&p, buf, sizeof(buf));
    printf("=== program %s (%u calls) ===\n%s\n", path, p.ncalls, buf);

    int counts[5] = {0};
    for (int i = 0; i < iters; i++) {
        xf_exec_result res;
        xf_execute(&p, g_cfg.timeout_ms, &res);
        counts[res.status]++;
        XF_INFO("repro run %d/%d: %s (faults=%u, %llums)",
                i + 1, iters, status_name(res.status), res.child_faults,
                (unsigned long long)res.elapsed_ms);
    }
    printf("=== summary: ok=%d childsig=%d crash=%d hang=%d error=%d ===\n",
           counts[XF_EXEC_OK], counts[XF_EXEC_CHILDSIG], counts[XF_EXEC_CRASH],
           counts[XF_EXEC_TIMEOUT], counts[XF_EXEC_ERROR]);
    xf_prog_free(&p);
    return 0;
}

/* True if the program reproduces a hang within `trials` attempts. */
static bool causes_hang(const xf_prog *p, int trials) {
    for (int i = 0; i < trials; i++) {
        xf_exec_result res;
        xf_execute(p, g_cfg.timeout_ms, &res);
        if (res.status == XF_EXEC_TIMEOUT) return true;
    }
    return false;
}

int xf_minimize(const char *path) {
    xf_prog p;
    if (!load_prog(path, &p)) return 1;

    if (!causes_hang(&p, 5)) {
        XF_WARN("minimize: %s does not reproduce a hang (nothing to minimize)", path);
        xf_prog_free(&p);
        return 1;
    }
    XF_INFO("minimize: starting from %u calls", p.ncalls);

    /* Pass 1: greedily drop calls from the end while the hang survives. */
    bool changed = true;
    while (changed) {
        changed = false;
        for (int i = (int)p.ncalls - 1; i >= 0; i--) {
            xf_prog trial;
            xf_prog_copy(&trial, &p);
            /* remove call i */
            for (uint32_t a = 0; a < trial.calls[i].nargs; a++)
                free(trial.calls[i].args[a].blob);
            memmove(&trial.calls[i], &trial.calls[i + 1],
                    (trial.ncalls - i - 1) * sizeof(xf_call));
            trial.ncalls--;

            if (trial.ncalls && causes_hang(&trial, 3)) {
                xf_prog_free(&p);
                p = trial;              /* keep the smaller program */
                changed = true;
                XF_INFO("minimize: dropped call %d -> %u calls", i, p.ncalls);
            } else {
                xf_prog_free(&trial);
            }
        }
    }

    /* Pass 2: shrink argument blobs to empty where the hang survives. */
    for (uint32_t i = 0; i < p.ncalls; i++) {
        for (uint32_t a = 0; a < p.calls[i].nargs; a++) {
            xf_arg *arg = &p.calls[i].args[a];
            if (!arg->blob || !arg->blob_len) continue;
            uint8_t *saved = arg->blob; uint32_t savedlen = arg->blob_len;
            arg->blob = NULL; arg->blob_len = 0;
            if (causes_hang(&p, 3)) {
                free(saved);            /* empty works — keep it empty */
            } else {
                arg->blob = saved; arg->blob_len = savedlen;
            }
        }
    }

    char out[1200];
    snprintf(out, sizeof(out), "%s.min", path);
    static char buf[1 << 20];
    size_t n = xf_prog_serialize(&p, buf, sizeof(buf));
    FILE *f = fopen(out, "w");
    if (f) { fwrite(buf, 1, n, f); fclose(f); }
    XF_INFO("minimize: wrote %s (%u calls)", out, p.ncalls);
    printf("%s\n", buf);
    xf_prog_free(&p);
    return 0;
}
