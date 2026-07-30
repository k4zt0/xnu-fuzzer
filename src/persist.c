#include "persist.h"
#include "crash.h"
#include "corpus.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static char s_pending_path[1024];
static char s_counter_path[1024];
static uint32_t s_fsync_every = 64;
static uint32_t s_since_fsync = 0;

void xf_persist_init(void) {
    mkdir(g_cfg.state_dir, 0755);
    snprintf(s_pending_path, sizeof(s_pending_path), "%s/pending.prog", g_cfg.state_dir);
    snprintf(s_counter_path, sizeof(s_counter_path), "%s/counter", g_cfg.state_dir);
}

void xf_persist_mark_pending(const xf_prog *p, uint64_t exec_index) {
    static char buf[1 << 20];
    size_t n = xf_prog_serialize(p, buf, sizeof(buf));

    /* Write atomically-ish: tmp then rename. */
    char tmp[1100];
    snprintf(tmp, sizeof(tmp), "%s.tmp", s_pending_path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    /* Prepend the exec index as a comment so post-reboot triage can log it. */
    char hdr[64];
    int hn = snprintf(hdr, sizeof(hdr), "# exec %llu\n", (unsigned long long)exec_index);
    ssize_t w1 = write(fd, hdr, (size_t)hn);
    ssize_t w2 = write(fd, buf, n);
    (void)w1; (void)w2;
    if (++s_since_fsync >= s_fsync_every) {
        fsync(fd);
        s_since_fsync = 0;
    }
    close(fd);
    rename(tmp, s_pending_path);
}

uint64_t xf_persist_load_counter(void) {
    FILE *f = fopen(s_counter_path, "r");
    if (!f) return 0;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1) v = 0;
    fclose(f);
    return v;
}

void xf_persist_store_counter(uint64_t v) {
    FILE *f = fopen(s_counter_path, "w");
    if (!f) return;
    fprintf(f, "%llu\n", (unsigned long long)v);
    fclose(f);
}

bool xf_persist_post_reboot_check(void) {
    /* Is there a pending program from before a possible reboot? */
    struct stat st;
    if (stat(s_pending_path, &st) != 0) return false;

    char summary[256] = {0};
    if (!xf_crash_check(summary, sizeof(summary))) {
        /* No new panic — the pending marker is just stale from clean shutdown
         * or an ongoing run. Leave it; the loop will overwrite it. */
        return false;
    }

    /* Attribute the panic to the pending program. */
    static char buf[1 << 20];
    FILE *f = fopen(s_pending_path, "r");
    if (!f) return true;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    xf_prog p;
    if (xf_prog_deserialize(&p, buf)) {
        char tag[64];
        snprintf(tag, sizeof(tag), "panic-repro-%ld", (long)st.st_mtime);
        xf_corpus_write_one(&p, g_cfg.crash_dir, tag);
        xf_prog_free(&p);
        XF_ERR("*** attributed panic to pending program, saved reproducer %s/%s.prog ***",
               g_cfg.crash_dir, tag);
    }

    /* Advance past the culprit so we don't reboot-loop on it. */
    char moved[1100];
    snprintf(moved, sizeof(moved), "%s.crashed", s_pending_path);
    rename(s_pending_path, moved);
    return true;
}
