#include "corpus.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

void xf_corpus_init(xf_corpus *c) { memset(c, 0, sizeof(*c)); }

void xf_corpus_free(xf_corpus *c) {
    for (uint32_t i = 0; i < c->count; i++) xf_prog_free(&c->items[i]);
    free(c->items);
    memset(c, 0, sizeof(*c));
}

void xf_corpus_add(xf_corpus *c, const xf_prog *p) {
    if (c->count == c->cap) {
        c->cap = c->cap ? c->cap * 2 : 256;
        c->items = realloc(c->items, c->cap * sizeof(*c->items));
    }
    xf_prog_copy(&c->items[c->count], p);
    c->count++;
}

const xf_prog *xf_corpus_pick(const xf_corpus *c, xf_rng_t *r) {
    if (c->count == 0) return NULL;
    return &c->items[xf_rng_below(r, c->count)];
}

void xf_corpus_write_one(const xf_prog *p, const char *dir, const char *tag) {
    static char buf[1 << 20];
    size_t n = xf_prog_serialize(p, buf, sizeof(buf));
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s.prog", dir, tag);
    FILE *f = fopen(path, "w");
    if (!f) { XF_WARN("corpus: cannot write %s", path); return; }
    fwrite(buf, 1, n, f);
    fclose(f);
}

void xf_corpus_save(const xf_corpus *c, const char *dir) {
    mkdir(dir, 0755);
    for (uint32_t i = 0; i < c->count; i++) {
        char tag[32];
        snprintf(tag, sizeof(tag), "c%06u", i);
        xf_corpus_write_one(&c->items[i], dir, tag);
    }
    XF_INFO("corpus: saved %u programs to %s", c->count, dir);
}

uint32_t xf_corpus_load(xf_corpus *c, const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *de;
    uint32_t loaded = 0;
    static char buf[1 << 20];
    while ((de = readdir(d))) {
        size_t len = strlen(de->d_name);
        if (len < 6 || strcmp(de->d_name + len - 5, ".prog") != 0) continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        xf_prog p;
        if (xf_prog_deserialize(&p, buf)) {
            xf_corpus_add(c, &p);
            xf_prog_free(&p);
            loaded++;
        }
    }
    closedir(d);
    if (loaded) XF_INFO("corpus: loaded %u programs from %s", loaded, dir);
    return loaded;
}

/* ----- novelty oracle ---------------------------------------------------- */
#define NOVELTY_BITS 20
#define NOVELTY_SIZE (1u << NOVELTY_BITS)
static uint8_t s_seen[NOVELTY_SIZE / 8];

static uint64_t mix64(uint64_t x) {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33; return x;
}

uint64_t xf_prog_signature(const xf_prog *p, int status, int signo) {
    /* Coarse, order-independent signature: the *set* of distinct descriptors
     * exercised (folded into a 256-bit sketch) plus the observed outcome.
     * Order/count are deliberately ignored so trivially-different programs
     * collapse to the same signature and the corpus stays bounded. */
    uint64_t sketch[4] = {0};
    for (uint32_t i = 0; i < p->ncalls; i++) {
        uint64_t b = mix64(p->calls[i].desc_id + 0x100);
        sketch[(b >> 6) & 3] |= 1ull << (b & 63);
    }
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < 4; i++) h = mix64(h ^ sketch[i]);
    h = mix64(h ^ ((uint64_t)status << 8 | (uint64_t)(unsigned)signo));
    return h;
}

bool xf_novelty_seen(uint64_t sig) {
    uint32_t idx = (uint32_t)(mix64(sig) & (NOVELTY_SIZE - 1));
    uint32_t byte = idx >> 3, bit = idx & 7;
    bool seen = (s_seen[byte] >> bit) & 1;
    s_seen[byte] |= (uint8_t)(1u << bit);
    return seen;
}
