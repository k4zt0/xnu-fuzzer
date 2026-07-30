/*
 * desc.c — unified interface-description registry.
 *
 * Flattens every surface's static/dynamic descriptor table into one array
 * with stable global ids (the array index). The generator/mutator sample
 * from here; serialization stores the global id.
 */
#include "desc.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

/* Raw BSD layer built at init (defined in bsd_desc.c). */
xf_call_desc *xf_bsd_build_raw(uint32_t *count);

static const xf_call_desc **s_reg = NULL;
static uint32_t             s_count = 0;
static uint32_t             s_cap = 0;

/* Per-surface index ranges, for fast surface-filtered sampling. */
static uint32_t s_surf_lo[XF_SURFACE_COUNT];
static uint32_t s_surf_hi[XF_SURFACE_COUNT];   /* [lo, hi)                   */

/* Ids of "curated" (typed, resource-aware) descriptors — everything except
 * the raw syscall-number layer. Sampling is biased toward these so programs
 * build meaningful fd/port sequences instead of drowning in raw noise. */
static uint32_t *s_curated = NULL;
static uint32_t  s_ncurated = 0, s_curated_cap = 0;
static void curated_push(uint32_t id) {
    if (s_ncurated == s_curated_cap) {
        s_curated_cap = s_curated_cap ? s_curated_cap * 2 : 128;
        s_curated = realloc(s_curated, s_curated_cap * sizeof(*s_curated));
    }
    s_curated[s_ncurated++] = id;
}

static void reg_push(const xf_call_desc *d) {
    if (s_count == s_cap) {
        s_cap = s_cap ? s_cap * 2 : 1024;
        s_reg = realloc(s_reg, s_cap * sizeof(*s_reg));
    }
    s_reg[s_count++] = d;
}


void xf_desc_init(bool want_iokit) {
    for (int i = 0; i < XF_SURFACE_COUNT; i++) s_surf_lo[i] = s_surf_hi[i] = 0;

    uint32_t n;

    if (g_cfg.enable_bsd) {
        s_surf_lo[XF_SURFACE_BSD] = s_count;
        const xf_call_desc *bsd = xf_bsd_table(&n);
        for (uint32_t i = 0; i < n; i++) { curated_push(s_count); reg_push(&bsd[i]); }
        /* Raw layer covering every syscall number (not curated). */
        uint32_t rn;
        xf_call_desc *raw = xf_bsd_build_raw(&rn);
        for (uint32_t i = 0; i < rn; i++) reg_push(&raw[i]);
        s_surf_hi[XF_SURFACE_BSD] = s_count;
    }

    if (g_cfg.enable_mach) {
        const xf_call_desc *m = xf_mach_table(&n);
        s_surf_lo[XF_SURFACE_MACH] = s_count;
        for (uint32_t i = 0; i < n; i++) { curated_push(s_count); reg_push(&m[i]); }
        s_surf_hi[XF_SURFACE_MACH] = s_count;
    }

    if (g_cfg.enable_iokit && want_iokit) {
        xf_iokit_discover();
        const xf_call_desc *io = xf_iokit_table(&n);
        if (n) {
            s_surf_lo[XF_SURFACE_IOKIT] = s_count;
            for (uint32_t i = 0; i < n; i++) { curated_push(s_count); reg_push(&io[i]); }
            s_surf_hi[XF_SURFACE_IOKIT] = s_count;
        }
    }

    XF_INFO("registry: %u descriptors (BSD %u..%u, MACH %u..%u, IOKIT %u..%u)",
            s_count,
            s_surf_lo[XF_SURFACE_BSD], s_surf_hi[XF_SURFACE_BSD],
            s_surf_lo[XF_SURFACE_MACH], s_surf_hi[XF_SURFACE_MACH],
            s_surf_lo[XF_SURFACE_IOKIT], s_surf_hi[XF_SURFACE_IOKIT]);
}

uint32_t xf_desc_count(void) { return s_count; }

const xf_call_desc *xf_desc_by_id(uint32_t id) {
    return id < s_count ? s_reg[id] : NULL;
}

uint32_t xf_desc_id_of(const xf_call_desc *d) {
    for (uint32_t i = 0; i < s_count; i++) if (s_reg[i] == d) return i;
    return 0;
}

const xf_call_desc *xf_desc_random(xf_rng_t *r) {
    if (s_count == 0) return NULL;
    /* ~55% of the time draw from the curated pool (typed, resource-aware) so
     * sequences stay meaningful; otherwise draw from the full registry to keep
     * exercising the entire raw syscall range. */
    if (s_ncurated && xf_rng_below(r, 100) < 55)
        return s_reg[s_curated[xf_rng_below(r, s_ncurated)]];
    return s_reg[xf_rng_below(r, s_count)];
}

const xf_call_desc *xf_desc_random_surface(xf_rng_t *r, xf_surface_t s) {
    uint32_t lo = s_surf_lo[s], hi = s_surf_hi[s];
    if (hi <= lo) return NULL;
    return s_reg[lo + xf_rng_below(r, hi - lo)];
}

const xf_call_desc *xf_desc_random_producer(xf_rng_t *r, xf_reskind_t kind) {
    /* Reservoir-sample a descriptor whose return produces `kind`. */
    const xf_call_desc *pick = NULL;
    uint32_t seen = 0;
    for (uint32_t i = 0; i < s_count; i++) {
        if (s_reg[i]->produces == kind) {
            seen++;
            if (xf_rng_below(r, seen) == 0) pick = s_reg[i];
        }
    }
    return pick;
}
