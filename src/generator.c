#include "generator.h"
#include "desc.h"

#include <stdlib.h>
#include <string.h>

/* Allocate a random inline blob of length in [min,max]. */
static void make_blob(xf_arg *arg, uint32_t min, uint32_t max, xf_rng_t *r) {
    if (max == 0) { arg->blob = NULL; arg->blob_len = 0; return; }
    if (max > 4096) max = 4096;
    uint32_t len = min + (uint32_t)xf_rng_below(r, (max - min) + 1);
    arg->blob = malloc(len ? len : 1);
    arg->blob_len = len;
    /* Fill with a mix of interesting bytes: mostly structured (words from the
     * interesting-value pool) with occasional pure randomness. */
    for (uint32_t i = 0; i + 8 <= len; i += 8) {
        uint64_t w = xf_rng_oneof(r, 3) ? xf_rng_next(r) : xf_rng_intesting(r);
        memcpy(arg->blob + i, &w, 8);
    }
    for (uint32_t i = (len / 8) * 8; i < len; i++)
        arg->blob[i] = (uint8_t)xf_rng_next(r);
}

void xf_gen_arg(xf_arg *arg, const xf_arg_desc *ad, xf_rng_t *r) {
    arg->type = ad->type;
    arg->blob = NULL;
    arg->blob_len = 0;
    arg->val = 0;

    switch (ad->type) {
    case XF_ARG_CONST:
        arg->val = ad->const_val;
        break;
    case XF_ARG_INT:
        arg->val = xf_rng_oneof(r, 2) ? xf_rng_intesting(r) : xf_rng_next(r);
        break;
    case XF_ARG_FLAGS: {
        uint64_t v = 0;
        if (ad->flag_count) {
            uint32_t k = (uint32_t)xf_rng_below(r, ad->flag_count + 1);
            for (uint32_t i = 0; i < k; i++)
                v |= ad->flags[xf_rng_below(r, ad->flag_count)];
        }
        if (xf_rng_oneof(r, 8)) v |= xf_rng_intesting(r); /* out-of-range bits */
        arg->val = v;
        break;
    }
    case XF_ARG_LEN:
        /* Filled in later by the executor from the referenced buffer; seed a
         * plausible value here so mutation has something to work with. */
        arg->val = xf_rng_oneof(r, 2) ? 0 : xf_rng_intesting(r);
        break;
    case XF_ARG_RESOURCE:
        /* Resolved by the caller against the resource pool; -1 default means
         * "no resource" so the executor passes an invalid handle. */
        arg->val = (uint64_t)-1;
        break;
    case XF_ARG_STRING: {
        uint32_t max = ad->buf_max ? ad->buf_max : 32;
        uint32_t len = 1 + (uint32_t)xf_rng_below(r, max);
        arg->blob = malloc(len + 1);
        for (uint32_t i = 0; i < len; i++) {
            /* Bias toward path-ish characters and existing device nodes. */
            static const char cs[] = "/tmp.abcdefghijklmnopqrstuvwxyz0123456789_-";
            arg->blob[i] = cs[xf_rng_below(r, sizeof(cs) - 1)];
        }
        arg->blob[len] = '\0';
        arg->blob_len = len + 1;
        break;
    }
    case XF_ARG_PTR:
    case XF_ARG_BUFFER:
        make_blob(arg, ad->buf_min, ad->buf_max, r);
        break;
    default:
        arg->val = xf_rng_next(r);
    }
}

/* Find or create a resource slot of the given kind. Returns slot index or -1. */
static int obtain_resource(xf_prog *p, xf_rng_t *r, xf_reskind_t kind) {
    /* Collect existing slots of this kind. */
    int candidates[XF_MAX_RESOURCES];
    uint32_t n = 0;
    for (uint32_t i = 0; i < p->nres && n < XF_MAX_RESOURCES; i++)
        if (p->res_kind[i] == kind) candidates[n++] = (int)i;

    /* Reuse an existing resource most of the time. */
    if (n && !xf_rng_oneof(r, 4))
        return candidates[xf_rng_below(r, n)];

    /* Otherwise try to insert a producer, if the program has room. */
    if (p->ncalls + 1 < XF_MAX_CALLS && p->nres < XF_MAX_RESOURCES) {
        const xf_call_desc *prod = xf_desc_random_producer(r, kind);
        if (prod) {
            xf_call *c = &p->calls[p->ncalls];
            memset(c, 0, sizeof(*c));
            c->desc = prod;
            c->desc_id = xf_desc_id_of(prod);
            c->nargs = prod->nargs;
            for (uint32_t a = 0; a < prod->nargs; a++)
                xf_gen_arg(&c->args[a], &prod->args[a], r);
            int slot = (int)p->nres++;
            p->res_kind[slot] = kind;
            c->res_slot = slot;
            p->ncalls++;
            return slot;
        }
    }
    if (n) return candidates[xf_rng_below(r, n)];
    return -1;   /* executor will pass an invalid handle */
}

int xf_gen_append_call(xf_prog *p, xf_rng_t *r) {
    if (p->ncalls >= XF_MAX_CALLS) return -1;

    const xf_call_desc *d = xf_desc_random(r);
    if (!d) return -1;

    /* Respect safety governor. */
    if (g_cfg.safe_mode && (d->flags & XF_C_DANGEROUS)) {
        /* pick again a few times, then bail out for this round */
        for (int t = 0; t < 8 && (d->flags & XF_C_DANGEROUS); t++)
            d = xf_desc_random(r);
        if (d->flags & XF_C_DANGEROUS) return -1;
    }

    xf_call *c = &p->calls[p->ncalls];
    memset(c, 0, sizeof(*c));
    c->desc = d;
    c->desc_id = xf_desc_id_of(d);
    c->nargs = d->nargs;
    c->res_slot = -1;

    for (uint32_t a = 0; a < d->nargs; a++) {
        const xf_arg_desc *ad = &d->args[a];
        if (ad->type == XF_ARG_RESOURCE) {
            int slot = obtain_resource(p, r, ad->res_kind);
            /* obtain_resource may have appended a producer, shifting our call
             * slot; re-fetch the current call pointer. */
            c = &p->calls[p->ncalls];
            xf_gen_arg(&c->args[a], ad, r);
            c->args[a].val = (uint64_t)slot;   /* slot index, resolved at exec */
        } else {
            xf_gen_arg(&c->args[a], ad, r);
        }
    }

    if (d->produces != XF_RES_NONE && p->nres < XF_MAX_RESOURCES) {
        int slot = (int)p->nres++;
        p->res_kind[slot] = d->produces;
        c->res_slot = slot;
    }

    int idx = (int)p->ncalls;
    p->ncalls++;
    return idx;
}

void xf_generate(xf_prog *p, xf_rng_t *r, uint32_t max_calls) {
    xf_prog_init(p);
    if (max_calls == 0 || max_calls > XF_MAX_CALLS) max_calls = XF_MAX_CALLS;
    uint32_t target = 1 + (uint32_t)xf_rng_below(r, max_calls);
    while (p->ncalls < target) {
        if (xf_gen_append_call(p, r) < 0) break;
    }
}
