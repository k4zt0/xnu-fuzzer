#include "mutator.h"
#include "generator.h"

#include <stdlib.h>
#include <string.h>

/* ----- blob-level mutations ---------------------------------------------- */
static void mutate_blob(xf_arg *arg, xf_rng_t *r) {
    if (!arg->blob || arg->blob_len == 0) {
        /* Grow an empty buffer occasionally. */
        if (xf_rng_oneof(r, 2)) {
            uint32_t len = 1 + (uint32_t)xf_rng_below(r, 64);
            arg->blob = malloc(len);
            for (uint32_t i = 0; i < len; i++) arg->blob[i] = (uint8_t)xf_rng_next(r);
            arg->blob_len = len;
        }
        return;
    }
    switch (xf_rng_below(r, 6)) {
    case 0: /* bit flip */
        arg->blob[xf_rng_below(r, arg->blob_len)] ^= 1u << xf_rng_below(r, 8);
        break;
    case 1: /* byte set to interesting value */
        arg->blob[xf_rng_below(r, arg->blob_len)] = (uint8_t)xf_rng_intesting(r);
        break;
    case 2: { /* overwrite an aligned word with an interesting value */
        if (arg->blob_len >= 8) {
            uint32_t off = (uint32_t)xf_rng_below(r, arg->blob_len - 7);
            uint64_t w = xf_rng_intesting(r);
            memcpy(arg->blob + off, &w, 8);
        }
        break;
    }
    case 3: { /* grow */
        uint32_t add = 1 + (uint32_t)xf_rng_below(r, 64);
        uint32_t nl = arg->blob_len + add;
        if (nl <= 8192) {
            arg->blob = realloc(arg->blob, nl);
            for (uint32_t i = arg->blob_len; i < nl; i++)
                arg->blob[i] = (uint8_t)xf_rng_next(r);
            arg->blob_len = nl;
        }
        break;
    }
    case 4: { /* shrink */
        if (arg->blob_len > 1)
            arg->blob_len -= 1 + (uint32_t)xf_rng_below(r, arg->blob_len - 1);
        break;
    }
    default: { /* random byte */
        arg->blob[xf_rng_below(r, arg->blob_len)] = (uint8_t)xf_rng_next(r);
        break;
    }
    }
}

/* ----- value-level mutations --------------------------------------------- */
static void mutate_val(xf_arg *arg, xf_rng_t *r) {
    switch (xf_rng_below(r, 5)) {
    case 0: arg->val = xf_rng_intesting(r); break;
    case 1: arg->val ^= 1ull << xf_rng_below(r, 64); break;
    case 2: arg->val += (uint64_t)((int64_t)xf_rng_below(r, 17) - 8); break;
    case 3: arg->val = (uint64_t)-(int64_t)arg->val; break;
    default: arg->val = xf_rng_next(r); break;
    }
}

static void mutate_one_arg(xf_call *c, xf_rng_t *r) {
    if (c->nargs == 0) return;
    uint32_t ai = (uint32_t)xf_rng_below(r, c->nargs);
    xf_arg *arg = &c->args[ai];
    switch (arg->type) {
    case XF_ARG_PTR:
    case XF_ARG_BUFFER:
    case XF_ARG_STRING:
        mutate_blob(arg, r);
        break;
    case XF_ARG_RESOURCE:
        /* occasionally corrupt the resource handle to hit error paths */
        if (xf_rng_oneof(r, 3)) arg->val = xf_rng_intesting(r);
        break;
    case XF_ARG_CONST:
        /* leave consts alone most of the time */
        if (xf_rng_oneof(r, 8)) mutate_val(arg, r);
        break;
    default:
        mutate_val(arg, r);
        break;
    }
}

static void remove_call(xf_prog *p, uint32_t idx) {
    for (uint32_t a = 0; a < p->calls[idx].nargs; a++)
        free(p->calls[idx].args[a].blob);
    memmove(&p->calls[idx], &p->calls[idx + 1],
            (p->ncalls - idx - 1) * sizeof(xf_call));
    p->ncalls--;
}

void xf_mutate(xf_prog *p, xf_rng_t *r) {
    uint32_t rounds = 1 + (uint32_t)xf_rng_below(r, 5);
    for (uint32_t i = 0; i < rounds; i++) {
        uint32_t op = (uint32_t)xf_rng_below(r, 10);
        if (op < 6) {                     /* 60%: tweak an argument          */
            if (p->ncalls)
                mutate_one_arg(&p->calls[xf_rng_below(r, p->ncalls)], r);
        } else if (op < 8) {              /* 20%: append a call              */
            xf_gen_append_call(p, r);
        } else if (op == 8) {             /* 10%: remove a call              */
            if (p->ncalls > 1)
                remove_call(p, (uint32_t)xf_rng_below(r, p->ncalls));
        } else {                          /* 10%: duplicate a call           */
            if (p->ncalls && p->ncalls < XF_MAX_CALLS) {
                uint32_t src = (uint32_t)xf_rng_below(r, p->ncalls);
                xf_call *s = &p->calls[src];
                xf_call *d = &p->calls[p->ncalls];
                memcpy(d, s, sizeof(*d));
                for (uint32_t a = 0; a < d->nargs; a++) {
                    if (d->args[a].blob && d->args[a].blob_len) {
                        uint8_t *nb = malloc(d->args[a].blob_len);
                        memcpy(nb, s->args[a].blob, d->args[a].blob_len);
                        d->args[a].blob = nb;
                    }
                }
                p->ncalls++;
            }
        }
    }
}

void xf_splice(xf_prog *p, const xf_prog *donor, xf_rng_t *r) {
    if (donor->ncalls == 0) return;
    uint32_t start = (uint32_t)xf_rng_below(r, donor->ncalls);
    for (uint32_t i = start; i < donor->ncalls && p->ncalls < XF_MAX_CALLS; i++) {
        xf_call *d = &p->calls[p->ncalls];
        memcpy(d, &donor->calls[i], sizeof(*d));
        for (uint32_t a = 0; a < d->nargs; a++) {
            if (d->args[a].blob && d->args[a].blob_len) {
                uint8_t *nb = malloc(d->args[a].blob_len);
                memcpy(nb, donor->calls[i].args[a].blob, d->args[a].blob_len);
                d->args[a].blob = nb;
            }
        }
        /* Remap donor resource slots into our pool conservatively. */
        if (d->res_slot >= 0 && p->nres < XF_MAX_RESOURCES) {
            p->res_kind[p->nres] = donor->res_kind[d->res_slot];
            d->res_slot = (int)p->nres++;
        }
        p->ncalls++;
    }
}
