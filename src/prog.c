#include "prog.h"
#include "desc.h"

#include <stdlib.h>
#include <string.h>

void xf_prog_init(xf_prog *p) {
    memset(p, 0, sizeof(*p));
}

void xf_prog_free(xf_prog *p) {
    for (uint32_t i = 0; i < p->ncalls; i++) {
        for (uint32_t a = 0; a < p->calls[i].nargs; a++) {
            free(p->calls[i].args[a].blob);
            p->calls[i].args[a].blob = NULL;
        }
    }
    p->ncalls = 0;
    p->nres = 0;
}

void xf_prog_copy(xf_prog *dst, const xf_prog *src) {
    memcpy(dst, src, sizeof(*dst));
    /* Deep-copy arg blobs so the two programs don't alias heap buffers. */
    for (uint32_t i = 0; i < dst->ncalls; i++) {
        for (uint32_t a = 0; a < dst->calls[i].nargs; a++) {
            xf_arg *arg = &dst->calls[i].args[a];
            if (arg->blob && arg->blob_len) {
                uint8_t *nb = malloc(arg->blob_len);
                memcpy(nb, arg->blob, arg->blob_len);
                arg->blob = nb;
            } else {
                arg->blob = NULL;
                arg->blob_len = 0;
            }
        }
    }
}

/* ----- Serialization ----------------------------------------------------- *
 * Text format, one call per line:
 *   <desc_id> <res_slot> <nargs> ; <type>:<val>:<bloblen>[:<hex>] ...
 * A leading "# xfuzz prog v1" header line documents the format. This is
 * deterministic and round-trips exactly, while staying greppable/diffable.
 */
static const char *k_hdr = "# xfuzz prog v1\n";

static size_t emit_hex(const uint8_t *b, uint32_t n, char *out, size_t cap) {
    static const char hx[] = "0123456789abcdef";
    size_t w = 0;
    for (uint32_t i = 0; i < n && w + 2 < cap; i++) {
        out[w++] = hx[b[i] >> 4];
        out[w++] = hx[b[i] & 0xF];
    }
    return w;
}

size_t xf_prog_serialize(const xf_prog *p, char *out, size_t cap) {
    size_t w = 0;
    int n = snprintf(out + w, cap - w, "%s", k_hdr);
    if (n > 0) w += (size_t)n;

    for (uint32_t i = 0; i < p->ncalls && w < cap; i++) {
        const xf_call *c = &p->calls[i];
        n = snprintf(out + w, cap - w, "%u %d %u ;",
                     c->desc_id, c->res_slot, c->nargs);
        if (n < 0) break;
        w += (size_t)n;
        for (uint32_t a = 0; a < c->nargs && w < cap; a++) {
            const xf_arg *arg = &c->args[a];
            n = snprintf(out + w, cap - w, " %u:%llu:%u",
                         (unsigned)arg->type,
                         (unsigned long long)arg->val, arg->blob_len);
            if (n < 0) break;
            w += (size_t)n;
            if (arg->blob && arg->blob_len && w + 1 < cap) {
                out[w++] = ':';
                w += emit_hex(arg->blob, arg->blob_len, out + w, cap - w);
            }
        }
        if (w < cap) out[w++] = '\n';
    }
    if (w < cap) out[w] = '\0'; else if (cap) out[cap - 1] = '\0';
    return w;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool xf_prog_deserialize(xf_prog *p, const char *text) {
    xf_prog_init(p);
    const char *line = text;
    if (strncmp(line, "# xfuzz", 7) == 0) {
        const char *nl = strchr(line, '\n');
        line = nl ? nl + 1 : line + strlen(line);
    }
    uint32_t maxres = 0;
    while (*line && p->ncalls < XF_MAX_CALLS) {
        const char *nl = strchr(line, '\n');
        if (!nl) nl = line + strlen(line);
        if (nl == line) { line = *nl ? nl + 1 : nl; continue; }

        xf_call *c = &p->calls[p->ncalls];
        memset(c, 0, sizeof(*c));

        unsigned desc_id = 0, nargs = 0;
        int res_slot = -1, consumed = 0;
        if (sscanf(line, "%u %d %u ;%n", &desc_id, &res_slot, &nargs, &consumed) < 3) {
            line = *nl ? nl + 1 : nl;
            continue;
        }
        c->desc_id  = desc_id;
        c->desc     = xf_desc_by_id(desc_id);
        c->res_slot = res_slot;
        c->nargs    = XF_MIN(nargs, XF_MAX_ARGS);
        if (res_slot >= 0 && (uint32_t)res_slot + 1 > maxres) maxres = res_slot + 1;

        const char *q = line + consumed;
        for (uint32_t a = 0; a < c->nargs && q < nl; a++) {
            while (q < nl && *q == ' ') q++;
            unsigned type = 0, blen = 0;
            unsigned long long val = 0;
            int cc = 0;
            if (sscanf(q, "%u:%llu:%u%n", &type, &val, &blen, &cc) < 3) break;
            q += cc;
            xf_arg *arg = &c->args[a];
            arg->type = (xf_argtype_t)type;
            arg->val  = val;
            arg->blob_len = blen;
            if (blen && q < nl && *q == ':') {
                q++;
                arg->blob = malloc(blen);
                for (uint32_t k = 0; k < blen && q + 1 < nl; k++) {
                    int hi = hexval(q[0]), lo = hexval(q[1]);
                    arg->blob[k] = (uint8_t)((hi < 0 ? 0 : hi) << 4 |
                                             (lo < 0 ? 0 : lo));
                    q += 2;
                }
            }
        }
        p->ncalls++;
        line = *nl ? nl + 1 : nl;
    }
    p->nres = XF_MIN(maxres, XF_MAX_RESOURCES);
    return p->ncalls > 0;
}
