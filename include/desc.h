/*
 * desc.h — the unified interface-description registry.
 *
 * At startup every surface (BSD, Mach, IOKit) registers its static
 * xf_call_desc table here. Each call gets a stable global id (its index in
 * the flattened registry) used for (de)serialization. The generator/mutator
 * pull random descriptors from this registry.
 */
#ifndef XF_DESC_H
#define XF_DESC_H

#include "prog.h"

/* Build the registry. IOKit discovery (probing which user clients open) is
 * done lazily/optionally; pass want_iokit=false for dry runs. */
void                 xf_desc_init(bool want_iokit);

uint32_t             xf_desc_count(void);
const xf_call_desc  *xf_desc_by_id(uint32_t id);
uint32_t             xf_desc_id_of(const xf_call_desc *d);

/* Pick a random descriptor, optionally constrained to one surface. Returns
 * NULL if no descriptor matches (e.g. surface disabled). */
const xf_call_desc  *xf_desc_random(xf_rng_t *r);
const xf_call_desc  *xf_desc_random_surface(xf_rng_t *r, xf_surface_t s);

/* Descriptors that can produce a given resource kind — used to satisfy a
 * consumer arg by inserting a producer earlier in the program. */
const xf_call_desc  *xf_desc_random_producer(xf_rng_t *r, xf_reskind_t kind);

/* Surface accessors implemented per-surface. Each returns its static table. */
const xf_call_desc  *xf_bsd_table(uint32_t *count);
const xf_call_desc  *xf_mach_table(uint32_t *count);
/* IOKit is discovered dynamically; the table is built at init. */
const xf_call_desc  *xf_iokit_table(uint32_t *count);
void                 xf_iokit_discover(void);   /* probe openable clients   */

#endif /* XF_DESC_H */
