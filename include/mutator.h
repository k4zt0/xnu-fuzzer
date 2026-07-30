/* mutator.h — evolve programs via structural + value mutations. */
#ifndef XF_MUTATOR_H
#define XF_MUTATOR_H

#include "prog.h"

/* Apply a random number of mutations in place. */
void xf_mutate(xf_prog *p, xf_rng_t *r);

/* Splice: graft a suffix of `donor` onto `p` (both stay valid). */
void xf_splice(xf_prog *p, const xf_prog *donor, xf_rng_t *r);

#endif /* XF_MUTATOR_H */
