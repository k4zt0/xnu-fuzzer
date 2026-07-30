/* generator.h — synthesize random programs from the description registry. */
#ifndef XF_GENERATOR_H
#define XF_GENERATOR_H

#include "prog.h"

/* Build a fresh random program (1..max_calls calls) into p. p must be init'd
 * or previously freed. */
void xf_generate(xf_prog *p, xf_rng_t *r, uint32_t max_calls);

/* Append one randomly-chosen call to an existing program, satisfying its
 * resource args from the pool (inserting producers as needed). Returns the
 * index of the appended call, or -1 if the program is full. */
int  xf_gen_append_call(xf_prog *p, xf_rng_t *r);

/* Materialize a concrete arg value/blob from a static arg description. */
void xf_gen_arg(xf_arg *arg, const xf_arg_desc *ad, xf_rng_t *r);

#endif /* XF_GENERATOR_H */
