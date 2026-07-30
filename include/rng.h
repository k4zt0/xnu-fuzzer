/* rng.h — fast, deterministic PRNG (xoshiro256**) for reproducible fuzzing. */
#ifndef XF_RNG_H
#define XF_RNG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct { uint64_t s[4]; } xf_rng_t;

/* Seed the generator. Any seed is valid (0 is remapped internally). */
void     xf_rng_seed(xf_rng_t *r, uint64_t seed);

/* Uniform 64-bit value. */
uint64_t xf_rng_next(xf_rng_t *r);

/* Uniform in [0, n).  n == 0 returns 0. */
uint64_t xf_rng_below(xf_rng_t *r, uint64_t n);

/* True with probability 1/n (n>=1). xf_rng_oneof(r,1) is always true. */
bool     xf_rng_oneof(xf_rng_t *r, uint64_t n);

/* A "biased" integer favouring small values and interesting boundaries —
 * the kind of value that trips kernel arithmetic (0, 1, -1, page sizes,
 * INT_MAX, etc.). */
uint64_t xf_rng_intesting(xf_rng_t *r);

#endif /* XF_RNG_H */
