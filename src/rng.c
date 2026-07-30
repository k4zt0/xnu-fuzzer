#include "rng.h"

/* SplitMix64 — used to expand a single seed into the xoshiro state. */
static uint64_t splitmix64(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

void xf_rng_seed(xf_rng_t *r, uint64_t seed) {
    if (seed == 0) seed = 0xDEADBEEFCAFEBABEULL;
    uint64_t sm = seed;
    for (int i = 0; i < 4; i++) r->s[i] = splitmix64(&sm);
}

static inline uint64_t rotl(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

uint64_t xf_rng_next(xf_rng_t *r) {
    const uint64_t result = rotl(r->s[1] * 5, 7) * 9;
    const uint64_t t = r->s[1] << 17;
    r->s[2] ^= r->s[0];
    r->s[3] ^= r->s[1];
    r->s[1] ^= r->s[2];
    r->s[0] ^= r->s[3];
    r->s[2] ^= t;
    r->s[3] = rotl(r->s[3], 45);
    return result;
}

uint64_t xf_rng_below(xf_rng_t *r, uint64_t n) {
    if (n == 0) return 0;
    /* Lemire's unbiased bounded method. */
    uint64_t x = xf_rng_next(r);
    __uint128_t m = (__uint128_t)x * (__uint128_t)n;
    uint64_t l = (uint64_t)m;
    if (l < n) {
        uint64_t t = -n % n;
        while (l < t) {
            x = xf_rng_next(r);
            m = (__uint128_t)x * (__uint128_t)n;
            l = (uint64_t)m;
        }
    }
    return (uint64_t)(m >> 64);
}

bool xf_rng_oneof(xf_rng_t *r, uint64_t n) {
    if (n <= 1) return true;
    return xf_rng_below(r, n) == 0;
}

/* A pool of values known to stress kernel integer handling. */
static const uint64_t k_interesting[] = {
    0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
    511, 512, 1023, 1024, 4095, 4096, 16383, 16384, 65535, 65536,
    0x7FFFFFFFULL, 0x80000000ULL, 0xFFFFFFFFULL,
    0x100000000ULL, 0x7FFFFFFFFFFFFFFFULL, 0x8000000000000000ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL,
    (uint64_t)-1, (uint64_t)-2, (uint64_t)-4096,
    0x4000000000000000ULL, 0xDEADBEEFULL, 0x41414141ULL,
    0x0000000100000000ULL, 0xAAAAAAAAAAAAAAAAULL, 0x5555555555555555ULL,
};

uint64_t xf_rng_intesting(xf_rng_t *r) {
    const uint64_t n = sizeof(k_interesting) / sizeof(k_interesting[0]);
    uint64_t v = k_interesting[xf_rng_below(r, n)];
    /* Occasionally perturb by a small delta to probe off-by-one edges. */
    if (xf_rng_oneof(r, 4)) v += (uint64_t)((int64_t)xf_rng_below(r, 9) - 4);
    return v;
}
