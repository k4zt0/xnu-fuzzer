/*
 * arch.h — arm64 raw syscall / Mach trap invocation.
 *
 * BSD syscalls: number in x16 (positive), args x0..x7, `svc #0x80`.
 * Mach traps:  number in x16 (negative), args x0..x7, `svc #0x80`.
 * Return value in x0; the carry flag signals error for BSD but we read the
 * raw x0 and let the caller interpret errno via the libc path when needed.
 */
#ifndef XF_ARCH_H
#define XF_ARCH_H

#include <stdint.h>

#if !defined(__aarch64__)
#error "xfuzz raw invocation path is arm64-only"
#endif

/* Generic 8-argument raw trap. `num` positive => BSD class, negative => Mach.
 * Returns the raw x0 result. */
static inline int64_t xf_raw_trap(int64_t num,
                                  uint64_t a0, uint64_t a1, uint64_t a2,
                                  uint64_t a3, uint64_t a4, uint64_t a5,
                                  uint64_t a6, uint64_t a7) {
    register uint64_t x0 __asm__("x0") = a0;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;
    register uint64_t x3 __asm__("x3") = a3;
    register uint64_t x4 __asm__("x4") = a4;
    register uint64_t x5 __asm__("x5") = a5;
    register uint64_t x6 __asm__("x6") = a6;
    register uint64_t x7 __asm__("x7") = a7;
    register int64_t  x16 __asm__("x16") = num;
    __asm__ __volatile__(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4),
          "r"(x5), "r"(x6), "r"(x7), "r"(x16)
        : "memory", "cc");
    return (int64_t)x0;
}

static inline int64_t xf_bsd_syscall(uint32_t nr, const uint64_t a[8]) {
    return xf_raw_trap((int64_t)nr, a[0], a[1], a[2], a[3],
                       a[4], a[5], a[6], a[7]);
}

/* Mach trap: pass the positive index; issued as its negative. */
static inline int64_t xf_mach_trap(uint32_t idx, const uint64_t a[8]) {
    return xf_raw_trap(-(int64_t)idx, a[0], a[1], a[2], a[3],
                       a[4], a[5], a[6], a[7]);
}

#endif /* XF_ARCH_H */
