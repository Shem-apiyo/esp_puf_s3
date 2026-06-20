#ifndef LINUX_COMPAT_H
#define LINUX_COMPAT_H

/*
 * LINUX_COMPAT.H
 * Minimal shim to build Linux kernel BCH library on ESP-IDF / Xtensa LX7.
 * Replaces linux/types.h dependencies only.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Linux kernel types used by bch.c */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t  s32;

/* Linux kernel allocator macros — map to standard heap */
#define kmalloc(size, flags)   malloc(size)
#define kzalloc(size, flags)   calloc(1, size)
#define kfree(ptr)             free(ptr)
#define GFP_KERNEL             0

/* Linux DIV_ROUND_UP macro */
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d)     (((n) + (d) - 1) / (d))
#endif

/* Linux ARRAY_SIZE macro */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)        (sizeof(arr) / sizeof((arr)[0]))
#endif

/* Linux min macro */
#ifndef min
#define min(a, b)              ((a) < (b) ? (a) : (b))
#endif

/* Suppress Linux module infrastructure */
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define pr_err(fmt, ...)
#define BUG()                  abort()


/* ---- bitrev8: reverse bits in a byte ---- */
static inline uint8_t bitrev8(uint8_t byte) {
    byte = (byte & 0xF0) >> 4 | (byte & 0x0F) << 4;
    byte = (byte & 0xCC) >> 2 | (byte & 0x33) << 2;
    byte = (byte & 0xAA) >> 1 | (byte & 0x55) << 1;
    return byte;
}

/* ---- cpu_to_be32: host to big-endian 32-bit ---- */
#include <stdint.h>
static inline uint32_t cpu_to_be32(uint32_t x) {
    return ((x & 0x000000FFU) << 24) |
           ((x & 0x0000FF00U) <<  8) |
           ((x & 0x00FF0000U) >>  8) |
           ((x & 0xFF000000U) >> 24);
}

/* ---- fls: find last set bit (1-indexed, 0 if none) ---- */
static inline int puf_fls(unsigned int x) {
    int r = 0;
    if (x == 0) return 0;
    if (x & 0xFFFF0000) { r += 16; x >>= 16; }
    if (x & 0xFF00)     { r +=  8; x >>=  8; }
    if (x & 0xF0)       { r +=  4; x >>=  4; }
    if (x & 0xC)        { r +=  2; x >>=  2; }
    if (x & 0x2)        { r +=  1; }
    return r + 1;
}


/* ---- WARN_ON: non-fatal assertion, evaluates condition ---- */
#include <stdio.h>
#define WARN_ON(cond) ({ \
    int __cond = !!(cond); \
    if (__cond) fprintf(stderr, "WARN_ON: %s\n", #cond); \
    __cond; \
})

/* ---- swap: exchange two values of same type ---- */
#define swap(a, b) do { \
    __typeof__(a) _tmp = (a); \
    (a) = (b); \
    (b) = _tmp; \
} while (0)

/* ---- errno constants ---- */
#define EINVAL  22
#define EBADMSG 74

/* ---- kzalloc_obj: allocate zeroed object by dereferencing pointer ---- */
#define kzalloc_obj(obj) calloc(1, sizeof(obj))

#endif /* LINUX_COMPAT_H */



